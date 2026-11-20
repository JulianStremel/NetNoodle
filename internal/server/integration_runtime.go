package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/source"
	"github.com/JulianStremel/netnoodle/internal/store"
)

const integrationPollTimeout = 30 * time.Second
const integrationProbeTimeout = 10 * time.Second

type integrationSupervisor struct {
	mu             sync.Mutex // serializes persistence changes and reconciliation
	ctx            context.Context
	config         []SourceSpec
	workers        map[string]*integrationWorker
	testSlots      chan struct{}
	plugins        map[string]*activeIntegration
	pluginsStarted bool
}

type integrationWorker struct {
	revision  string
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.Mutex
	running   bool
	lastPoll  time.Time
	lastOKAt  time.Time
	lastError string
}

func newIntegrationSupervisor() *integrationSupervisor {
	return &integrationSupervisor{workers: map[string]*integrationWorker{}, plugins: map[string]*activeIntegration{}, testSlots: make(chan struct{}, 4)}
}

func (s *Server) startIntegrationSupervisor(ctx context.Context, specs []SourceSpec) error {
	sup := s.integrations
	sup.mu.Lock()
	defer sup.mu.Unlock()
	if sup.ctx != nil {
		return errors.New("source supervisor already started")
	}
	sup.ctx, sup.config = ctx, specs
	if err := s.reconcileIntegrationsLocked(ctx); err != nil {
		sup.ctx = nil
		return err
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				sup.mu.Lock()
				for key, a := range sup.plugins {
					stopPlugin(a)
					delete(sup.plugins, key)
				}
				s.SetNotifiers(nil)
				for key, w := range sup.workers {
					stopIntegration(w)
					delete(sup.workers, key)
				}
				sup.mu.Unlock()
				return
			case <-ticker.C:
				sup.mu.Lock()
				if err := s.reconcileIntegrationsLocked(ctx); err != nil && ctx.Err() == nil {
					s.log.Warn("cannot refresh integrations")
				}
				sup.mu.Unlock()
			}
		}
	}()
	return nil
}

func stopIntegration(w *integrationWorker) {
	if w.cancel != nil {
		w.cancel()
		<-w.done
	}
}

func integrationKey(id int64) string        { return fmt.Sprintf("db:%d", id) }
func configIntegrationKey(index int) string { return fmt.Sprintf("config:%d", index) }

// Caller holds supervisor.mu. Runtime result fields do not change revisions.
func (s *Server) reconcileIntegrationsLocked(ctx context.Context) error {
	sup := s.integrations
	if sup.ctx == nil || sup.ctx.Err() != nil {
		return nil
	}
	rows, err := s.st.ListIntegrations(ctx)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	start := func(key, revision string, i store.Integration, config bool, every time.Duration) {
		wanted[key] = true
		if old := sup.workers[key]; old != nil {
			if old.revision == revision {
				return
			}
			stopIntegration(old)
		}
		w := &integrationWorker{revision: revision}
		sup.workers[key] = w
		if !i.Enabled {
			return
		}
		var src source.Source
		var err error
		if config {
			src, err = source.Registry.Build(i.Type, i.Name, i.Settings)
		} else {
			src, every, err = buildIntegration(i)
			if s.reservedName(i.Name) {
				err = errors.New("reserved name")
			}
		}
		if err != nil {
			w.lastError = "Invalid settings; check required fields, URL and TLS settings."
			return
		}
		if every <= 0 {
			every = 10 * time.Minute
		}
		if every < 30*time.Second {
			every = 30 * time.Second
		}
		workerCtx, cancel := context.WithCancel(sup.ctx)
		w.cancel, w.done, w.running = cancel, make(chan struct{}), true
		go s.runIntegration(workerCtx, w, src, every, i, config)
	}
	for index, spec := range sup.config {
		name := spec.Name
		if name == "" {
			name = spec.Type
		}
		b, _ := json.Marshal(spec)
		start(configIntegrationKey(index), string(b), store.Integration{Type: spec.Type, Name: name, Settings: spec.Settings, Enabled: !spec.Disabled}, true, spec.Interval.Duration)
	}
	for _, i := range rows {
		if i.Kind != "source" {
			continue
		}
		revision := integrationRevision(i)
		start(integrationKey(i.ID), revision, i, false, 0)
	}
	for key, w := range sup.workers {
		if !wanted[key] {
			stopIntegration(w)
			delete(sup.workers, key)
		}
	}
	return s.reconcilePluginsLocked(rows)
}

func integrationRevision(i store.Integration) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s/%t/%s", i.Kind, i.Type, i.Name, i.Settings, i.Secrets, i.Enabled, i.UpdatedAt.Format(time.RFC3339Nano))
}

func (s *Server) reservedName(name string) bool {
	// Config reservations are immutable. Database names are protected against
	// enrolled peers atomically by the store's shared namespace constraints.
	if s.reserved[strings.ToLower(name)] {
		return true
	}
	for _, i := range s.configPlugins() {
		if strings.EqualFold(i.Name, name) {
			return true
		}
	}
	return len(s.cfg.MQTT) > 0 && string(s.cfg.MQTT) != "null" && strings.EqualFold(name, "mqtt")
}

func buildIntegration(i store.Integration) (source.Source, time.Duration, error) {
	raw, err := integrationSettings(i)
	if err != nil {
		return nil, 0, err
	}
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(raw, &settings)
	interval := "10m"
	if b, ok := settings["interval"]; ok && json.Unmarshal(b, &interval) != nil {
		return nil, 0, errors.New("invalid interval")
	}
	delete(settings, "interval")
	every, err := time.ParseDuration(interval)
	if err != nil || every < 30*time.Second {
		return nil, 0, errors.New("poll interval must be at least 30s")
	}
	raw, _ = json.Marshal(settings)
	src, err := source.Registry.Build(i.Type, i.Name, raw)
	return src, every, err
}

func pollIntegration(ctx context.Context, src source.Source, emit func(proto.Observation) error) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("source poll failed")
		}
	}()
	return src.Poll(ctx, emit)
}

func (s *Server) runIntegration(ctx context.Context, w *integrationWorker, src source.Source, every time.Duration, i store.Integration, config bool) {
	defer close(w.done)
	defer func() { w.mu.Lock(); w.running = false; w.mu.Unlock() }()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		pollCtx, cancel := context.WithTimeout(ctx, time.Minute)
		err := pollIntegration(pollCtx, src, func(obs proto.Observation) error {
			if err := pollCtx.Err(); err != nil {
				return err
			}
			obs.Version, obs.Source = proto.Version, src.Name()
			raw, _ := json.Marshal(obs)
			_, err := s.Ingest(pollCtx, obs, raw)
			return err
		})
		if err == nil {
			err = pollCtx.Err()
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		at := s.now().UTC()
		errText := ""
		// Remote errors may reflect credentials, including encoded fragments.
		// Keep raw constructor/poll errors out of APIs, events and logs.
		if err != nil {
			errText = "Poll failed; check credentials, URL and TLS settings."
		}
		w.mu.Lock()
		w.lastPoll, w.lastError = at, errText
		if err == nil {
			w.lastOKAt = at
		}
		w.mu.Unlock()
		if !config {
			if err := s.st.SetIntegrationResult(ctx, i.ID, i.UpdatedAt, at, errText); err != nil && ctx.Err() == nil {
				s.log.Warn("cannot save integration poll state")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
