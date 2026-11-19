package server

import (
	"context"
	"encoding/json"
	"time"

	"netnoodle/internal/notify"
	"netnoodle/internal/proto"
	"netnoodle/internal/registry"
	"netnoodle/internal/source"
	"netnoodle/internal/store"
)

// SourceSpec is a source entry in the config: the common plug-in fields
// plus the poll interval.
type SourceSpec struct {
	registry.Spec
	Interval Duration `json:"interval,omitempty"`
}

// event writes an entry to the event log only.
func (s *Server) event(ctx context.Context, typ, actor, summary string) {
	if err := s.st.AddEvent(ctx, store.Event{At: s.now(), Type: typ, Actor: actor, Summary: summary}); err != nil {
		s.log.Error("event", "err", err)
	}
}

// emit writes an event to the log and sends it to all notifiers. Sending
// happens in the background with a timeout; a slow notifier never blocks
// ingest.
func (s *Server) emit(ctx context.Context, e notify.Event, actor, data string) {
	if e.At.IsZero() {
		e.At = s.now()
	}
	if err := s.st.AddEvent(ctx, store.Event{At: e.At, Type: e.Type, Actor: actor, Summary: e.Title, Data: data}); err != nil {
		s.log.Error("event", "err", err)
	}
	for _, n := range s.notifiers {
		go func(n notify.Notifier) {
			nctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := n.Notify(nctx, e); err != nil {
				s.log.Warn("notify", "notifier", n.Name(), "err", err)
			}
		}(n)
	}
}

// SetNotifiers installs the notifiers built from the config.
func (s *Server) SetNotifiers(ns []notify.Notifier) { s.notifiers = ns }

// RunSources polls each in-process source on its interval until ctx ends.
func (s *Server) RunSources(ctx context.Context, specs []SourceSpec) error {
	for _, spec := range specs {
		if spec.Disabled {
			continue
		}
		if spec.Name == "" {
			spec.Name = spec.Type
		}
		src, err := source.Registry.Build(spec.Type, spec.Name, spec.Settings)
		if err != nil {
			return err
		}
		every := spec.Interval.Duration
		if every <= 0 {
			every = 10 * time.Minute
		}
		if every < 30*time.Second {
			every = 30 * time.Second
		}
		go s.pollLoop(ctx, src, every)
	}
	return nil
}

func (s *Server) pollLoop(ctx context.Context, src source.Source, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		start := time.Now()
		n := 0
		err := src.Poll(ctx, func(obs proto.Observation) error {
			obs.Version = proto.Version
			obs.Source = src.Name()
			raw, _ := json.Marshal(obs)
			_, err := s.Ingest(ctx, obs, raw)
			n += len(obs.Entities)
			return err
		})
		if err != nil && ctx.Err() == nil {
			s.log.Warn("source poll", "source", src.Name(), "err", err)
			s.event(ctx, "source.error", src.Name(), err.Error())
		} else {
			s.log.Info("source poll", "source", src.Name(), "entities", n, "took", time.Since(start).Round(time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunMaintenance purges old raw observations and expired sessions daily.
func (s *Server) RunMaintenance(ctx context.Context, keep time.Duration) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		now := s.now()
		if err := s.st.PurgeObservations(ctx, now.Add(-keep)); err != nil && ctx.Err() == nil {
			s.log.Warn("purge observations", "err", err)
		}
		_ = s.st.PurgeSessions(ctx, now)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
