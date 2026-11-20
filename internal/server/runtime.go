package server

import (
	"context"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
)

// SourceSpec is a source entry in the config: the common plug-in fields
// plus the poll interval.
type SourceSpec struct {
	registry.Spec
	Interval Duration `json:"interval,omitempty"`
}

// reservedNames are names that peers may not enroll with: the names of the
// in-process sources (their data is stored under the source name).
func reservedNames(cfg Config) map[string]bool {
	m := map[string]bool{"local": true, "server": true}
	for _, s := range cfg.Sources {
		n := s.Name
		if n == "" {
			n = s.Type
		}
		m[strings.ToLower(n)] = true
	}
	return m
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
	// MQTT has its own bounded queue and shares one connection with discovery.
	// Queue every event before the general notifier concurrency limiter.
	if s.mqtt != nil {
		_ = s.mqtt.Notify(ctx, e)
	}
	if err := s.st.AddEvent(ctx, store.Event{At: e.At, Type: e.Type, Actor: actor, Summary: e.Title, Data: data}); err != nil {
		s.log.Error("event", "err", err)
	}
	for _, n := range s.notifiers {
		// At most cap(notifySem) sends run at a time; a burst drops the rest
		// (they stay in the event log).
		select {
		case s.notifySem <- struct{}{}:
		default:
			s.log.Warn("notify queue full, event not sent", "notifier", n.Name(), "type", e.Type)
			continue
		}
		go func(n notify.Notifier) {
			defer func() { <-s.notifySem }()
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

// RunSources starts the supervisor for config and database sources. Individual
// constructor or poll failures are recorded without stopping other sources.
func (s *Server) RunSources(ctx context.Context, specs []SourceSpec) error {
	return s.startIntegrationSupervisor(ctx, specs)
}

// eventRetention is how long the event log is kept.
const eventRetention = 90 * 24 * time.Hour

// RunMaintenance purges old raw observations and expired sessions daily.
func (s *Server) RunMaintenance(ctx context.Context, keep time.Duration) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		now := s.now()
		if err := s.st.PurgeObservations(ctx, now.Add(-keep)); err != nil && ctx.Err() == nil {
			s.log.Warn("purge observations", "err", err)
		}
		if err := s.st.ExpireProposals(ctx, now.Add(-7*24*time.Hour)); err != nil && ctx.Err() == nil {
			s.log.Warn("expire proposals", "err", err)
		}
		if err := s.st.PurgeProposals(ctx, now.Add(-90*24*time.Hour)); err != nil && ctx.Err() == nil {
			s.log.Warn("purge proposals", "err", err)
		}
		_ = s.st.PurgeSessions(ctx, now)
		_ = s.st.PurgeEvents(ctx, now.Add(-eventRetention))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
