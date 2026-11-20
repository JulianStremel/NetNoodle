// Shared adapters connect each registry to the same schema, persistence and API
// mechanism. Only construction and the kind-specific dry run differ.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/llm"
	"github.com/JulianStremel/netnoodle/internal/mqtt"
	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/source"
	"github.com/JulianStremel/netnoodle/internal/store"
)

type integrationRegistry struct {
	kind   string
	types  func() []string
	schema func(string) (registry.Schema, bool)
	build  func(string, string, json.RawMessage) (any, error)
}

func registryAdapter[T any](kind string, r *registry.Registry[T]) integrationRegistry {
	return integrationRegistry{kind, r.Types, r.Schema, func(typ, name string, raw json.RawMessage) (any, error) { return r.Build(typ, name, raw) }}
}
func integrationRegistries() []integrationRegistry {
	return []integrationRegistry{
		registryAdapter("source", source.Registry), registryAdapter("notify", notify.Registry),
		registryAdapter("intel", intel.Matchers), registryAdapter("intel", intel.Enrichers), registryAdapter("llm", llm.Registry),
	}
}
func supportedIntegrationKind(kind string) bool {
	for _, r := range integrationRegistries() {
		if r.kind == kind {
			return true
		}
	}
	return false
}
func integrationSchema(kind, typ string) (registry.Schema, bool) {
	for _, r := range integrationRegistries() {
		if r.kind == kind {
			if s, ok := r.schema(typ); ok {
				return s, true
			}
		}
	}
	return registry.Schema{}, false
}
func buildPlugin(i store.Integration) (any, error) {
	// Sources have an additional polling interval handled by their supervisor.
	if i.Kind == "source" {
		src, _, err := buildIntegration(i)
		return src, err
	}
	raw, err := integrationSettings(i)
	if err != nil {
		return nil, err
	}
	for _, r := range integrationRegistries() {
		if r.kind == i.Kind {
			if _, ok := r.schema(i.Type); ok {
				return r.build(i.Type, i.Name, raw)
			}
		}
	}
	return nil, errors.New("unknown integration kind or type")
}
func integrationSettings(i store.Integration) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	var secrets map[string]string
	if json.Unmarshal(i.Settings, &settings) != nil || json.Unmarshal(i.Secrets, &secrets) != nil {
		return nil, errors.New("invalid settings")
	}
	if settings == nil {
		settings = map[string]json.RawMessage{}
	}
	for key, value := range secrets {
		settings[key], _ = json.Marshal(value)
	}
	raw, _ := json.Marshal(settings)
	return raw, nil
}

// Config entries use the same public schema projection but cannot be mutated.
func (s *Server) configPlugins() []store.Integration {
	out := []store.Integration{}
	add := func(kind string, specs []registry.Spec) {
		for _, spec := range specs {
			name := spec.Name
			if name == "" {
				name = spec.Type
			}
			raw := spec.Settings
			if len(raw) == 0 {
				raw = json.RawMessage(`{}`)
			}
			out = append(out, store.Integration{Kind: kind, Type: spec.Type, Name: name, Settings: raw, Secrets: json.RawMessage(`{}`), Enabled: !spec.Disabled})
		}
	}
	add("notify", s.cfg.Notifiers)
	add("intel", s.cfg.Matchers)
	add("intel", s.cfg.Enrichers)
	add("llm", s.cfg.LLMs)
	return out
}

type activeIntegration struct {
	revision string
	row      store.Integration
	plugin   any
	cancel   context.CancelFunc
	done     chan struct{}
	errText  string
}

func stopPlugin(a *activeIntegration) {
	if a.cancel != nil {
		a.cancel()
		<-a.done
	}
}

// Called under the common supervisor lock. Immutable plugin snapshots allow
// in-flight sends and matches to finish safely during a swap.
func (s *Server) reconcilePluginsLocked(rows []store.Integration) error {
	sup := s.integrations
	wanted := map[string]bool{}
	intelChanged := !sup.pluginsStarted
	sup.pluginsStarted = true
	install := func(key string, i store.Integration, config bool) {
		wanted[key] = true
		revision := integrationRevision(i)
		if old := sup.plugins[key]; old != nil {
			if old.revision == revision {
				return
			}
			stopPlugin(old)
			if old.row.Kind == "intel" {
				intelChanged = true
			}
		}
		a := &activeIntegration{revision: revision, row: i}
		sup.plugins[key] = a
		if i.Kind == "intel" {
			intelChanged = true
		}
		if !i.Enabled {
			return
		}
		var p any
		var err error
		if config {
			for _, r := range integrationRegistries() {
				if r.kind == i.Kind {
					for _, typ := range r.types() {
						if typ == i.Type {
							p, err = r.build(i.Type, i.Name, i.Settings)
						}
					}
				}
			}
			if p == nil && err == nil {
				err = errors.New("unknown integration")
			}
		} else {
			p, err = buildPlugin(i)
		}
		if err != nil {
			a.errText = "Invalid settings; check required fields, URL and TLS settings."
			return
		}
		a.plugin = p
		if publisher, ok := p.(*mqtt.Publisher); ok {
			publisher.BindProvider(s.mqttSnapshot)
			ctx, cancel := context.WithCancel(sup.ctx)
			a.cancel, a.done = cancel, make(chan struct{})
			go func() { defer close(a.done); publisher.Run(ctx) }()
		}
	}
	for index, i := range s.configPlugins() {
		install(configPluginKey(index), i, true)
	}
	for _, i := range rows {
		if i.Kind != "source" {
			install(integrationKey(i.ID), i, false)
		}
	}
	for key, a := range sup.plugins {
		if !wanted[key] {
			stopPlugin(a)
			if a.row.Kind == "intel" {
				intelChanged = true
			}
			delete(sup.plugins, key)
		}
	}
	ns := []notify.Notifier{}
	ms := []intel.Matcher{}
	es := []intel.Enricher{}
	keys := make([]string, 0, len(sup.plugins))
	for key := range sup.plugins {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		a := sup.plugins[key]
		switch p := a.plugin.(type) {
		case notify.Notifier:
			ns = append(ns, p)
		case intel.Matcher:
			ms = append(ms, p)
		case intel.Enricher:
			es = append(es, p)
		}
	}
	s.SetNotifiers(ns)
	if intelChanged {
		s.SetIntel(ms, es)
		s.KickIntel()
	}
	return nil
}
func configPluginKey(index int) string { return "plugin:" + configIntegrationKey(index) }

// Every dry run gets a fresh instance. Feed caches and results are discarded.
func testPlugin(ctx context.Context, p any) (map[string]any, error) {
	switch v := p.(type) {
	case notify.Notifier:
		e := notify.Event{Type: "integration.test", Title: "Integration test", At: time.Now().UTC()}
		if tester, ok := p.(interface {
			Test(context.Context, notify.Event) error
		}); ok {
			return nil, tester.Test(ctx, e)
		}
		return nil, v.Notify(ctx, e)
	case llm.Provider:
		start := time.Now()
		reply, err := v.Complete(ctx, llm.Request{User: "Reply with OK", MaxTokens: 16, Timeout: integrationPollTimeout})
		return map[string]any{"reply_length": len(reply.Text), "latency_ms": time.Since(start).Milliseconds()}, err
	case interface{ Test(context.Context) error }:
		return nil, v.Test(ctx)
	case intel.Refresher:
		return nil, v.Refresh(ctx)
	}
	return nil, errors.New("integration has no test action")
}
