// Package registry is the generic plug-in mechanism. Every pluggable part
// (sources, matchers, enrichers, deciders, guards, notifiers, actor
// backends) has one Registry. Implementations register a factory under a
// type name in an init function; config entries select them by that name.
package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Factory builds one instance from its name and its raw JSON settings.
type Factory[T any] func(name string, settings json.RawMessage) (T, error)

// Registry maps type names to factories for one interface T.
type Registry[T any] struct {
	kind string
	mu   sync.RWMutex
	f    map[string]Factory[T]
}

// New returns an empty registry. kind is used in error messages only.
func New[T any](kind string) *Registry[T] {
	return &Registry[T]{kind: kind, f: map[string]Factory[T]{}}
}

// Register adds a factory. It panics on a duplicate type name, because that
// is a programming error found at start-up.
func (r *Registry[T]) Register(typ string, f Factory[T]) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.f[typ]; dup {
		panic(fmt.Sprintf("registry %s: duplicate type %q", r.kind, typ))
	}
	r.f[typ] = f
}

// Build creates an instance of the given type.
func (r *Registry[T]) Build(typ, name string, settings json.RawMessage) (T, error) {
	r.mu.RLock()
	f, ok := r.f[typ]
	r.mu.RUnlock()
	if !ok {
		var zero T
		return zero, fmt.Errorf("%s: unknown type %q (known: %v)", r.kind, typ, r.Types())
	}
	return f(name, settings)
}

// Types returns the registered type names, sorted.
func (r *Registry[T]) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.f))
	for k := range r.f {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Spec is the common config shape for one plug-in instance.
type Spec struct {
	Type     string          `json:"type"`
	Name     string          `json:"name"`
	Disabled bool            `json:"disabled,omitempty"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

// BuildAll builds every enabled spec. Instance names must be unique.
func BuildAll[T any](r *Registry[T], specs []Spec) ([]T, error) {
	seen := map[string]bool{}
	var out []T
	for _, s := range specs {
		if s.Disabled {
			continue
		}
		if s.Name == "" {
			s.Name = s.Type
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("%s: duplicate instance name %q", r.kind, s.Name)
		}
		seen[s.Name] = true
		v, err := r.Build(s.Type, s.Name, s.Settings)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", r.kind, s.Name, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// Decode is a helper for factories: it decodes settings strictly into v.
// Empty settings leave v unchanged (defaults).
func Decode(settings json.RawMessage, v any) error {
	if len(settings) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(settings))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
