package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/JulianStremel/netnoodle/internal/registry"
)

// Opener creates a backend using its settings and the server's data directory.
type Opener func(ctx context.Context, dataDir string, settings json.RawMessage) (Store, error)

var backends = registry.New[Opener]("store")

// Register registers a backend at startup. Duplicate names panic.
func Register(name string, opener Opener) {
	if name == "" || opener == nil {
		panic("store: name and opener are required")
	}
	backends.Register(name, func(_ string, _ json.RawMessage) (Opener, error) { return opener, nil })
}

// Open opens the configured backend. An omitted type selects SQLite for
// compatibility with installations predating the store configuration key.
// Programs must import their backend implementations to register them.
func Open(ctx context.Context, spec registry.Spec, dataDir string) (Store, error) {
	if spec.Type == "" {
		spec.Type = "sqlite"
	}
	opener, err := backends.Build(spec.Type, spec.Name, nil)
	if err != nil {
		return nil, err
	}
	st, err := opener(ctx, dataDir, spec.Settings)
	if err != nil {
		return nil, fmt.Errorf("store %q: %w", spec.Type, err)
	}
	return st, nil
}
