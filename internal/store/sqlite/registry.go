package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func init() {
	store.Register("sqlite", func(ctx context.Context, dataDir string, settings json.RawMessage) (store.Store, error) {
		cfg := struct {
			Path string `json:"path"`
		}{Path: "netnoodle.db"}
		if len(settings) > 0 && !json.Valid(settings) {
			return nil, fmt.Errorf("invalid SQLite settings JSON")
		}
		if err := registry.Decode(settings, &cfg); err != nil {
			return nil, fmt.Errorf("SQLite settings: %w", err)
		}
		if !filepath.IsLocal(cfg.Path) {
			return nil, fmt.Errorf("SQLite path must be relative to data_dir")
		}
		return Open(ctx, filepath.Join(dataDir, cfg.Path))
	})
}
