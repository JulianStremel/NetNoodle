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
		path, err := DatabasePath(dataDir, settings)
		if err != nil {
			return nil, err
		}
		return openWithOptions(ctx, path, migrationOptions{fs: migrations, free: freeSpace, backupDir: filepath.Join(dataDir, "backups")})
	})
}

// DatabasePath resolves SQLite settings without opening or migrating the database.
func DatabasePath(dataDir string, settings json.RawMessage) (string, error) {
	cfg := struct {
		Path string `json:"path"`
	}{Path: "netnoodle.db"}
	if len(settings) > 0 && !json.Valid(settings) {
		return "", fmt.Errorf("invalid SQLite settings JSON")
	}
	if err := registry.Decode(settings, &cfg); err != nil {
		return "", fmt.Errorf("SQLite settings: %w", err)
	}
	if !filepath.IsLocal(cfg.Path) {
		return "", fmt.Errorf("SQLite path must be relative to data_dir")
	}
	return filepath.Join(dataDir, cfg.Path), nil
}
