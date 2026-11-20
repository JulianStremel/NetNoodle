package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/registry"
)

func TestStoreConfig(t *testing.T) {
	for _, tc := range []struct {
		name, input, typ, settings string
		invalid                    bool
	}{
		{name: "absent", input: `{}`, typ: "sqlite"},
		{name: "sqlite", input: `{"store":{"type":"sqlite","settings":{"path":"custom.db"}}}`, typ: "sqlite", settings: `{"path":"custom.db"}`},
		{name: "custom", input: `{"store":{"type":"other","settings":{"endpoint":"test"}}}`, typ: "other", settings: `{"endpoint":"test"}`},
		{name: "strict", input: `{"store":{"type":"sqlite","typo":true}}`, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.input), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid config accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Store.Type != tc.typ || string(cfg.Store.Settings) != tc.settings {
				t.Fatalf("store config: %+v", cfg.Store)
			}
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip Config
			if err := json.Unmarshal(b, &roundtrip); err != nil || roundtrip.Store.Type != tc.typ {
				t.Fatal(roundtrip.Store, err)
			}
		})
	}
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing.json")} {
		cfg, err := LoadConfig(path)
		if err != nil || cfg.Store.Type != "sqlite" {
			t.Fatal(cfg.Store, err)
		}
	}
}

// TestMandatoryGuards: an explicit guard list cannot remove the protected,
// scope and kill switch guards (security review 2026-11-20).
func TestMandatoryGuards(t *testing.T) {
	c := Config{Guards: []registry.Spec{{Type: "rate"}}}
	c.applyIntelDefaults()
	for _, kind := range MandatoryGuards {
		if !slices.ContainsFunc(c.Guards, func(g registry.Spec) bool { return g.Type == kind }) {
			t.Fatalf("guard %s missing: %+v", kind, c.Guards)
		}
	}
}
