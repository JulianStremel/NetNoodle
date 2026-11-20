package sqlite_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func TestRegistryDefaultAndCustomPath(t *testing.T) {
	for _, tc := range []struct{ name, settings, path string }{
		{"absent", "", "netnoodle.db"},
		{"empty", "{}", "netnoodle.db"},
		{"custom", `{"path":"custom.db"}`, "custom.db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			st, err := store.Open(context.Background(), registry.Spec{Settings: json.RawMessage(tc.settings)}, dir)
			if err != nil {
				t.Fatal(err)
			}
			id, err := st.CreateUser(context.Background(), "existing", []byte("hash"))
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, tc.path)); err != nil {
				t.Fatal(err)
			}
			st, err = store.Open(context.Background(), registry.Spec{Type: "sqlite", Settings: json.RawMessage(tc.settings)}, dir)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			u, err := st.UserByName(context.Background(), "existing")
			if err != nil || u.ID != id {
				t.Fatalf("reopened database: %+v %v", u, err)
			}
		})
	}
}

func TestRegistryStrictSettings(t *testing.T) {
	for _, settings := range []string{`{"unknown":true}`, `{"path":42}`, `{"path":""}`, `{"path":"../escape.db"}`, `{"path":"/absolute.db"}`, `[]`, `{} {}`, `{`} {
		t.Run(settings, func(t *testing.T) {
			st, err := store.Open(context.Background(), registry.Spec{Type: "sqlite", Settings: json.RawMessage(settings)}, t.TempDir())
			if err == nil {
				st.Close()
				t.Fatal("invalid settings accepted")
			}
		})
	}
}
