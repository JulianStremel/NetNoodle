package sqlite

import (
	"bytes"
	"database/sql"
	"github.com/JulianStremel/netnoodle/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExportRemovesCredentialURLs(t *testing.T) {
	db := open(t)
	now := time.Now()
	for _, typ := range []string{"webhook", "custom"} {
		_, err := db.CreateIntegration(t.Context(), store.Integration{Kind: "notify", Type: typ, Name: typ, Settings: []byte(`{"url":"https://host/legacy-url-secret","custom_endpoint":"https://host/path-token-secret?key=secret","format":"json"}`), Secrets: []byte(`{"url":"https://host/stored-url-secret","password":"stored-password-secret"}`), Enabled: true, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(t.TempDir(), "export.db")
	if err := db.ExportBackup(t.Context(), file); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"legacy-url-secret", "path-token-secret", "stored-url-secret", "stored-password-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("export retained %s", secret)
		}
	}
	snapshot, err := sql.Open("sqlite", file)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var n int
	if err := snapshot.QueryRow(`SELECT COUNT(*) FROM integrations WHERE enabled<>0 OR secrets_json<>'{}' OR settings_json<>'{"format":"json"}'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("export not sanitized: %d %v", n, err)
	}
	rows, err := db.ListIntegrations(t.Context())
	if err != nil || len(rows) != 2 || !bytes.Contains(rows[0].Secrets, []byte("stored-password-secret")) {
		t.Fatalf("live data modified: %+v %v", rows, err)
	}
}
