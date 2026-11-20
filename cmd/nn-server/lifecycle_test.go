package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/store/sqlite"
)

func TestLifecycleLockAndRestoreCLI(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "database.db")
	backupDir := filepath.Join(dir, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backupDir, "netnoodle-test.db")
	if err := st.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	st.Close()
	config := filepath.Join(dir, "config.json")
	b, _ := json.Marshal(map[string]any{"data_dir": dir, "store": map[string]any{"type": "sqlite", "settings": map[string]string{"path": "database.db"}}})
	if err := os.WriteFile(config, b, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireDataLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireDataLock(dir); err == nil {
		t.Fatal("second lock accepted")
	}
	if err := lifecycle(ctx, "restore", []string{"--latest", "--config", config}); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatal(err)
	}
	// Export is an online read-only snapshot, even with the server lock held.
	if err := lifecycle(ctx, "export", []string{"--out", filepath.Join(dir, "online.tar.gz"), "--config", config}); err != nil {
		t.Fatal(err)
	}
	lock.Close()
	for _, args := range [][]string{{"--latest"}, {"--file", backup}, {"--latest", "--dry-run"}} {
		args = append(args, "--config", config)
		if err := lifecycle(ctx, "restore", args); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{}, {"--latest", "--file", backup}} {
		if err := lifecycle(ctx, "restore", args); err == nil {
			t.Fatal("invalid flags accepted")
		}
	}
}

func TestExportContentsAndSecrets(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := sqlite.Open(ctx, filepath.Join(dir, "netnoodle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateUser(ctx, "exported", []byte("hash")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls/cert.pem", "tls/key.pem", "tls/pull-client-cert.pem", "tls/pull-client-key.pem", "keys/order-ed25519.pem", "netnoodle.json", "tokens.json", "keys/tokens.json", "tls/config.json", "backups/not-exported.db"} {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(dir, "export.tar.gz")
	if err := exportArchive(ctx, st, dir, archive); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(archive)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal(info, err)
		}
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	var manifest struct{ Files []string }
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Mode != 0o600 {
			t.Fatal(h)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "manifest.json" {
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
		}
		if h.Name == "netnoodle.db" {
			path := filepath.Join(t.TempDir(), "snapshot.db")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			snapshot, err := sqlite.OpenReadOnly(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			u, err := snapshot.UserByName(ctx, "exported")
			snapshot.Close()
			if err != nil || u.Name != "exported" {
				t.Fatal(u, err)
			}
		}
	}
	want := []string{"netnoodle.db", "manifest.json", "tls/cert.pem", "tls/key.pem", "tls/pull-client-cert.pem", "tls/pull-client-key.pem", "keys/order-ed25519.pem"}
	sort.Strings(names)
	sort.Strings(want)
	sort.Strings(manifest.Files)
	if !reflect.DeepEqual(names, want) || !reflect.DeepEqual(manifest.Files, want) {
		t.Fatal(names, manifest.Files)
	}
	if err := exportArchive(ctx, st, dir, archive); err == nil {
		t.Fatal("overwrote existing archive")
	}
}
