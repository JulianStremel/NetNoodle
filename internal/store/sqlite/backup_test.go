package sqlite

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func migrationFS(t *testing.T) fstest.MapFS {
	t.Helper()
	out := fstest.MapFS{}
	err := fs.WalkDir(migrations, "migrations", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(migrations, name)
		if err != nil {
			return err
		}
		out[name] = &fstest.MapFile{Data: b}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMigrationBackupSafety(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "database # space.db")
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(ctx, "before", []byte("hash")); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(path), "backups")
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("new database backed up")
	}
	opts := migrationOptions{fs: migrationFS(t), free: freeSpace}
	opts.fs.(fstest.MapFS)["migrations/0012_test.sql"] = &fstest.MapFile{Data: []byte(`CREATE TABLE test_new (id INTEGER);`)}
	checks := 0
	opts.free = func(string) (uint64, error) { checks++; return 0, nil }
	if _, err := openWithOptions(ctx, path, opts); err == nil || !strings.Contains(err.Error(), "insufficient free disk") {
		t.Fatalf("low disk: %v", err)
	}
	if checks != 1 {
		t.Fatal(checks)
	}
	opts.free = func(string) (uint64, error) { return 0, fmt.Errorf("space unavailable") }
	if _, err := openWithOptions(ctx, path, opts); err == nil || !strings.Contains(err.Error(), "refusing migration without backup") {
		t.Fatal(err)
	}
	opts.free = freeSpace
	db, err = openWithOptions(ctx, path, opts)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	backup, err := LatestBackup(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.Base(backup), "0011_peer_version-") {
		t.Fatal(backup)
	}
	old, err := openExisting(ctx, backup, "ro")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := old.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='test_new'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("backup is post-migration", n, err)
	}
	if err := old.QueryRow(`SELECT count(*) FROM users WHERE name='before'`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	old.Close()
	// No pending migrations means no backup or free-space call.
	opts.free = func(string) (uint64, error) { t.Error("space checked with no pending migrations"); return 0, nil }
	db, err = openWithOptions(ctx, path, opts)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	// Unknown applied migrations refuse a downgrade without changing the DB.
	if _, err := Open(ctx, path); err == nil || !strings.Contains(err.Error(), "database schema is newer than this nn-server") {
		t.Fatal(err)
	}
	// Each failing migration is fully rolled back; the error identifies its backup.
	opts.fs.(fstest.MapFS)["migrations/0013_fail.sql"] = &fstest.MapFile{Data: []byte(`CREATE TABLE should_rollback(id); INVALID SQL;`)}
	opts.free = freeSpace
	if _, err := openWithOptions(ctx, path, opts); err == nil || !strings.Contains(err.Error(), "pre-migration backup:") {
		t.Fatal(err)
	}
	raw, err := openExisting(ctx, path, "ro")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='should_rollback'`).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}

func TestBackupRotation(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 6; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("netnoodle-%02d.db", i)), []byte("backup"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "pre-restore-old.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rotateBackups(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatal(entries)
	}
	latest, err := LatestBackup(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(latest) != "netnoodle-05.db" {
		t.Fatal(latest)
	}
}

func TestRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "current.db")
	backups := filepath.Join(dir, "backups")
	if err := os.Mkdir(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(ctx, "original", []byte("hash")); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backups, "netnoodle-original.db")
	if err := db.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(ctx, "new", []byte("hash")); err != nil {
		t.Fatal(err)
	}
	db.Close()
	bad := filepath.Join(dir, "corrupt.db")
	if err := os.WriteFile(bad, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, path, bad, backups, false); err == nil {
		t.Fatal("corrupt backup accepted")
	}
	if _, err := Restore(ctx, path, backup, backups, true); err != nil {
		t.Fatal(err)
	}
	assertUsers := func(path string, want int) {
		t.Helper()
		db, err := openExisting(ctx, path, "ro")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil || n != want {
			t.Fatal(path, n, err)
		}
	}
	assertUsers(path, 2)
	latest, err := LatestBackup(backups)
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := Restore(ctx, path, latest, backups, false)
	if err != nil {
		t.Fatal(err)
	}
	assertUsers(path, 1)
	assertUsers(preserved, 2)
	assertUsers(backup, 1)
	// Explicit file restore also works; source and destination stay intact.
	if _, err := Restore(ctx, path, preserved, backups, false); err != nil {
		t.Fatal(err)
	}
	assertUsers(path, 2)
	// A corrupt current database is recoverable and its bytes are retained.
	broken := []byte("damaged current database")
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(path+suffix, []byte(suffix), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	saved, err := Restore(ctx, path, backup, backups, false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(saved)
	if err != nil || string(data) != string(broken) {
		t.Fatal(string(data), err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		data, err := os.ReadFile(saved + suffix)
		if err != nil || string(data) != suffix {
			t.Fatal(string(data), err)
		}
		if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
			t.Fatal("old sidecar left in place", err)
		}
	}
	assertUsers(path, 1)
}
