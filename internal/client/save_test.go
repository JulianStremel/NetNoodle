package client

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSaveCredentialsPrivateAtomic: credentials replace a symlink instead of
// following it, and a directory that others can write is refused (security
// review 2026-11-20).
func TestSaveCredentialsPrivateAtomic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks and mode bits are Unix semantics")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "creds.json")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := SaveCredentials(path, Credentials{Token: "secret"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("symlink target overwritten")
	}
	if i, err := os.Lstat(path); err != nil || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm() != 0o600 {
		t.Fatal(i, err)
	}
	shared := filepath.Join(dir, "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := SaveCredentials(filepath.Join(shared, "c.json"), Credentials{}); err == nil {
		t.Fatal("world-writable directory accepted")
	}
}
