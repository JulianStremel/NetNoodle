package actor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJournalDurabilityPruningAndBindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.journal")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	e := JournalEntry{Backend: "pve", Target: "pve/lab/100", Action: "isolate", Expires: time.Now().Add(time.Hour), Changed: []string{"net0"}}
	if err = j.Put("active", e); err != nil {
		t.Fatal(err)
	}
	// Mutating a returned snapshot must not corrupt durable or in-memory state.
	entries := j.Entries()
	entries["active"].Changed[0] = "net9"
	e.Expires = time.Now().Add(-49 * time.Hour)
	if err = j.Put("old", e); err != nil {
		t.Fatal(err)
	}
	e.Expires = time.Now().Add(-47 * time.Hour)
	if err = j.Put("recent", e); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := j.Entries()["old"]; ok {
		t.Fatal("old entry retained")
	}
	if _, ok := j.Entries()["recent"]; !ok {
		t.Fatal("revert history pruned early")
	}
	got, ok := j.Get("active", "pve", "pve/lab/100", "isolate")
	if !ok || got.Changed[0] != "net0" {
		t.Fatal(got)
	}
	for _, args := range [][4]string{{"active", "other", "pve/lab/100", "isolate"}, {"active", "pve", "pve/lab/101", "isolate"}, {"active", "pve", "pve/lab/100", "snapshot"}} {
		if _, ok = j.Get(args[0], args[1], args[2], args[3]); ok {
			t.Fatal("journal binding bypass")
		}
	}
	// Failed durable writes must leave the previous in-memory state intact.
	j.path = filepath.Join(path, "not-a-directory")
	if err = j.Put("failed", e); err == nil {
		t.Fatal("write unexpectedly succeeded")
	}
	if _, ok := j.Entries()["failed"]; ok {
		t.Fatal("failed write committed")
	}
	if err = os.WriteFile(path, []byte(`null`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenJournal(path); err == nil {
		t.Fatal("invalid journal accepted")
	}
}
