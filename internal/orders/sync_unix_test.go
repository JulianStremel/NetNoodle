//go:build !windows

package orders

import (
	"path/filepath"
	"testing"
)

func TestParentDirectorySync(t *testing.T) {
	dir := t.TempDir()
	if e := syncParent(filepath.Join(dir, "nonce")); e != nil {
		t.Fatal(e)
	}
	if e := syncParent(filepath.Join(dir, "missing", "outbox")); e == nil {
		t.Fatal("directory sync must report open errors")
	}
}
