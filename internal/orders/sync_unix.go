//go:build !windows

package orders

import (
	"os"
	"path/filepath"
)

func syncParent(name string) error {
	d, e := os.Open(filepath.Dir(name))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
