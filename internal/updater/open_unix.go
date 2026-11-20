//go:build !windows

package updater

import (
	"golang.org/x/sys/unix"
	"os"
)

// A writable request may be replaced between Lstat and Open. O_NOFOLLOW stops
// symlink traversal; O_NONBLOCK prevents a substituted FIFO from hanging root.
func openJSON(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), path), nil
}
