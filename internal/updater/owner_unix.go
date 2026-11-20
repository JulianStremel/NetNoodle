//go:build unix

package updater

import (
	"fmt"
	"os"
	"syscall"
)

// ownedBySelf refuses a state directory that another user owns or that
// others can access.
func ownedBySelf(p string) error {
	i, e := os.Lstat(p)
	if e != nil {
		return e
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.IsDir() || int(st.Uid) != os.Geteuid() || i.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state_dir %s must be a directory owned by this user with mode 0700", p)
	}
	return nil
}
