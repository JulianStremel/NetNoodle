package scan

import (
	"errors"
	"syscall"
)

// wsaeconnrefused is the Windows error for a refused connection. Go does
// not map it to syscall.ECONNREFUSED on Windows.
const wsaeconnrefused = 10061

// isRefused is true if the host answered with a TCP reset, so it is up.
func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == wsaeconnrefused
}
