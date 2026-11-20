//go:build linux

package hostactor

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

type execRunner struct{}

func nativeRunner() Runner { return execRunner{} }

func (execRunner) Run(ctx context.Context, program string, args []string, stdin string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr cappedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// Bound pipe draining too, in case a descendant inherits the output fds.
	cmd.WaitDelay = commandTimeout
	err := cmd.Run()
	if stdout.overflow || stderr.overflow {
		err = errors.New("output exceeds 1 MiB")
	}
	return stdout.Bytes(), stderr.Bytes(), err
}
