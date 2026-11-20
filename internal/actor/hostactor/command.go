package hostactor

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/JulianStremel/netnoodle/internal/actor"
)

// cappedBuffer drains excess output without retaining it. A noisy command
// cannot grow memory or deadlock on a full stdout/stderr pipe.
type cappedBuffer struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *cappedBuffer) Len() int      { return b.buffer.Len() }
func (b *cappedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := maxOutput - b.Len()
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

func (b *Backend) command(ctx context.Context, program string, args []string, stdin string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	if (program == b.settings.NFT && stdin != "") || (program == b.settings.Systemctl && len(args) > 0 && (args[0] == "start" || args[0] == "stop")) {
		trackMutation(ctx)
	}
	out, stderr, err := b.runner.Run(ctx, program, args, stdin)
	overflow := len(out) > maxOutput || len(stderr) > maxOutput
	if overflow {
		err = errors.New("output exceeds 1 MiB")
		out = nil
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		var exit interface{ ExitCode() int }
		code := -1
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		if overflow {
			return out, errors.New("host: command output exceeds 1 MiB")
		}
		return out, commandError(code)
	}
	return out, nil
}

type commandError int

func (e commandError) Error() string { return fmt.Sprintf("host: command failed (rc %d)", int(e)) }
func (e commandError) ExitCode() int { return int(e) }

type mutationKey struct{}

func trackMutation(ctx context.Context) {
	if sent, ok := ctx.Value(mutationKey{}).(*bool); ok {
		*sent = true
	}
}
func uncertain(err error) error { return fmt.Errorf("%w: %w", actor.ErrPossiblyApplied, err) }
