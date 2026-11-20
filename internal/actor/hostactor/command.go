package hostactor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
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
	out, stderr, err := b.runner.Run(ctx, program, args, stdin)
	if len(out) > maxOutput || len(stderr) > maxOutput {
		err = errors.New("output exceeds 1 MiB")
		out = nil
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		detail := strings.TrimSpace(string(stderr))
		if len(detail) > 512 {
			detail = detail[:512]
		}
		return out, fmt.Errorf("host: %s %s: %w; stderr: %s", program, strings.Join(args, " "), err, detail)
	}
	return out, nil
}
