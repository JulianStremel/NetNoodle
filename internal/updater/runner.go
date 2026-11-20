package updater

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Runner never invokes a shell. Env contains explicit overrides only.
type Runner interface {
	Run(context.Context, []string, string, ...string) (string, error)
}
type ExecRunner struct{ Timeout time.Duration }
type capped struct {
	mu sync.Mutex
	b  []byte
}

func (b *capped) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if left := MaxJSON - len(b.b); left > 0 {
		b.b = append(b.b, p[:min(left, n)]...)
	}
	return n, nil
}
func (r ExecRunner) Run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Env = os.Environ()
	for _, v := range env {
		k, _, _ := strings.Cut(v, "=")
		for i := len(c.Env) - 1; i >= 0; i-- {
			if strings.HasPrefix(c.Env[i], k+"=") {
				c.Env = append(c.Env[:i], c.Env[i+1:]...)
			}
		}
		c.Env = append(c.Env, v)
	}
	var out, stderr capped
	c.Stdout = &out
	c.Stderr = &stderr
	err := c.Run()
	if err != nil {
		return string(out.b), fmt.Errorf("%s: %w: %s", name, err, stderr.b[:min(len(stderr.b), 4096)])
	}
	return string(out.b), nil
}
