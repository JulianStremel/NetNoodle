//go:build linux

package hostactor

import (
	"context"
	"testing"
)

func TestLinuxExecuteUsesRunner(t *testing.T) {
	f := newFake(t)
	b := build(t, `{"agent":"web01"}`, f)
	if _, err := b.Execute(context.Background(), order("block-port")); err != nil || len(f.calls) != 6 {
		t.Fatalf("Linux execution: %v, calls=%+v", err, f.calls)
	}
}
