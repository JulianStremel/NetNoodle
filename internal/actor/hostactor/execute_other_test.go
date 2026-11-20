//go:build !linux

package hostactor

import (
	"context"
	"strings"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

func TestNonLinuxRefusesEveryOrder(t *testing.T) {
	f := newFake(t)
	b := build(t, `{"agent":"web01","services":["nginx.service"]}`, f)
	for _, action := range []string{"block-port", "unblock-port", "stop-service", "start-service", "other", ""} {
		msg, err := b.Execute(context.Background(), order(action))
		if msg != "" || err == nil || !strings.Contains(err.Error(), "Linux") || len(f.calls) != 0 {
			t.Fatalf("non-Linux executed %s: message=%q err=%v calls=%+v", action, msg, err, f.calls)
		}
	}
	if _, err := b.Execute(context.Background(), proto.Order{}); err == nil {
		t.Fatal("non-Linux accepted empty order")
	}
	if _, _, err := nativeRunner().Run(context.Background(), "/usr/sbin/nft", nil, ""); err == nil {
		t.Fatal("non-Linux native runner accepted command")
	}
}
