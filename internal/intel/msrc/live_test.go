package msrc

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

// TestLive checks a Windows build against the real MSRC API.
// Run: NN_LIVE_MSRC="pkg:generic/microsoft/windows@10.0.26100.1?type=client&release=24H2" go test -run Live ./internal/intel/msrc
func TestLive(t *testing.T) {
	purl := os.Getenv("NN_LIVE_MSRC")
	if purl == "" {
		t.Skip("set NN_LIVE_MSRC to a Windows PURL")
	}
	mi, err := New("msrc", json.RawMessage(`{"months":3}`))
	if err != nil {
		t.Fatal(err)
	}
	mi.(*Matcher).background = false
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	start := time.Now()
	hits, err := mi.Match(ctx, []proto.Component{{PURL: purl}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d hits in %v", len(hits), time.Since(start))
	for i, h := range hits {
		if i < 8 {
			t.Logf("%s %.1f fixed=%s %v", h.Vuln.ID, h.Vuln.Score, h.Fixed, h.Vuln.Facts)
		}
	}
	if len(hits) == 0 {
		t.Error("no hits; an old build should have some")
	}
}
