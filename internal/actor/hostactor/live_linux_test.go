//go:build linux

package hostactor

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

// TestLiveNFT runs against the real nft binary. It needs CAP_NET_ADMIN and is
// opt-in: NN_LIVE_NFT=1 go test -run LiveNFT ./internal/actor/hostactor
func TestLiveNFT(t *testing.T) {
	if os.Getenv("NN_LIVE_NFT") != "1" {
		t.Skip("set NN_LIVE_NFT=1 (needs nft and CAP_NET_ADMIN)")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed")
	}
	raw, _ := json.Marshal(map[string]any{"agent": "web01", "nft": nft, "max_ttl": "1h"})
	b, err := New("host", raw)
	if err != nil {
		t.Fatal(err)
	}
	order := func(action string) proto.Order {
		return proto.Order{Action: action, TTL: 600, Targets: []proto.Identifier{{Kind: "agent", Value: "web01", Strength: proto.Strong}},
			Params: map[string]any{"ports": []any{"443/tcp", "53/udp"}}}
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ { // twice: the structure must be idempotent
		if msg, err := b.Execute(ctx, order("block-port")); err != nil {
			t.Fatalf("block: %v", err)
		} else {
			t.Log(msg)
		}
	}
	out, _ := exec.Command(nft, "-y", "list", "table", "inet", "netnoodle").CombinedOutput()
	s := string(out)
	t.Log(s)
	if !strings.Contains(s, "443") || !strings.Contains(s, "53") || strings.Count(s, "@blocked_tcp") != 2 || strings.Count(s, "ct state established,related accept") != 2 || !strings.Contains(s, "hook prerouting priority mangle") && !strings.Contains(s, "hook prerouting priority -150") || !strings.Contains(s, "timeout") {
		t.Fatalf("unexpected ruleset:\n%s", s)
	}
	for _, chain := range []string{"input", "prerouting"} {
		out, e := exec.Command(nft, "-j", "list", "chain", "inet", "netnoodle", chain).Output()
		if e != nil {
			t.Fatal(e)
		}
		var doc nftDocument
		if e = json.Unmarshal(out, &doc); e != nil {
			t.Fatal(e)
		}
		seen := [4]bool{}
		dropSeen := false
		for _, entry := range doc.Nftables {
			if entry.Rule == nil {
				continue
			}
			k := ruleKind(entry.Rule.Expr)
			if k < 0 {
				continue
			}
			if seen[k] {
				t.Fatalf("duplicate rule in %s", chain)
			}
			seen[k] = true
			if k == 1 || k == 2 {
				dropSeen = true
			} else if dropSeen {
				t.Fatalf("late accept rule in %s", chain)
			}
		}
		for _, ok := range seen {
			if !ok {
				t.Fatalf("missing protection in %s", chain)
			}
		}
	}
	if _, err := b.Execute(ctx, order("unblock-port")); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	out, _ = exec.Command(nft, "list", "set", "inet", "netnoodle", "blocked_tcp").CombinedOutput()
	if strings.Contains(string(out), "443") {
		t.Fatalf("element still present:\n%s", out)
	}
	if _, err := b.Execute(ctx, proto.Order{Action: "block-port", TTL: 60, Targets: []proto.Identifier{{Kind: "agent", Value: "web01"}},
		Params: map[string]any{"ports": []any{"22/tcp"}}}); err == nil {
		t.Fatal("port 22 blocked")
	}
}
