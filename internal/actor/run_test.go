package actor_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	_ "github.com/JulianStremel/netnoodle/internal/actor/logactor"
	"github.com/JulianStremel/netnoodle/internal/client"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

type panicBackend struct{ called int }

func (b *panicBackend) Name() string { return "panic" }
func (b *panicBackend) Capabilities() []proto.Capability {
	return []proto.Capability{{Action: "isolate", TargetIDKinds: []string{"mac"}}}
}
func (b *panicBackend) Execute(context.Context, proto.Order) (string, error) {
	b.called++
	panic("boom")
}
func TestActorSafetyChecks(t *testing.T) {
	for _, test := range []string{"signature", "wrong actor", "expired", "every target", "empty allow", "rate", "dry run", "panic", "far future"} {
		t.Run(test, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			cfg := actor.Config{NonceFile: filepath.Join(t.TempDir(), "nonces"), MaxPerHour: 1, Backends: []registry.Spec{{Type: "log"}}, Allow: []actor.AllowRule{{Action: "isolate", Targets: []string{"mac=aa:*"}}}}
			r, e := actor.NewRunner(cfg, client.Credentials{Role: "actor", Name: "actor", OrderKey: orders.PublicKey(key)})
			if e != nil {
				t.Fatal(e)
			}
			b := &panicBackend{}
			r.Backends = []actor.Backend{b}
			now := time.Now().UTC()
			r.Now = func() time.Time { return now }
			o := proto.Order{Version: proto.Version, ID: "one", Actor: "actor", Action: "isolate", Nonce: "nonce", NotAfter: now.Add(time.Minute), Targets: []proto.Identifier{{Kind: "mac", Value: "aa:bb", Strength: proto.Strong}}}
			expected := proto.OrderRejected
			reason := ""
			switch test {
			case "wrong actor":
				o.Actor = "other"
				reason = "wrong actor"
			case "expired":
				o.NotAfter = now
				reason = "expired"
			case "far future":
				o.NotAfter = now.Add(48 * time.Hour)
				reason = "too far"
			case "every target":
				o.Targets = append(o.Targets, proto.Identifier{Kind: "mac", Value: "bb:cc"})
				reason = "allow list"
			case "empty allow":
				r.Allow = nil
				reason = "allow list"
			case "dry run":
				expected = proto.OrderDone
				reason = "dry run"
			case "panic":
				r.DryRun = false
				expected = proto.OrderFailed
				reason = "backend panic"
			case "rate":
				env, _ := orders.Sign(key, o)
				if r.Handle(context.Background(), env).Status != proto.OrderDone {
					t.Fatal("first order")
				}
				o.Nonce = "second"
				reason = "rate limit"
			case "signature":
				reason = "signature"
			}
			env, _ := orders.Sign(key, o)
			if test == "signature" {
				env.Sig[0] ^= 1
			}
			res := r.Handle(context.Background(), env)
			if res.Status != expected || !strings.Contains(res.Message, reason) {
				t.Fatal(res)
			}
			if test != "panic" && b.called != 0 {
				t.Fatal("unsafe execution")
			}
			if test == "panic" && b.called != 1 {
				t.Fatal("backend not called")
			}
		})
	}
}
