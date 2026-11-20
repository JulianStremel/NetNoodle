package actor_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/client"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

type reviewBackend struct {
	caps    []proto.Capability
	message string
	err     error
	calls   int
	journal *actor.Journal
}

func (b *reviewBackend) Name() string                     { return "review" }
func (b *reviewBackend) Capabilities() []proto.Capability { return b.caps }
func (b *reviewBackend) Execute(context.Context, proto.Order) (string, error) {
	b.calls++
	return b.message, b.err
}

func reviewRunner(t *testing.T) (*actor.Runner, func(string, string, bool, string) proto.OrderResult) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	r, err := actor.NewRunner(actor.Config{NonceFile: filepath.Join(t.TempDir(), "nonces"), MaxPerHour: 1, Backends: []registry.Spec{{Type: "log"}}, Allow: []actor.AllowRule{{Action: "isolate", Targets: []string{"agent=*", "proxmox.guest=pve/*/*"}}, {Action: "unisolate", Targets: []string{"agent=*", "proxmox.guest=pve/*/*"}}}}, client.Credentials{Role: "actor", Name: "actor", OrderKey: orders.PublicKey(key)})
	if err != nil {
		t.Fatal(err)
	}
	r.DryRun = false
	i := 0
	return r, func(action, kind string, revert bool, target string) proto.OrderResult {
		i++
		o := proto.Order{Version: proto.Version, ID: fmt.Sprint(i), Actor: "actor", Action: action, Nonce: fmt.Sprint(i), NotAfter: time.Now().Add(time.Minute), Targets: []proto.Identifier{{Kind: kind, Value: target}}, Revert: revert}
		env, e := orders.Sign(key, o)
		if e != nil {
			t.Fatal(e)
		}
		return r.Handle(context.Background(), env)
	}
}

func TestRevertRateExemption(t *testing.T) {
	for _, forward := range []bool{true, false} {
		t.Run(fmt.Sprint(forward), func(t *testing.T) {
			r, handle := reviewRunner(t)
			b := &reviewBackend{caps: []proto.Capability{{Action: "isolate", TargetIDKinds: []string{"agent"}, RevertAction: "unisolate"}, {Action: "unisolate", TargetIDKinds: []string{"agent"}}}}
			r.Backends = []actor.Backend{b}
			// Merely naming an inverse action does not grant the exemption.
			action := "isolate"
			if !forward {
				action = "unisolate"
			}
			if got := handle(action, "agent", false, "web01"); got.Status != proto.OrderDone {
				t.Fatal(got)
			}
			if got := handle("isolate", "agent", true, "web01"); got.Status != proto.OrderRejected || got.Message != "invalid revert action" {
				t.Fatal(got)
			}
			if got := handle("unisolate", "agent", false, "web01"); got.Status != proto.OrderRejected || !strings.Contains(got.Message, "rate limit") {
				t.Fatal(got)
			}
			if got := handle("unisolate", "agent", true, "web01"); got.Status != proto.OrderDone {
				t.Fatal(got)
			}
			if b.calls != 2 {
				t.Fatal(b.calls)
			}
		})
	}
}

func TestUncertainAndUTF8ResultMessages(t *testing.T) {
	for _, tc := range []struct {
		message string
		err     error
		status  proto.OrderStatus
	}{
		{strings.Repeat("x", 3999) + "€tail", nil, proto.OrderDone},
		{"", fmt.Errorf("verification: %w", actor.ErrPossiblyApplied), proto.OrderUncertain},
		{"", errors.New(strings.Repeat("界", 2000)), proto.OrderFailed},
		{strings.Repeat("x", 3998) + "😀", nil, proto.OrderDone},
		{"bad\xfftext", nil, proto.OrderDone},
	} {
		t.Run(string(tc.status)+fmt.Sprint(len(tc.message)), func(t *testing.T) {
			r, handle := reviewRunner(t)
			b := &reviewBackend{caps: []proto.Capability{{Action: "isolate", TargetIDKinds: []string{"agent"}}}, message: tc.message, err: tc.err}
			r.Backends = []actor.Backend{b}
			got := handle("isolate", "agent", false, "web01")
			if got.Status != tc.status || len(got.Message) > 4000 || !utf8.ValidString(got.Message) {
				t.Fatal(got)
			}
			if tc.status == proto.OrderUncertain && !strings.HasPrefix(got.Message, "possibly applied: ") {
				t.Fatal(got)
			}
			if len(tc.message) > 4000 && (!strings.HasPrefix(tc.message, got.Message) || len(got.Message) < 3998) {
				t.Fatal("incorrect rune boundary")
			}
		})
	}
}

func TestBackendScopeRouting(t *testing.T) {
	for _, tc := range []struct {
		kind, target, scope string
		allowed             bool
	}{
		{"agent", "web02", "agent=web02", true}, {"agent", "web02", "agent=web03", false},
		{"proxmox.guest", "pve/lab/100", "proxmox.guest=pve/*", true},
		{"proxmox.guest", "pve/lab/100", "proxmox.guest=other/*", false},
		{"agent", "web02", "", true},
	} {
		t.Run(tc.target+tc.scope, func(t *testing.T) {
			r, handle := reviewRunner(t)
			first := &reviewBackend{caps: []proto.Capability{{Action: "isolate", TargetIDKinds: []string{tc.kind}, TargetScope: []string{tc.kind + "=wrong"}}}}
			second := &reviewBackend{caps: []proto.Capability{{Action: "isolate", TargetIDKinds: []string{tc.kind}}}}
			if tc.scope != "" {
				second.caps[0].TargetScope = []string{tc.scope}
			}
			r.Backends = []actor.Backend{first, second}
			got := handle("isolate", tc.kind, false, tc.target)
			if (got.Status == proto.OrderDone) != tc.allowed || first.calls != 0 || (second.calls == 1) != tc.allowed {
				t.Fatal(got, first.calls, second.calls)
			}
		})
	}
}

func (b *reviewBackend) SetJournal(j *actor.Journal) { b.journal = j }
func init() {
	actor.Registry.Register("review-journal-test", func(string, json.RawMessage) (actor.Backend, error) { return &reviewBackend{}, nil })
}

func TestRunnerInjectsDurableJournal(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "nonces")
	r, err := actor.NewRunner(actor.Config{NonceFile: path, Backends: []registry.Spec{{Type: "review-journal-test"}}}, client.Credentials{Role: "actor", OrderKey: orders.PublicKey(key)})
	if err != nil {
		t.Fatal(err)
	}
	b := r.Backends[0].(*reviewBackend)
	if b.journal == nil || b.journal != r.Journal {
		t.Fatal("journal not injected")
	}
	if err = b.journal.Put("persisted", actor.JournalEntry{Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	reopened, err := actor.OpenJournal(path + ".journal")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Entries()["persisted"]; !ok {
		t.Fatal("journal not next to nonce file")
	}
}
