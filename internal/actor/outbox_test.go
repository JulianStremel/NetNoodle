package actor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/client"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
)

type testProtocol func(context.Context, string, string, any, any) error

func (p testProtocol) Do(ctx context.Context, m, path string, in, out any) error {
	return p(ctx, m, path, in, out)
}
func TestOutboxRetryClassification(t *testing.T) {
	for _, tc := range []struct {
		message string
		keep    bool
	}{
		{"network unavailable", true}, {"POST /v1/orders/result: 503 down", true},
		{"POST /v1/orders/result: 408 timeout", true}, {"POST /v1/orders/result: 429 busy", true},
		{"POST /v1/orders/result: 400 invalid", false}, {"POST /v1/orders/result: 401 invalid token", false},
		{"POST /v1/orders/result: 409 too late", false}, {"", false},
	} {
		t.Run(tc.message, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outbox")
			o, e := openOutbox(path)
			if e != nil {
				t.Fatal(e)
			}
			result := proto.OrderResult{Version: proto.Version, OrderID: "one", Status: proto.OrderDone, At: time.Now().UTC()}
			if e = o.add(result); e != nil {
				t.Fatal(e)
			}
			var onDisk []proto.OrderResult
			b, e := os.ReadFile(path)
			if e != nil || json.Unmarshal(b, &onDisk) != nil || len(onDisk) != 1 {
				t.Fatal("result not persisted", e)
			}
			e = o.flush(context.Background(), testProtocol(func(context.Context, string, string, any, any) error {
				if tc.message == "" {
					return nil
				}
				return errors.New(tc.message)
			}))
			if e != nil {
				t.Fatal(e)
			}
			reopened, e := openOutbox(path)
			if e != nil || reopened.contains("one") != tc.keep {
				t.Fatal("wrong persisted retry state", reopened, e)
			}
		})
	}
}

func TestRunnerOutboxRestartAndEveryPoll(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	name := filepath.Join(t.TempDir(), "nonce")
	cfg := Config{NonceFile: name}
	creds := client.Credentials{Role: "actor", Name: "actor", OrderKey: orders.PublicKey(key)}
	r, e := NewRunner(cfg, creds)
	if e != nil {
		t.Fatal(e)
	}
	original := proto.OrderResult{Version: proto.Version, OrderID: "lost", Status: proto.OrderDone, Message: "executed before restart", At: time.Now().UTC()}
	if e = r.outbox.add(original); e != nil {
		t.Fatal(e)
	}
	r, e = NewRunner(cfg, creds)
	if e != nil {
		t.Fatal(e)
	}
	attempts, polls := 0, 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := r.Run(ctx, testProtocol(func(_ context.Context, method, path string, in, out any) error {
		if path == "/v1/orders/result" {
			attempts++
			got := in.(proto.OrderResult)
			if got != original {
				t.Fatal(got)
			}
			b, e := os.ReadFile(name + ".outbox")
			if e != nil || len(b) == 0 {
				t.Fatal("send preceded persistence", e)
			}
			return errors.New("POST /v1/orders/result: 503 retry")
		}
		if method == "GET" {
			polls++
			if polls == 2 {
				cancel()
				return context.Canceled
			}
			*out.(*[]orders.Envelope) = nil
		}
		return nil
	}))
	if !errors.Is(err, context.Canceled) || polls != 2 || attempts < 3 {
		t.Fatal(attempts, polls, err)
	}
	r, e = NewRunner(cfg, creds)
	if e != nil || !r.outbox.contains("lost") {
		t.Fatal("lost result after restart", e)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	delivered := false
	err = r.Run(ctx, testProtocol(func(_ context.Context, method, path string, in, out any) error {
		if path == "/v1/orders/result" {
			delivered = true
			return nil
		}
		if path == "/v1/actor/hello" && !delivered {
			t.Fatal("startup did not resend")
		}
		if method == "GET" {
			cancel()
			return context.Canceled
		}
		return nil
	}))
	if !errors.Is(err, context.Canceled) || !delivered {
		t.Fatal(err)
	}
	reopened, e := openOutbox(name + ".outbox")
	if e != nil || len(reopened.results) != 0 {
		t.Fatal(e, reopened)
	}
}

type reversibleBackend struct{}

func (reversibleBackend) Name() string { return "test" }
func (reversibleBackend) Capabilities() []proto.Capability {
	return []proto.Capability{{Action: "isolate", TargetIDKinds: []string{"mac"}, RevertAction: "unisolate"}, {Action: "unisolate", TargetIDKinds: []string{"mac"}}}
}
func (reversibleBackend) Execute(context.Context, proto.Order) (string, error) { return "done", nil }
func TestRevertAllowAndRateExemption(t *testing.T) {
	bs := []Backend{reversibleBackend{}}
	rules := []AllowRule{{Action: "isolate", Targets: []string{"mac=*"}}}
	if e := validateRevertAllow(rules, bs); e == nil {
		t.Fatal("missing revert permission accepted")
	}
	rules = append(rules, AllowRule{Action: "unisolate", Targets: []string{"mac=aa:*"}})
	if e := validateRevertAllow(rules, bs); e == nil {
		t.Fatal("narrower revert permission accepted")
	}
	rules[1].Targets = []string{"mac=*"}
	if e := validateRevertAllow(rules, bs); e != nil {
		t.Fatal(e)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ns, e := orders.OpenNonceStore(filepath.Join(t.TempDir(), "nonce"))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	r := Runner{Name: "actor", Key: key.Public().(ed25519.PublicKey), Nonces: ns, Allow: rules, Backends: bs, MaxPerHour: 1, DryRun: true, Now: func() time.Time { return now }}
	// Reverts are exempt only for a journaled forward order (security review 2026-11-20).
	r.Journal = &Journal{}
	if e := r.Journal.Put("fwd", JournalEntry{Backend: bs[0].Name(), Target: "aa:bb", Action: "isolate"}); e != nil {
		t.Fatal(e)
	}
	for i, tc := range []struct {
		revert bool
		value  string
		want   proto.OrderStatus
	}{
		{true, "aa:bb", proto.OrderDone}, // does not consume the only rate slot
		{false, "aa:bb", proto.OrderDone},
		{true, "aa:bb", proto.OrderDone}, // still executes after the rate limit
		{false, "aa:bb", proto.OrderRejected},
		{true, "", proto.OrderRejected}, // '*' must not authorize an empty target
	} {
		action := "isolate"
		if tc.revert {
			action = "unisolate"
		}
		o := proto.Order{Version: proto.Version, ID: string(rune('a' + i)), Nonce: string(rune('a' + i)), Actor: "actor", Action: action, Revert: tc.revert, NotAfter: now.Add(time.Minute), Targets: []proto.Identifier{{Kind: "mac", Value: tc.value, Strength: proto.Strong}}}
		if tc.revert {
			o.RevertOf = "fwd"
		}
		env, _ := orders.Sign(key, o)
		res := r.Handle(context.Background(), env)
		if res.Status != tc.want {
			t.Fatal(i, res)
		}
	}
}

func TestRunnerPersistsBeforeSendAndStopsOnWriteFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			name := filepath.Join(t.TempDir(), "nonce")
			r, e := NewRunner(Config{NonceFile: name}, client.Credentials{Role: "actor", Name: "actor", OrderKey: orders.PublicKey(key)})
			if e != nil {
				t.Fatal(e)
			}
			r.Now = func() time.Time { return time.Now().UTC() }
			r.Backends = []Backend{reversibleBackend{}}
			r.Allow = []AllowRule{{Action: "isolate", Targets: []string{"mac=*"}}}
			env, e := orders.Sign(key, proto.Order{Version: proto.Version, ID: "executed", Nonce: "one", Actor: "actor", Action: "isolate", NotAfter: time.Now().Add(time.Minute), Targets: []proto.Identifier{{Kind: "mac", Value: "aa:bb", Strength: proto.Strong}}})
			if e != nil {
				t.Fatal(e)
			}
			if fail {
				if e = os.Mkdir(name+".outbox", 0700); e != nil {
					t.Fatal(e)
				}
			}
			polls, sends := 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e = r.Run(ctx, testProtocol(func(_ context.Context, method, path string, in, out any) error {
				if method == "GET" {
					polls++
					if polls == 1 {
						*out.(*[]orders.Envelope) = []orders.Envelope{env}
						return nil
					}
					cancel()
					return context.Canceled
				}
				if path == "/v1/orders/result" {
					sends++
					b, e := os.ReadFile(name + ".outbox")
					if e != nil {
						t.Fatal(e)
					}
					var results []proto.OrderResult
					if e = json.Unmarshal(b, &results); e != nil || len(results) != 1 || results[0].Status != proto.OrderDone || results[0] != in.(proto.OrderResult) {
						t.Fatal("send preceded durable result", results, e)
					}
					return errors.New("network unavailable")
				}
				return nil
			}))
			if fail {
				if e == nil || sends != 0 {
					t.Fatal("sent without durable result", sends, e)
				}
			} else if !errors.Is(e, context.Canceled) || sends < 2 {
				t.Fatal("did not resend on next poll", sends, e)
			}
		})
	}
}

func TestRevertTargetCoverage(t *testing.T) {
	for _, tc := range []struct {
		inverse, forward string
		want             bool
	}{
		{"mac=*", "mac=aa:*", true}, {"mac=aa:*", "mac=aa:bb", true},
		{"mac=aa:*", "mac=*", false}, {"mac=*", "agent=*", false},
		{"agent=*", "agent=host/guest*", false}, {"mac=aa:*", "mac=aa:*", true},
	} {
		if got := coversTarget(tc.inverse, tc.forward); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
