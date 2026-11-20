package decide

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type testDecider struct {
	name string
	p    Proposal
	ok   bool
	err  error
}

func (d testDecider) Name() string { return d.name }
func (d testDecider) Decide(context.Context, Situation) (Proposal, bool, error) {
	return d.p, d.ok, d.err
}

type testGuard struct {
	name string
	f    func(Proposal) (Proposal, error)
}

func (g testGuard) Name() string                                                       { return g.name }
func (g testGuard) Check(_ context.Context, _ Situation, p Proposal) (Proposal, error) { return g.f(p) }
func TestEvaluateInvariants(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		ttl          int64
		tier, want   Tier
	}{
		{"no TTL", "isolate", 0, TierAuto, TierApprove},
		{"irreversible", "delete", 60, TierAuto, TierApprove},
		{"empty auto", "", 60, TierAuto, TierNotify},
		{"empty approve", "", 0, TierApprove, TierNotify},
		{"reversible", "snapshot", 60, TierAuto, TierAuto},
		{"negative TTL", "isolate", -1, TierAuto, TierApprove},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok, e := Evaluate(context.Background(), []Decider{testDecider{"rules", Proposal{Tier: tc.tier, Action: tc.action, TTL: tc.ttl}, true, nil}}, nil, Situation{})
			if e != nil || !ok || p.Tier != tc.want {
				t.Fatalf("%+v %v %v", p, ok, e)
			}
		})
	}
}
func TestEvaluateMonotonic(t *testing.T) {
	ctx := context.Background()
	base := Proposal{Tier: TierApprove, Action: "isolate", TTL: 60, Reason: "base", Params: map[string]any{"nested": map[string]any{"a": "safe"}}}
	ran := 0
	guards := []Guard{
		testGuard{"bad", func(p Proposal) (Proposal, error) {
			p.Tier = TierAuto
			p.Params["nested"].(map[string]any)["a"] = "unsafe"
			return p, nil
		}},
		testGuard{"notify", func(p Proposal) (Proposal, error) {
			ran++
			p.Tier = TierNotify
			p.Reason = "only notify"
			return p, nil
		}},
		testGuard{"last", func(p Proposal) (Proposal, error) { ran++; return p, nil }},
	}
	p, ok, e := Evaluate(ctx, []Decider{testDecider{"base", base, true, nil}, testDecider{"bad-decider", Proposal{Tier: TierAuto, Action: "delete", TTL: 300}, true, nil}}, guards, Situation{})
	if e == nil || !ok || p.Tier != TierNotify || p.Action != "isolate" || p.TTL != 60 || ran != 2 || !reflect.DeepEqual(p.DecidedBy, []string{"base", "notify"}) || p.Params["nested"].(map[string]any)["a"] != "safe" {
		t.Fatalf("%+v, %v, %d", p, e, ran)
	}
}
func TestEvaluateErrorsAndSafer(t *testing.T) {
	for _, a := range []Tier{TierNone, TierNotify, TierApprove, TierAuto} {
		for _, b := range []Tier{TierNone, TierNotify, TierApprove, TierAuto} {
			if Safer(a, b) != Safer(b, a) {
				t.Fatal("asymmetric")
			}
		}
	}
	called := false
	p, ok, e := Evaluate(context.Background(), []Decider{testDecider{"skip", Proposal{}, false, nil}, testDecider{"base", Proposal{Tier: TierAuto, Action: "isolate", TTL: 60}, true, nil}}, []Guard{testGuard{"failed", func(p Proposal) (Proposal, error) { return p, errors.New("store down") }}, testGuard{"last", func(p Proposal) (Proposal, error) { called = true; return p, nil }}}, Situation{})
	if !ok || e == nil || p.Tier != TierApprove || !called {
		t.Fatalf("%+v %v", p, e)
	}
	_, ok, e = Evaluate(context.Background(), nil, nil, Situation{})
	if ok || e != nil {
		t.Fatal("no opinion")
	}
	p, _, e = Evaluate(context.Background(), []Decider{testDecider{"base", Proposal{Tier: TierAuto, Action: "isolate", TTL: 60}, true, nil}, testDecider{"safer", Proposal{Tier: TierApprove, Action: "isolate", TTL: 30, Reason: "review"}, true, nil}}, nil, Situation{})
	if e != nil || p.Tier != TierApprove || p.TTL != 30 || len(p.DecidedBy) != 2 {
		t.Fatalf("%+v %v", p, e)
	}
}
