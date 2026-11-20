package guards

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/intel"
)

type settings struct {
	v   string
	err error
}

func TestScopeTrustRequiresAllAddresses(t *testing.T) {
	g := build(t, "scope", `{"networks":["10.0.0.0/8"]}`)
	for _, tags := range [][]string{nil, {"auto"}} {
		for _, ips := range [][]string{nil, {"10.1.2.3", "203.0.113.1"}, {"10.1.2.3", "bad"}} {
			p, err := g.Check(context.Background(), decide.Situation{Device: decide.Device{IPs: ips, Tags: tags}, Networks: []string{"10.0.0.0/8"}}, decide.Proposal{Tier: decide.TierAuto})
			if err != nil || p.Tier != decide.TierApprove {
				t.Fatal(ips, tags, p, err)
			}
		}
	}
}

func TestRateCountsDistinctProposalKeys(t *testing.T) {
	g := build(t, "rate", `{"per_hour":3}`)
	now := time.Now()
	g.now = func() time.Time { return now }
	s := decide.Situation{Device: decide.Device{ID: 1}, Vuln: intel.Vuln{ID: "v1"}}
	p := decide.Proposal{Tier: decide.TierAuto, Action: "isolate"}
	check := func(s decide.Situation, p decide.Proposal, want decide.Tier) {
		t.Helper()
		out, err := g.Check(context.Background(), s, p)
		if err != nil || out.Tier != want {
			t.Fatal(out, err)
		}
	}
	for range 100 {
		check(s, p, decide.TierAuto)
	}
	s.Vuln.ID = "v2"
	check(s, p, decide.TierAuto)
	p.Action = "snapshot"
	check(s, p, decide.TierAuto)
	s.Device.ID = 2
	check(s, p, decide.TierApprove)
	s.Device.ID = 1
	check(s, p, decide.TierAuto) // Existing keys still pass at capacity.
	now = now.Add(time.Hour)
	s.Device.ID = 2
	check(s, p, decide.TierAuto)
	if len(g.times) != 1 {
		t.Fatal("expired keys retained", g.times)
	}
}

func (s settings) GetSetting(context.Context, string) (string, error) { return s.v, s.err }
func build(t *testing.T, kind, raw string) *guard {
	t.Helper()
	g, e := decide.Guards.Build(kind, kind, json.RawMessage(raw))
	if e != nil {
		t.Fatal(e)
	}
	return g.(*guard)
}
func TestGuards(t *testing.T) {
	ctx := context.Background()
	auto := decide.Proposal{Tier: decide.TierAuto, Action: "isolate", TTL: 60}
	for _, tc := range []struct {
		kind, raw string
		s         decide.Situation
		want      decide.Tier
	}{
		{"protected", `{}`, decide.Situation{Device: decide.Device{Tags: []string{"protected"}}}, decide.TierApprove},
		{"protected", `{}`, decide.Situation{}, decide.TierAuto},
		{"scope", `{}`, decide.Situation{}, decide.TierApprove},
		{"scope", `{}`, decide.Situation{Device: decide.Device{Tags: []string{"auto"}}}, decide.TierApprove},
		{"scope", `{"networks":["10.1.2.3/32"]}`, decide.Situation{Device: decide.Device{IPs: []string{"10.1.2.3"}}}, decide.TierAuto},
		{"scope", `{"networks":["10.1.2.3/32"]}`, decide.Situation{Device: decide.Device{IPs: []string{"10.1.2.4"}}}, decide.TierApprove},
	} {
		g := build(t, tc.kind, tc.raw)
		p, e := g.Check(ctx, tc.s, auto)
		if e != nil || p.Tier != tc.want {
			t.Fatalf("%s %+v %v", tc.kind, p, e)
		}
	}
	g := build(t, "killswitch", `{}`)
	for _, v := range []string{"on", "off"} {
		g.SetSettings(settings{v: v})
		p, e := g.Check(ctx, decide.Situation{}, auto)
		if e != nil || (p.Tier == decide.TierApprove) != (v == "on") {
			t.Fatalf("%s %+v %v", v, p, e)
		}
	}
	g.SetSettings(settings{err: errors.New("store down")})
	if _, e := g.Check(ctx, decide.Situation{}, auto); e == nil {
		t.Fatal("missing error")
	}
}
func TestRateSlidingWindow(t *testing.T) {
	g := build(t, "rate", `{"per_hour":2}`)
	now := time.Now()
	g.now = func() time.Time { return now }
	p := decide.Proposal{Tier: decide.TierAuto}
	for i := range 3 {
		out, e := g.Check(context.Background(), decide.Situation{Device: decide.Device{ID: int64(i)}}, p)
		if e != nil || (out.Tier == decide.TierAuto) != (i < 2) {
			t.Fatalf("%d %+v %v", i, out, e)
		}
	}
	now = now.Add(time.Hour)
	out, _ := g.Check(context.Background(), decide.Situation{}, p)
	if out.Tier != decide.TierAuto {
		t.Fatal("window did not slide")
	}
	for _, kind := range []string{"protected", "scope", "rate", "killswitch"} {
		g := build(t, kind, `{}`)
		out, e := g.Check(context.Background(), decide.Situation{}, decide.Proposal{Tier: decide.TierNotify})
		if e != nil || out.Tier != decide.TierNotify {
			t.Fatal("changed safe tier")
		}
	}
}
func TestGuardSettings(t *testing.T) {
	for _, tc := range []struct{ kind, raw string }{{"scope", `{"networks":["bad"]}`}, {"rate", `{"per_hour":0}`}, {"rate", `{"per_hour":-1}`}, {"protected", `{"extra":1}`}, {"killswitch", `{"on":true}`}} {
		if _, e := decide.Guards.Build(tc.kind, tc.kind, json.RawMessage(tc.raw)); e == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
