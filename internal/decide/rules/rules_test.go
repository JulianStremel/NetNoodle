package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/intel"
)

func TestWhenFields(t *testing.T) {
	s := decide.Situation{Device: decide.Device{Kind: "host", Tags: []string{"auto", "lan"}, Exposed: true, IPs: []string{"10.1.2.34"}}, Vuln: intel.Vuln{Score: 8, KEV: true, EPSS: .6}, Confidence: "high", Networks: []string{"10.1.2.0/24"}, RelatedRisk: 7}
	for _, tc := range []struct{ field, yes, no string }{
		{"min_score", "8", "8.1"}, {"max_score", "8", "7.9"}, {"kev", "true", "false"}, {"min_epss", "0.6", "0.7"}, {"exposed", "true", "false"},
		{"kinds", `["vm","host"]`, `["vm"]`}, {"tags_any", `["dmz","lan"]`, `["dmz"]`}, {"tags_none", `["protected"]`, `["auto"]`},
		{"networks", `["10.1.2.34/32"]`, `["10.1.2.35/32"]`}, {"confidence", `"high"`, `"low"`}, {"min_related_risk", "7", "7.1"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			for i, v := range []string{tc.yes, tc.no} {
				raw := json.RawMessage(fmt.Sprintf(`{"rules":[{"name":"one","when":{%q:%s},"then":{"tier":"notify"}}]}`, tc.field, v))
				r, e := New("rules", raw)
				if e != nil {
					t.Fatal(e)
				}
				_, ok, e := r.Decide(context.Background(), s)
				if e != nil || ok != (i == 0) {
					t.Fatalf("%s match=%v err=%v", v, ok, e)
				}
			}
		})
	}
	r, e := New("defaults", DefaultRules)
	if e != nil {
		t.Fatal(e)
	}
	p, ok, e := r.Decide(context.Background(), s)
	if e != nil || !ok || p.Action != "isolate" || p.Tier != decide.TierApprove || p.TTL != 86400 {
		t.Fatalf("%+v %v", p, e)
	}
}
func TestSettingsValidation(t *testing.T) {
	for _, raw := range []string{
		`{"unknown":true}`, `{"rules":[{"name":"","then":{"tier":"notify"}}]}`,
		`{"rules":[{"name":"a","then":{"tier":"notify"}},{"name":"a","then":{"tier":"none"}}]}`,
		`{"rules":[{"name":"a","when":{"unknown":1},"then":{"tier":"notify"}}]}`,
		`{"rules":[{"name":"a","when":{"networks":["nope"]},"then":{"tier":"notify"}}]}`,
		`{"rules":[{"name":"a","when":{"confidence":"medium"},"then":{"tier":"notify"}}]}`,
		`{"rules":[{"name":"a","then":{"tier":"run"}}]}`,
		`{"rules":[{"name":"a","then":{"tier":"auto","ttl":"soon"}}]}`,
		`{"rules":[{"name":"a","then":{"tier":"auto","ttl":"-1h"}}]}`,
		`{"rules":[{"name":"a","when":{"min_score":11},"then":{"tier":"none"}}]}`,
		`{"rules":[{"name":"a","when":{"min_score":8,"max_score":7},"then":{"tier":"none"}}]}`,
	} {
		if _, e := New("r", json.RawMessage(raw)); e == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	list := []string{}
	for i := range 501 {
		list = append(list, fmt.Sprintf(`{"name":"r%d","then":{"tier":"notify"}}`, i))
	}
	if _, e := New("r", json.RawMessage(`{"rules":[`+strings.Join(list, ",")+`]}`)); e == nil {
		t.Fatal("501 rules accepted")
	}
}
func TestANDAndNetworks(t *testing.T) {
	var w When
	_ = json.Unmarshal([]byte(`{"kev":true,"exposed":true,"min_score":9}`), &w)
	if matches(w, decide.Situation{Vuln: intel.Vuln{KEV: true, Score: 9}}) {
		t.Fatal("conditions must all match")
	}
	if InNetworks(decide.Situation{Networks: []string{"10.0.1.0/24"}}, []string{"10.0.1.1/32"}) {
		t.Fatal("narrow CIDR must not admit a whole network")
	}
}

func TestNetworkTrustRequiresAllAddresses(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  []string
		want bool
	}{
		{"no addresses", nil, false},
		{"inside", []string{"10.1.2.3", "10.9.8.7"}, true},
		{"mixed", []string{"10.1.2.3", "203.0.113.1"}, false},
		{"mixed reversed", []string{"203.0.113.1", "10.1.2.3"}, false},
		{"invalid", []string{"10.1.2.3", "invalid"}, false},
		{"IPv6 outside", []string{"10.1.2.3", "2001:db8::1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := decide.Situation{Device: decide.Device{IPs: tc.ips}, Networks: []string{"10.0.0.0/8"}}
			if got := InNetworks(s, []string{"10.0.0.0/8"}); got != tc.want {
				t.Fatalf("InNetworks=%v want %v", got, tc.want)
			}
			if got := matches(When{Networks: []string{"10.0.0.0/8"}}, s); got != tc.want {
				t.Fatalf("rule matches=%v want %v", got, tc.want)
			}
		})
	}
}

func TestTTLAndActionValidation(t *testing.T) {
	for _, ttl := range []string{"1ns", "500ms", "999999999ns"} {
		if _, err := New("rules", json.RawMessage(fmt.Sprintf(`{"rules":[{"name":"r","then":{"tier":"approve","action":"isolate","ttl":%q}}]}`, ttl))); err == nil {
			t.Errorf("accepted TTL %s", ttl)
		}
	}
	for _, ttl := range []string{"", "0s", "1s", "1500ms"} {
		r, err := New("rules", json.RawMessage(fmt.Sprintf(`{"rules":[{"name":"r","then":{"tier":"approve","action":"isolate","ttl":%q}}]}`, ttl)))
		if err != nil {
			t.Fatal(ttl, err)
		}
		p, _, err := r.Decide(context.Background(), decide.Situation{})
		if err != nil || (ttl == "" && p.TTL != 0) {
			t.Fatal(p, err)
		}
	}
	for _, action := range append(append([]string(nil), decide.KnownActions...), "", "delete", "isolte") {
		_, err := New("rules", json.RawMessage(fmt.Sprintf(`{"rules":[{"name":"r","then":{"tier":"approve","action":%q}}]}`, action)))
		unknown := action == "delete" || action == "isolte"
		if (err != nil) != unknown {
			t.Fatalf("action %q: %v", action, err)
		}
	}
}

func TestReachable(t *testing.T) {
	levels := []string{"local", "tunnel", "internet"}
	for i, want := range levels {
		r, err := New("r", json.RawMessage(fmt.Sprintf(`{"rules":[{"name":"reachable","when":{"reachable":%q},"then":{"tier":"notify"}}]}`, want)))
		if err != nil {
			t.Fatal(err)
		}
		for j, got := range levels {
			_, ok, err := r.Decide(context.Background(), decide.Situation{Device: decide.Device{Reach: got}})
			if err != nil || ok != (j >= i) {
				t.Errorf("want >= %s, device %s: %v %v", want, got, ok, err)
			}
		}
	}
	for _, invalid := range []string{"vpn", "Internet", "remote"} {
		if _, err := New("r", json.RawMessage(fmt.Sprintf(`{"rules":[{"name":"r","when":{"reachable":%q},"then":{"tier":"notify"}}]}`, invalid))); err == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}

func TestDefaultReachableKEV(t *testing.T) {
	r, err := New("default", DefaultRules)
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"local", "tunnel", "internet"} {
		for _, exposed := range []bool{false, true} {
			s := decide.Situation{Device: decide.Device{Reach: level, Exposed: exposed}, Vuln: intel.Vuln{KEV: true}}
			p, ok, err := r.Decide(context.Background(), s)
			if !ok || err != nil {
				t.Fatal(p, ok, err)
			}
			if exposed {
				reason := "rule kev-reachable"
				if level == "local" {
					reason = "rule kev-exposed"
				}
				if p.Reason != reason || p.Tier != decide.TierApprove || p.Action != "isolate" || p.TTL != 86400 {
					t.Fatalf("%s: %+v", level, p)
				}
			} else if p.Tier != decide.TierNotify || p.Reason != "rule kev" {
				t.Fatalf("unexposed %s: %+v", level, p)
			}
		}
	}
}
