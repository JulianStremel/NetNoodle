// Package rules implements ordered operator decision rules.
package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

type When struct {
	Reachable      string   `json:"reachable"`
	MinScore       *float64 `json:"min_score"`
	MaxScore       *float64 `json:"max_score"`
	KEV            *bool    `json:"kev"`
	MinEPSS        *float64 `json:"min_epss"`
	Exposed        *bool    `json:"exposed"`
	Kinds          []string `json:"kinds"`
	TagsAny        []string `json:"tags_any"`
	TagsNone       []string `json:"tags_none"`
	Networks       []string `json:"networks"`
	Confidence     string   `json:"confidence"`
	MinRelatedRisk *float64 `json:"min_related_risk"`
}
type Then struct {
	Tier   string `json:"tier"`
	Action string `json:"action"`
	// Approve rules may omit TTL: permanent until reverted by an operator.
	TTL    string         `json:"ttl"`
	Params map[string]any `json:"params"`
}
type Rule struct {
	Name string `json:"name"`
	When When   `json:"when"`
	Then Then   `json:"then"`
}
type Settings struct {
	Rules []Rule `json:"rules"`
}
type Rules struct {
	name  string
	rules []Rule
}

func init() { decide.Deciders.Register("rules", New) }
func New(name string, raw json.RawMessage) (decide.Decider, error) {
	var cfg Settings
	if err := registry.Decode(raw, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Rules) > 500 {
		return nil, fmt.Errorf("at most 500 rules")
	}
	names := map[string]bool{}
	for _, r := range cfg.Rules {
		if strings.TrimSpace(r.Name) == "" || names[r.Name] {
			return nil, fmt.Errorf("rule names must be unique and non-empty")
		}
		names[r.Name] = true
		if _, ok := tier(r.Then.Tier); !ok {
			return nil, fmt.Errorf("%s: invalid tier", r.Name)
		}
		if r.Then.Action != "" && !slices.Contains(decide.KnownActions, r.Then.Action) {
			return nil, fmt.Errorf("%s: unknown action %q", r.Name, r.Then.Action)
		}
		if r.Then.TTL != "" {
			d, e := time.ParseDuration(r.Then.TTL)
			if e != nil || d < 0 || (d > 0 && d < time.Second) {
				return nil, fmt.Errorf("%s: invalid TTL", r.Name)
			}
		}
		for _, n := range r.When.Networks {
			if _, e := netip.ParsePrefix(n); e != nil {
				return nil, e
			}
		}
		if r.When.Reachable != "" && !slices.Contains([]string{"local", "tunnel", "internet"}, r.When.Reachable) {
			return nil, fmt.Errorf("%s: invalid reachable level", r.Name)
		}
		if r.When.Confidence != "" && r.When.Confidence != "high" && r.When.Confidence != "low" {
			return nil, fmt.Errorf("invalid confidence")
		}
		for _, v := range []struct {
			p   *float64
			max float64
		}{{r.When.MinScore, 10}, {r.When.MaxScore, 10}, {r.When.MinEPSS, 1}, {r.When.MinRelatedRisk, 10}} {
			if v.p != nil && (*v.p < 0 || *v.p > v.max) {
				return nil, fmt.Errorf("threshold out of range")
			}
		}
		if r.When.MinScore != nil && r.When.MaxScore != nil && *r.When.MinScore > *r.When.MaxScore {
			return nil, fmt.Errorf("min_score exceeds max_score")
		}
	}
	return &Rules{name, cfg.Rules}, nil
}
func tier(s string) (decide.Tier, bool) {
	switch s {
	case "none":
		return decide.TierNone, true
	case "notify":
		return decide.TierNotify, true
	case "approve":
		return decide.TierApprove, true
	case "auto":
		return decide.TierAuto, true
	}
	return decide.TierNone, false
}
func (r *Rules) Name() string { return r.name }
func (r *Rules) RuleNames() []string {
	out := []string{}
	for _, v := range r.rules {
		out = append(out, v.Name)
	}
	return out
}

// InNetworks fails closed: every address must belong to the configured networks.
// Graph-derived network summaries cannot establish trust in a device's addresses.
func InNetworks(s decide.Situation, networks []string) bool {
	if len(s.Device.IPs) == 0 {
		return false
	}
	prefixes := []netip.Prefix{}
	for _, n := range networks {
		p, e := netip.ParsePrefix(n)
		if e != nil {
			return false
		}
		prefixes = append(prefixes, p)
	}
	for _, ip := range s.Device.IPs {
		a, e := netip.ParseAddr(ip)
		if e != nil {
			return false
		}
		inside := false
		for _, p := range prefixes {
			inside = inside || p.Contains(a.Unmap())
		}
		if !inside {
			return false
		}
	}
	return true
}
func matches(w When, s decide.Situation) bool {
	if w.Reachable != "" {
		rank := map[string]int{"local": 0, "tunnel": 1, "internet": 2}
		if rank[s.Device.Reach] < rank[w.Reachable] {
			return false
		}
	}
	if w.MinScore != nil && s.Vuln.Score < *w.MinScore || w.MaxScore != nil && s.Vuln.Score > *w.MaxScore || w.KEV != nil && s.Vuln.KEV != *w.KEV || w.MinEPSS != nil && s.Vuln.EPSS < *w.MinEPSS || w.Exposed != nil && s.Device.Exposed != *w.Exposed || w.Confidence != "" && s.Confidence != w.Confidence || w.MinRelatedRisk != nil && s.RelatedRisk < *w.MinRelatedRisk {
		return false
	}
	if len(w.Kinds) > 0 && !slices.Contains(w.Kinds, s.Device.Kind) {
		return false
	}
	if len(w.TagsAny) > 0 {
		ok := false
		for _, t := range w.TagsAny {
			ok = ok || slices.Contains(s.Device.Tags, t)
		}
		if !ok {
			return false
		}
	}
	for _, t := range w.TagsNone {
		if slices.Contains(s.Device.Tags, t) {
			return false
		}
	}
	return len(w.Networks) == 0 || InNetworks(s, w.Networks)
}
func (r *Rules) Decide(_ context.Context, s decide.Situation) (decide.Proposal, bool, error) {
	for _, v := range r.rules {
		if matches(v.When, s) {
			t, _ := tier(v.Then.Tier)
			d, _ := time.ParseDuration(v.Then.TTL)
			params := map[string]any{}
			b, _ := json.Marshal(v.Then.Params)
			_ = json.Unmarshal(b, &params)
			return decide.Proposal{Tier: t, Action: v.Then.Action, TTL: int64(d / time.Second), Params: params, Reason: "rule " + v.Name}, true, nil
		}
	}
	return decide.Proposal{}, false, nil
}

// VPN/internet KEV findings require approval only when the vulnerable
// component has an exposed listener; a VPN interface alone is insufficient.
var DefaultRules = json.RawMessage(`{"rules":[{"name":"kev-reachable","when":{"kev":true,"exposed":true,"reachable":"tunnel"},"then":{"tier":"approve","action":"isolate","ttl":"24h"}},{"name":"kev-exposed","when":{"kev":true,"exposed":true},"then":{"tier":"approve","action":"isolate","ttl":"24h"}},{"name":"critical-exposed","when":{"min_score":9,"exposed":true},"then":{"tier":"approve","action":"block-port","ttl":"24h"}},{"name":"kev","when":{"kev":true},"then":{"tier":"notify"}},{"name":"high","when":{"min_score":7},"then":{"tier":"notify"}}]}`)
