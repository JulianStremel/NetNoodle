// Package guards implements the final safety checks on recorded proposals.
package guards

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/decide/rules"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

type guard struct {
	name, kind string
	networks   []string
	perHour    int
	settings   decide.Settings
	mu         sync.Mutex
	times      []time.Time
	now        func() time.Time
}

func init() {
	for _, kind := range []string{"protected", "scope", "rate", "killswitch"} {
		decide.Guards.Register(kind, func(name string, raw json.RawMessage) (decide.Guard, error) {
			g := &guard{name: name, kind: kind, perHour: 10, now: time.Now}
			switch kind {
			case "scope":
				var c struct {
					Networks []string `json:"networks"`
				}
				if e := registry.Decode(raw, &c); e != nil {
					return nil, e
				}
				for _, n := range c.Networks {
					if _, e := netip.ParsePrefix(n); e != nil {
						return nil, e
					}
				}
				g.networks = c.Networks
			case "rate":
				c := struct {
					PerHour int `json:"per_hour"`
				}{10}
				if e := registry.Decode(raw, &c); e != nil {
					return nil, e
				}
				if c.PerHour < 1 {
					return nil, fmt.Errorf("per_hour must be positive")
				}
				g.perHour = c.PerHour
			default:
				if e := registry.Decode(raw, &struct{}{}); e != nil {
					return nil, e
				}
			}
			return g, nil
		})
	}
}
func (g *guard) Name() string                  { return g.name }
func (g *guard) SetSettings(s decide.Settings) { g.settings = s }
func (g *guard) Check(ctx context.Context, s decide.Situation, p decide.Proposal) (decide.Proposal, error) {
	if p.Tier != decide.TierAuto {
		return p, nil
	}
	reason := ""
	switch g.kind {
	case "protected":
		if slices.Contains(s.Device.Tags, "protected") {
			reason = "protected device requires approval"
		}
	case "scope":
		if !slices.Contains(s.Device.Tags, "auto") && !rules.InNetworks(s, g.networks) {
			reason = "outside automatic scope"
		}
	case "rate":
		// Sliding window is in memory: restarting the server resets this limit.
		g.mu.Lock()
		now := g.now()
		i := 0
		for i < len(g.times) && !g.times[i].After(now.Add(-time.Hour)) {
			i++
		}
		g.times = append([]time.Time(nil), g.times[i:]...)
		if len(g.times) >= g.perHour {
			reason = "hourly automatic proposal limit reached"
		} else {
			g.times = append(g.times, now)
		}
		g.mu.Unlock()
	case "killswitch":
		if g.settings == nil {
			return p, fmt.Errorf("settings not injected")
		}
		v, e := g.settings.GetSetting(ctx, "decide.killswitch")
		if e != nil {
			return p, e
		}
		if v == "on" {
			reason = "kill switch is on"
		}
	}
	if reason != "" {
		p.Tier = decide.TierApprove
		p.Reason = reason
	}
	return p, nil
}
