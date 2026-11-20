// Package decide turns findings into proposals for actions.
//
// The pipeline for one Situation is:
//
//	deciders (in order) → combine → guards (all) → Proposal
//
// Deciders propose. Guards can only make a proposal safer (lower the tier,
// require approval, or drop the action). No guard and no later decider can
// widen the scope that an earlier rule-based decider allowed.
package decide

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

// Tier is the level of automation for a proposal.
type Tier int

const (
	TierNone    Tier = -1 // no action at all
	TierNotify  Tier = 0  // notify only
	TierAuto    Tier = 1  // run automatically (must be reversible and have a TTL)
	TierApprove Tier = 2  // run after a human approves
)

func (t Tier) String() string {
	switch t {
	case TierNone:
		return "none"
	case TierNotify:
		return "notify"
	case TierAuto:
		return "auto"
	case TierApprove:
		return "approve"
	}
	return "unknown"
}

// Device is the device context a decider can see.
type Device struct {
	ID       int64
	Name     string
	Kind     string
	Tags     []string
	IPs      []string
	Exposed  bool  // the vulnerable component backs a listening service
	Ports    []int // listening ports of that component
	ParentID int64
}

// Situation is one finding (vulnerability on a device) to decide on.
type Situation struct {
	Networks    []string
	RelatedRisk float64
	FindingID   int64
	Device      Device
	Vuln        intel.Vuln
	Component   string // PURL
	Confidence  string // high | low
}

// Proposal is the outcome. Action is abstract ("isolate", "stop-service",
// "block-port"); the planner maps it to an actor capability.
type Proposal struct {
	Tier      Tier
	Action    string
	Params    map[string]any
	TTL       int64 // seconds, 0 = permanent
	Reason    string
	DecidedBy []string
}

// KnownActions are the reversible actions understood by the decision pipeline.
var KnownActions = []string{"isolate", "block-port", "stop-service", "snapshot"}

// Decider proposes an action for a situation. ok=false means "no opinion".
type Decider interface {
	Name() string
	Decide(ctx context.Context, s Situation) (p Proposal, ok bool, err error)
}

// Guard checks a proposal and may only make it safer.
type Guard interface {
	Name() string
	Check(ctx context.Context, s Situation, p Proposal) (Proposal, error)
}

var (
	Deciders = registry.New[Decider]("decider")
	Guards   = registry.New[Guard]("guard")
)

// Safer returns the safer of two tiers for the purpose of combining: auto is
// the least safe, then approve, then notify, then none.
func Safer(a, b Tier) Tier {
	rank := func(t Tier) int {
		switch t {
		case TierAuto:
			return 0
		case TierApprove:
			return 1
		case TierNotify:
			return 2
		}
		return 3
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

// Settings is the read-only configuration dependency injected into guards.
type Settings interface {
	GetSetting(context.Context, string) (string, error)
}

// Evaluate keeps the first proposal's action scope. Later plug-ins may reduce
// its tier, remove its action, or shorten its TTL, but cannot replace its scope.
// Errors are returned alongside the safe result so callers can record both.
func Evaluate(ctx context.Context, ds []Decider, gs []Guard, s Situation) (Proposal, bool, error) {
	p := Proposal{Tier: TierNone}
	found := false
	var errs []error
	addReason := func(v string) {
		if v != "" {
			if p.Reason != "" {
				p.Reason += "; "
			}
			p.Reason += v
		}
	}
	apply := func(name string, q Proposal) {
		if q.Tier < TierNone || q.Tier > TierApprove || Safer(p.Tier, q.Tier) != q.Tier {
			errs = append(errs, fmt.Errorf("%s attempted a less safe tier", name))
			return
		}
		if q.Action != "" && !slices.Contains(KnownActions, q.Action) {
			q.Action = ""
		}
		changed := q.Tier != p.Tier
		p.Tier = q.Tier
		if q.Action == "" && p.Action != "" {
			p.Action = ""
			changed = true
		}
		if q.TTL > 0 && (p.TTL == 0 || q.TTL < p.TTL) {
			p.TTL = q.TTL
			changed = true
		}
		if changed {
			p.DecidedBy = append(p.DecidedBy, name)
			addReason(q.Reason)
		}
	}
	invariant := func() {
		if p.Action != "" && !slices.Contains(KnownActions, p.Action) {
			p.Action = ""
			addReason("unknown action")
		}
		if p.Action == "" && (p.Tier == TierAuto || p.Tier == TierApprove) {
			p.Tier = TierNotify
			addReason("no action specified")
		}
		if p.Tier == TierAuto && p.TTL <= 0 {
			p.Tier = TierApprove
			addReason("automatic actions require a reversible action and positive TTL")
		}
	}
	for _, d := range ds {
		q, ok, err := d.Decide(ctx, s)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.Name(), err))
			continue
		}
		if !ok {
			continue
		}
		if !found {
			p = q
			p.DecidedBy = []string{d.Name()}
			found = true
			if p.Tier < TierNone || p.Tier > TierApprove {
				p.Tier = TierNone
				errs = append(errs, fmt.Errorf("%s: invalid tier", d.Name()))
			}
		} else {
			apply(d.Name(), q)
		}
		invariant()
	}
	if !found {
		return p, false, errors.Join(errs...)
	}
	for _, g := range gs {
		// Copy mutable fields: a guard cannot mutate the accepted proposal in place.
		q := p
		q.DecidedBy = append([]string(nil), p.DecidedBy...)
		if p.Params != nil {
			b, e := json.Marshal(p.Params)
			if e != nil {
				return Proposal{Tier: TierNone}, true, e
			}
			q.Params = nil
			_ = json.Unmarshal(b, &q.Params)
		}
		q, err := g.Check(ctx, s, q)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", g.Name(), err))
			if p.Tier == TierAuto {
				q = p
				q.Tier = TierApprove
				q.Reason = "guard failed; approval required"
			} else {
				continue
			}
		}
		if q.Tier == p.Tier && q.Action == p.Action && q.TTL == p.TTL && reflect.DeepEqual(q.Params, p.Params) {
			continue
		}
		apply(g.Name(), q)
		invariant()
	}
	p.Reason = strings.TrimSpace(p.Reason)
	return p, true, errors.Join(errs...)
}
