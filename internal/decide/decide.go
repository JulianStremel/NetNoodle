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
	Tags     map[string]string
	Exposed  bool  // the vulnerable component backs a listening service
	Ports    []int // listening ports of that component
	ParentID int64
}

// Situation is one finding (vulnerability on a device) to decide on.
type Situation struct {
	FindingID  int64
	Device     Device
	Vuln       intel.Vuln
	Component  string // PURL
	Confidence string // high | low
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
