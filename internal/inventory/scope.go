package inventory

import (
	"errors"

	"netnoodle/internal/proto"
)

// MaxEntities is the largest number of entities (with all children) in one
// observation.
const MaxEntities = 20000

// AgentKind is the identifier kind that only the server assigns: it names
// the agent peer that reports a device.
const AgentKind = "agent"

// CountEntities counts entities and all their children.
func CountEntities(es []proto.Entity) int {
	n := 0
	for i := range es {
		n += 1 + CountEntities(es[i].Children)
	}
	return n
}

func isAgentID(id proto.Identifier) bool {
	n, ok := normalizeIdentifier(id)
	return ok && n.Kind == AgentKind
}

func withoutAgentIDs(ids []proto.Identifier) []proto.Identifier {
	out := ids[:0:0]
	for _, id := range ids {
		if !isAgentID(id) {
			out = append(out, id)
		}
	}
	return out
}

// StripAgentIDs removes agent identifiers from all entities and parent
// links. Only the server assigns them, for agent peers.
func StripAgentIDs(es []proto.Entity) {
	for i := range es {
		e := &es[i]
		e.Identifiers = withoutAgentIDs(e.Identifiers)
		e.Parent = withoutAgentIDs(e.Parent)
		StripAgentIDs(e.Children)
	}
}

// ErrAgentShape is returned for agent reports that break the agent rules.
var ErrAgentShape = errors.New("an agent must send exactly one top-level entity without children or parent")

// PrepareAgent applies the agent rules to an observation of agent peer
// `name`: exactly one entity, no children, no parent link, no agent
// identifiers except the one the server adds. The entity is normalized
// first, so different spellings of the kind cannot pass the filter, and a
// slot is kept free for the server's identifier.
func PrepareAgent(obs *proto.Observation, name string) error {
	if len(obs.Entities) != 1 {
		return ErrAgentShape
	}
	e := &obs.Entities[0]
	if len(e.Children) > 0 || len(e.Parent) > 0 {
		return ErrAgentShape
	}
	NormalizeEntity(e)
	ids := withoutAgentIDs(e.Identifiers)
	if len(ids) >= maxIdentifiers {
		ids = ids[:maxIdentifiers-1]
	}
	e.Identifiers = append(ids, proto.Identifier{Kind: AgentKind, Value: name, Strength: proto.Strong})
	return nil
}

// resolveAgent finds the device of an agent report. The agent identifier
// decides. On the first report, the agent may claim one existing device
// that matches its MACs or (weakly) its IP or host name, but only if no
// other agent owns that device. Agent reports never merge devices.
func (r *resolver) resolveAgent(e *proto.Entity) (int64, error) {
	if dev, ok, err := r.tx.Lookup(AgentKind, r.agent); err != nil || ok {
		return dev, err
	}
	try := func(id proto.Identifier) (int64, bool, error) {
		cand, ok, err := r.tx.Lookup(id.Kind, id.Value)
		if err != nil || !ok {
			return 0, false, err
		}
		have, err := r.tx.Identifiers(cand)
		if err != nil {
			return 0, false, err
		}
		for _, h := range have {
			if h.Kind == AgentKind {
				return 0, false, nil
			}
		}
		if id.Strength == proto.Weak {
			if c, err := r.conflicts(cand, e.Identifiers); err != nil || c {
				return 0, false, err
			}
		}
		return cand, true, nil
	}
	for _, id := range e.Identifiers {
		if id.Strength == proto.Strong && id.Kind != AgentKind {
			if dev, ok, err := try(id); err != nil || ok {
				return dev, err
			}
		}
	}
	for _, kind := range weakOrder {
		for _, id := range e.Identifiers {
			if id.Kind == kind && id.Strength == proto.Weak {
				if dev, ok, err := try(id); err != nil || ok {
					return dev, err
				}
			}
		}
	}
	return 0, nil
}
