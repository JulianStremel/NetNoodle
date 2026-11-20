package inventory

import (
	"errors"
	"regexp"
	"strings"

	"github.com/JulianStremel/netnoodle/internal/proto"
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

// ChildKind is the identifier kind that the server gives to the
// containers that an agent reports: "<agent>/<runtime>/<id>". Only the
// server assigns it.
const ChildKind = "agent.child"

// ContainerIDKind is the identifier kind with which an agent names one of
// its containers, for example "lxc/101" or "docker/3f2a9c1b7e44".
const ContainerIDKind = "container.id"

// MaxAgentChildren is the largest number of containers in one agent report.
const MaxAgentChildren = 1000

func isAgentID(id proto.Identifier) bool {
	n, ok := normalizeIdentifier(id)
	return ok && (n.Kind == AgentKind || n.Kind == ChildKind)
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

// agentKinds are the identifier kinds an agent may report about its host.
// Other kinds (for example proxmox.guest) belong to other sources; an
// agent could otherwise pre-claim them and capture a later import.
var agentKinds = map[string]bool{"mac": true, "ip": true, "hostname": true}

// movableByAgent are the kinds an agent report may move from another device.
var movableByAgent = map[string]bool{"ip": true, "hostname": true}

// ErrAgentShape is returned for agent reports that break the agent rules.
var ErrAgentShape = errors.New("an agent must send exactly one top-level entity without parent; children must be containers with one container.id and no children")

var containerIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// agentIDs keeps the identifiers that an agent may report and keeps a slot
// free for the server's identifier.
func agentIDs(ids []proto.Identifier) []proto.Identifier {
	var out []proto.Identifier
	for _, id := range ids {
		if agentKinds[id.Kind] {
			out = append(out, id)
		}
	}
	if len(out) >= maxIdentifiers {
		out = out[:maxIdentifiers-1]
	}
	return out
}

// PrepareAgent applies the agent rules to an observation of agent peer
// `name`: exactly one entity, no parent link, no agent identifiers except
// the one the server adds. The entity is normalized first, so different
// spellings of the kind cannot pass the filter, and a slot is kept free
// for the server's identifier.
//
// Children are the containers of the host (D-050). Each must be of kind
// container, have no children and no parent link, and have exactly one
// container.id identifier. The server replaces it with
// agent.child=<agent>/<container.id>, so one agent can never name the
// containers of another one.
func PrepareAgent(obs *proto.Observation, name string) error {
	if len(obs.Entities) != 1 {
		return ErrAgentShape
	}
	e := &obs.Entities[0]
	if len(e.Parent) > 0 || len(e.Children) > MaxAgentChildren {
		return ErrAgentShape
	}
	// Check the children before normalization, which drops entities
	// without identifiers.
	for i := range e.Children {
		c := &e.Children[i]
		if len(c.Children) > 0 || len(c.Parent) > 0 {
			return ErrAgentShape
		}
		var cid string
		for _, id := range c.Identifiers {
			if strings.TrimSpace(strings.ToLower(id.Kind)) == ContainerIDKind {
				if cid != "" || !containerIDRE.MatchString(id.Value) {
					return ErrAgentShape
				}
				cid = id.Value
			}
		}
		if cid == "" {
			return ErrAgentShape
		}
		NormalizeEntity(c)
		c.Kind = proto.KindContainer
		c.Identifiers = append(agentIDs(c.Identifiers), proto.Identifier{Kind: ChildKind, Value: name + "/" + cid, Strength: proto.Strong})
	}
	NormalizeEntity(e)
	e.Identifiers = append(agentIDs(e.Identifiers), proto.Identifier{Kind: AgentKind, Value: name, Strength: proto.Strong})
	return nil
}

// resolveAgentChild finds the device of a container that an agent reports
// under its host device `parent`. The agent.child identifier decides. On
// the first report the container may claim an existing device by MAC, but
// only one that is already a guest of the same host (for example from the
// Proxmox import) and that no agent owns. It never merges devices.
func (r *resolver) resolveAgentChild(e *proto.Entity, parent int64) (int64, error) {
	for _, id := range e.Identifiers {
		if id.Kind == ChildKind {
			if dev, ok, err := r.tx.Lookup(ChildKind, id.Value); err != nil || ok {
				return dev, err
			}
		}
	}
	for _, id := range e.Identifiers {
		if id.Kind != "mac" || id.Strength != proto.Strong {
			continue
		}
		cand, ok, err := r.tx.Lookup(id.Kind, id.Value)
		if err != nil || !ok {
			if err != nil {
				return 0, err
			}
			continue
		}
		p, err := r.tx.ParentOf(cand)
		if err != nil {
			return 0, err
		}
		if p != parent {
			continue
		}
		have, err := r.tx.Identifiers(cand)
		if err != nil {
			return 0, err
		}
		owned := false
		for _, h := range have {
			if h.Kind == AgentKind || h.Kind == ChildKind {
				owned = true
			}
		}
		if !owned {
			return cand, nil
		}
	}
	return 0, nil
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
