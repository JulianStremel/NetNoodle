package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
	"github.com/JulianStremel/netnoodle/internal/version"
)

type orderState struct {
	run       sync.Mutex
	mu        sync.Mutex
	key       ed25519.PrivateKey
	kick      chan struct{}
	wakes     map[int64]chan struct{}
	polls     map[int64]int
	pollTotal int
}

func newOrderState() *orderState {
	return &orderState{kick: make(chan struct{}, 1), wakes: map[int64]chan struct{}{}, polls: map[int64]int{}}
}

// SetOrderKey installs the persistent key before serving requests.
func (s *Server) SetOrderKey(key ed25519.PrivateKey) { s.orders.key = key }
func (s *Server) kickPlanner() {
	select {
	case s.orders.kick <- struct{}{}:
	default:
	}
}
func (s *Server) orderWake(id int64) <-chan struct{} {
	s.orders.mu.Lock()
	defer s.orders.mu.Unlock()
	ch := s.orders.wakes[id]
	if ch == nil {
		ch = make(chan struct{})
		s.orders.wakes[id] = ch
	}
	return ch
}
func (s *Server) wakeActor(id int64) {
	s.orders.mu.Lock()
	defer s.orders.mu.Unlock()
	if ch := s.orders.wakes[id]; ch != nil {
		close(ch)
	}
	s.orders.wakes[id] = make(chan struct{})
}
func randomOrderID() (string, error) {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func (s *Server) queueSigned(ctx context.Context, o store.Order) error {
	var e error
	o.ID, e = randomOrderID()
	if e != nil {
		return e
	}
	o.Nonce, e = randomOrderID()
	if e != nil {
		return e
	}
	o.Version = proto.Version
	o.CreatedAt = s.now()
	o.NotAfter = o.CreatedAt.Add(10 * time.Minute)
	o.Envelope, e = orders.Sign(s.orders.key, o.Order)
	if e != nil {
		return e
	}
	if e = s.st.QueueOrder(ctx, o); e != nil {
		return e
	}
	s.wakeActor(o.ActorPeerID)
	return nil
}
func (s *Server) RunPlanner(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		if e := s.planOrders(ctx); e != nil && ctx.Err() == nil {
			s.log.Error("plan orders", "err", e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.orders.kick:
		}
	}
}

// planOrders serializes planning with results and operator scheduling. Matching
// scopes win, then strong identifiers, then lowest peer ID. Weak targets are refused.
func (s *Server) planOrders(ctx context.Context) error {
	s.orders.run.Lock()
	defer s.orders.run.Unlock()
	now := s.now()
	if e := s.st.ExpireProposals(ctx, now.Add(-7*24*time.Hour)); e != nil {
		return e
	}
	expiring, e := s.st.ExpiringOrders(ctx, now)
	if e != nil {
		return e
	}
	if e := s.st.ExpireOrders(ctx, now); e != nil {
		return e
	}
	for _, o := range expiring {
		severity := "warning"
		if o.Revert {
			severity = "critical"
		}
		s.emit(ctx, notify.Event{Type: "order.expired", Severity: severity, Title: "Order " + o.ID + " expired", Detail: "order expired", Link: "#/actions"}, o.Actor, `{"severity":"`+severity+`"}`)
	}
	if e = s.queueDueReverts(ctx, now); e != nil {
		return e
	}
	actors, e := s.st.ListActors(ctx)
	if e != nil {
		return e
	}
	// Share the decision lock with the kill switch setter; a completed switch
	// can never race a new order insertion.
	s.decide.run.Lock()
	defer s.decide.run.Unlock()
	kill, e := s.st.GetSetting(ctx, "decide.killswitch")
	if e != nil {
		return e
	}
	if kill == "on" {
		return nil
	}
	ps, e := s.st.PlanningProposals(ctx)
	if e != nil {
		return e
	}
	sort.Slice(actors, func(i, j int) bool { return actors[i].Peer.ID < actors[j].Peer.ID })
	var nodes map[int64]GraphNode
	for _, p := range ps {
		if p.Tier == "auto" {
			s.invalidateDecisionContext()
			nodes, e = s.decisionContext(ctx)
			if e != nil {
				return e
			}
			break
		}
	}
	s.decide.mu.Lock()
	gs := s.decide.guards
	s.decide.mu.Unlock()
	for _, p := range ps {
		deadline := p.ExpiresAt
		if deadline.IsZero() {
			deadline = p.CreatedAt.Add(7 * 24 * time.Hour)
		}
		if (p.State == "approved" || p.State == "no-actor") && !deadline.After(now) {
			if e = s.st.SetProposalOrderState(ctx, p.ID, "expired", "proposal expired", now); e != nil {
				return e
			}
			continue
		}
		d, e := s.st.GetDevice(ctx, p.DeviceID)
		if e != nil {
			return e
		}
		intersection := []proto.Identifier{}
		for _, snap := range p.TargetSnapshot {
			if !store.StrongTarget(snap) {
				continue
			}
			for _, id := range d.IDs {
				if store.StrongTarget(id.Identifier) && id.Kind == snap.Kind && id.Value == snap.Value {
					intersection = append(intersection, snap)
					break
				}
			}
		}
		if len(intersection) == 0 {
			if e = s.st.SetProposalOrderState(ctx, p.ID, "pending", "device identity changed; approve again", now); e != nil {
				return e
			}
			continue
		}
		if p.Tier == "auto" {
			fs, err := s.st.ListFindings(ctx, store.FindingFilter{DeviceID: p.DeviceID, State: "open", Limit: maxEvaluationsPerDevice})
			if err != nil {
				return err
			}
			var finding *store.FindingRow
			for i := range fs {
				if fs[i].VulnID == p.VulnID && fs[i].PURL == p.PURL {
					finding = &fs[i]
					break
				}
			}
			reason := "finding no longer open; approve again"
			safe := false
			if finding != nil {
				q, _, err := decide.Evaluate(ctx, []decide.Decider{pinnedDecider{p}}, gs, findingSituation(d, *finding, nodes[p.DeviceID]))
				safe = err == nil && q.Tier == decide.TierAuto && q.Action == p.Action
				reason = q.Reason
				p.TTL = q.TTL
			}
			if !safe {
				if reason == "" {
					reason = "guards require approval"
				}
				if e = s.st.SetProposalOrderState(ctx, p.ID, "pending", reason, now); e != nil {
					return e
				}
				continue
			}
		}
		var chosen *store.ActorCaps
		var capability proto.Capability
		var targets []proto.Identifier
		best := -1
		agentOnly := false
		tooOld := false
		for i, a := range actors {
			if a.Peer.Disabled {
				continue
			}
			for _, c := range a.Capabilities {
				if c.Action != p.Action || (p.Tier == "auto" && (!c.Reversible || c.RevertAction == "" || p.TTL <= 0)) {
					continue
				}
				// Rank each supported kind independently. Every selected value
				// must match scope; never send an out-of-scope sibling value.
				for _, kind := range c.TargetIDKinds {
					ids := []proto.Identifier{}
					score := 1
					if len(c.TargetScope) > 0 {
						score = 2
					}
					for _, id := range intersection {
						if id.Kind != kind || !matchesTargetScope(c.TargetScope, id) {
							continue
						}
						if id.Kind == "mac" && !p.OverrideAgentOnly && !p.TargetReportedElsewhere[id.Kind+"="+id.Value] {
							agentOnly = true
							continue
						}
						ids = append(ids, id)
					}
					if len(ids) == 0 || score <= best {
						continue
					}
					if version.Outdated(a.Peer.Version, version.Version) {
						tooOld = true
						continue
					}
					best, chosen, capability, targets = score, &actors[i], c, ids
				}
			}
		}
		if chosen == nil {
			if tooOld {
				if e = s.st.SetProposalOrderState(ctx, p.ID, "no-actor", "actor version too old", now); e != nil {
					return e
				}
				continue
			}
			if agentOnly {
				if e = s.st.SetProposalOrderState(ctx, p.ID, "pending", "target MAC only reported by the device's own agent — confirm with UniFi/scan data or approve again with override", now); e != nil {
					return e
				}
				continue
			}
			if e = s.st.SetProposalOrderState(ctx, p.ID, "no-actor", "no actor with matching capability and identifiers", now); e != nil {
				return e
			}
			continue
		}
		sort.Slice(targets, func(i, j int) bool {
			a, b := targets[i], targets[j]
			if a.Strength != b.Strength {
				return a.Strength == proto.Strong
			}
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			return a.Value < b.Value
		})
		if len(targets) > 16 {
			targets = targets[:16]
		}
		revert := ""
		if capability.Reversible {
			revert = capability.RevertAction
		}
		o := store.Order{Order: proto.Order{Actor: chosen.Peer.Name, Action: p.Action, Targets: targets, Params: p.Params, TTL: p.TTL}, ProposalID: p.ID, ActorPeerID: chosen.Peer.ID, RevertAction: revert}
		if e = s.queueSigned(ctx, o); e != nil && !errors.Is(e, store.ErrConflict) {
			return e
		}
	}
	return nil
}

// Replay the saved proposal through today's guards without asking deciders to widen it.
type pinnedDecider struct{ p store.Proposal }

func (p pinnedDecider) Name() string { return "saved proposal" }
func (p pinnedDecider) Decide(context.Context, decide.Situation) (decide.Proposal, bool, error) {
	return decide.Proposal{Tier: decide.TierAuto, Action: p.p.Action, Params: p.p.Params, TTL: p.p.TTL, Reason: p.p.Reason}, true, nil
}

func (s *Server) acquireOrderPoll(id int64) bool {
	s.orders.mu.Lock()
	defer s.orders.mu.Unlock()
	if s.orders.pollTotal >= 256 || s.orders.polls[id] >= 2 {
		return false
	}
	s.orders.polls[id]++
	s.orders.pollTotal++
	return true
}
func (s *Server) releaseOrderPoll(id int64) {
	s.orders.mu.Lock()
	defer s.orders.mu.Unlock()
	s.orders.pollTotal--
	s.orders.polls[id]--
	if s.orders.polls[id] == 0 {
		delete(s.orders.polls, id)
		delete(s.orders.wakes, id)
	}
}

func matchesTargetScope(patterns []string, id proto.Identifier) bool {
	return proto.MatchesScope(patterns, id)
}

// Called under orders.run by expiry planning and explicit uncertain results.
// Recovery always goes to the original actor, regardless of current scopes.
func (s *Server) queueDueReverts(ctx context.Context, now time.Time) error {
	os, e := s.st.DueReverts(ctx, now)
	if e != nil {
		return e
	}
	actors, e := s.st.ListActors(ctx)
	if e != nil {
		return e
	}
	enabled := map[int64]bool{}
	for _, a := range actors {
		enabled[a.Peer.ID] = !a.Peer.Disabled
	}
	for _, o := range os {
		if o.Revert || o.Reverted || o.RevertAction == "" || o.RevertAttempts >= 6 {
			continue
		}
		if !enabled[o.ActorPeerID] {
			first, err := s.st.MarkRevertBlocked(ctx, o.ID)
			if err != nil {
				return err
			}
			if first {
				s.emit(ctx, notify.Event{Type: "order.revert-blocked", Severity: "critical", Title: "revert blocked: actor " + o.Actor + " disabled", Link: "#/actions"}, o.Actor, `{"severity":"critical"}`)
			}
			continue
		}
		r := store.Order{Order: proto.Order{Actor: o.Actor, Action: o.RevertAction, Targets: o.Targets, Params: o.Params, Revert: true, RevertOf: o.ID}, ProposalID: o.ProposalID, ActorPeerID: o.ActorPeerID}
		if e = s.queueSigned(ctx, r); e != nil && !errors.Is(e, store.ErrConflict) {
			return e
		}
	}

	return nil
}
