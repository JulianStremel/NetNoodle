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

	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

type orderState struct {
	run   sync.Mutex
	mu    sync.Mutex
	key   ed25519.PrivateKey
	kick  chan struct{}
	wakes map[int64]chan struct{}
}

func newOrderState() *orderState {
	return &orderState{kick: make(chan struct{}, 1), wakes: map[int64]chan struct{}{}}
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

// planOrders serializes planning with results and operator scheduling. Strong
// identifiers win; actors with equal strength are ordered by lowest peer ID.
func (s *Server) planOrders(ctx context.Context) error {
	s.orders.run.Lock()
	defer s.orders.run.Unlock()
	now := s.now()
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
		if o.Revert || o.Reverted || o.RevertAction == "" || o.RevertAttempts >= 6 || !enabled[o.ActorPeerID] {
			continue
		}
		r := store.Order{Order: proto.Order{Actor: o.Actor, Action: o.RevertAction, Targets: o.Targets, Params: o.Params, Revert: true, RevertOf: o.ID}, ProposalID: o.ProposalID, ActorPeerID: o.ActorPeerID}
		if e = s.queueSigned(ctx, r); e != nil && !errors.Is(e, store.ErrConflict) {
			return e
		}
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
	for _, p := range ps {
		d, e := s.st.GetDevice(ctx, p.DeviceID)
		if e != nil {
			return e
		}
		var chosen *store.ActorCaps
		var capability proto.Capability
		var targets []proto.Identifier
		best := -1
		for i, a := range actors {
			if a.Peer.Disabled {
				continue
			}
			for _, c := range a.Capabilities {
				if c.Action != p.Action || (p.Tier == "auto" && (!c.Reversible || c.RevertAction == "" || p.TTL <= 0)) {
					continue
				}
				// Address the device by ONE identifier kind: the first kind
				// in the capability's order that the device has as a strong
				// identifier, else the first kind it has at all. Sending
				// every kind would make the actor check (and act on) more
				// than needed, for example an IP next to the MAC.
				kind, score := "", 0
				for _, want := range c.TargetIDKinds {
					for _, id := range d.IDs {
						if id.Kind != want {
							continue
						}
						if id.Strength == proto.Strong && score == 0 {
							kind, score = want, 1
						} else if kind == "" {
							kind = want
						}
					}
					if score == 1 {
						break
					}
				}
				ids := []proto.Identifier{}
				for _, id := range d.IDs {
					if kind != "" && id.Kind == kind {
						ids = append(ids, id.Identifier)
					}
				}
				if len(ids) == 0 || score <= best {
					continue
				}
				best = score
				chosen = &actors[i]
				capability = c
				targets = ids
			}
		}
		if chosen == nil {
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
		if e = s.queueSigned(ctx, o); e != nil {
			return e
		}
	}
	return nil
}
