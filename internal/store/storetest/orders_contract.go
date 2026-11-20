package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func actor(t *testing.T, st store.Store, name string, now time.Time) store.Peer {
	t.Helper()
	ctx := context.Background()
	_, err := st.CreateJoinToken(ctx, []byte("join-"+name), store.RoleActor, name, 1, now.Add(time.Hour))
	must(t, err)
	p, err := st.Enroll(ctx, []byte("join-"+name), name, []byte("token-"+name), now, nil)
	must(t, err)
	return p
}

func envelope(t *testing.T, o *store.Order) {
	t.Helper()
	b, err := json.Marshal(o.Order)
	must(t, err)
	o.Envelope = orders.Envelope{Payload: b, Sig: []byte("signature")}
}

func newOrder(t *testing.T, st store.Store, now time.Time, name string, peer store.Peer) store.Order {
	t.Helper()
	id := ingest(t, st, "scan", now, false, proto.Entity{Identifiers: []proto.Identifier{strong("serial", name)}}).Devices[0]
	p, _, err := st.UpsertProposal(context.Background(), store.Proposal{DeviceID: id, VulnID: name, Action: "isolate", Tier: "auto", State: "auto", TTL: 60, CreatedAt: now})
	must(t, err)
	o := store.Order{Order: proto.Order{Version: proto.Version, ID: name, Actor: peer.Name, Action: "isolate", Targets: p.TargetSnapshot, TTL: 60, NotAfter: now.Add(time.Hour)}, ProposalID: p.ID, ActorPeerID: peer.ID, CreatedAt: now, RevertAction: "unisolate"}
	envelope(t, &o)
	return o
}

func testOrderExactlyOnePerProposal(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	p := actor(t, st, "actor", now)
	o := newOrder(t, st, now, "one", p)
	raceCalls(t, 12, func(i int) error {
		candidate := o
		candidate.ID = fmt.Sprint("candidate-", i)
		// Marshal independently: contenders must not share a mutable envelope.
		payload, err := json.Marshal(candidate.Order)
		if err != nil {
			return err
		}
		candidate.Envelope.Payload = payload
		return st.QueueOrder(ctx, candidate)
	}, store.ErrConflict)
	rows, err := st.ListOrders(ctx, store.OrderFilter{ProposalID: o.ProposalID})
	must(t, err)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	// A repeated initial order is rejected as well.
	if err := st.QueueOrder(ctx, o); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate order: %v", err)
	}
}

func testOrderResultOwnershipAndIdempotence(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	owner, other := actor(t, st, "owner", now), actor(t, st, "other", now)
	o := newOrder(t, st, now, "order", owner)
	must(t, st.QueueOrder(ctx, o))
	sent, err := st.SendOrders(ctx, owner.ID, now)
	must(t, err)
	if len(sent) != 1 || !reflect.DeepEqual(sent[0], o.Envelope) {
		t.Fatal(sent)
	}
	r := proto.OrderResult{OrderID: o.ID, Status: proto.OrderDone, At: now}
	if err := st.FinishOrder(ctx, other.ID, r, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other actor result: %v", err)
	}
	must(t, st.FinishOrder(ctx, owner.ID, r, now))
	must(t, st.FinishOrder(ctx, owner.ID, r, now.Add(time.Minute)))
	r.Status = proto.OrderFailed
	if err := st.FinishOrder(ctx, owner.ID, r, now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("changed result: %v", err)
	}
	got, err := st.GetOrder(ctx, o.ID)
	must(t, err)
	if got.State != "done" || !got.ResultRecorded || !got.RevertDueAt.Equal(now.Add(time.Minute)) {
		t.Fatal(got)
	}
}

func testOrderConcurrentResults(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	p := actor(t, st, "actor", now)
	o := newOrder(t, st, now, "order", p)
	must(t, st.QueueOrder(ctx, o))
	_, err := st.SendOrders(ctx, p.ID, now)
	must(t, err)
	raceCalls(t, 12, func(i int) error {
		return st.FinishOrder(ctx, p.ID, proto.OrderResult{OrderID: o.ID, Status: proto.OrderDone, At: now, Message: fmt.Sprint(i)}, now)
	}, store.ErrConflict)
}

func testOrderLateResultGrace(t *testing.T, open func(*testing.T) store.Store) {
	for _, delta := range []time.Duration{time.Hour, 24 * time.Hour, 24*time.Hour + time.Second} {
		t.Run(delta.String(), func(t *testing.T) {
			st, ctx, now := open(t), context.Background(), time.Now().UTC()
			p := actor(t, st, "actor", now)
			o := newOrder(t, st, now, "order", p)
			must(t, st.QueueOrder(ctx, o))
			_, err := st.SendOrders(ctx, p.ID, now)
			must(t, err)
			must(t, st.ExpireOrders(ctx, o.NotAfter))
			err = st.FinishOrder(ctx, p.ID, proto.OrderResult{OrderID: o.ID, Status: proto.OrderDone, At: now}, o.NotAfter.Add(delta))
			if delta <= 24*time.Hour {
				must(t, err)
			} else if !errors.Is(err, store.ErrConflict) {
				t.Fatalf("result after grace: %v", err)
			}
		})
	}
}

func testOrderRevertSchedulingAndAttempts(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	p := actor(t, st, "actor", now)
	o := newOrder(t, st, now, "order", p)
	must(t, st.QueueOrder(ctx, o))
	_, err := st.SendOrders(ctx, p.ID, now)
	must(t, err)
	must(t, st.FinishOrder(ctx, p.ID, proto.OrderResult{OrderID: o.ID, Status: proto.OrderDone, At: now}, now))
	due, err := st.DueReverts(ctx, now.Add(59*time.Second))
	must(t, err)
	if len(due) != 0 {
		t.Fatal(due)
	}
	must(t, st.ScheduleRevert(ctx, o.ID, now))
	for attempt := 1; attempt <= 6; attempt++ {
		due, err = st.DueReverts(ctx, now)
		must(t, err)
		if len(due) != 1 || due[0].ID != o.ID || due[0].RevertAttempts != attempt-1 {
			t.Fatal(due)
		}
		r := o
		r.ID, r.Action, r.Revert, r.RevertOf = fmt.Sprint("revert-", attempt), "unisolate", true, o.ID
		r.CreatedAt, r.NotAfter = now, now.Add(time.Hour)
		envelope(t, &r)
		must(t, st.QueueOrder(ctx, r))
		got, err := st.GetOrder(ctx, o.ID)
		must(t, err)
		if got.RevertAttempts != attempt || !got.RevertDueAt.IsZero() {
			t.Fatal(got)
		}
		if err := st.ScheduleRevert(ctx, o.ID, now); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("scheduled duplicate revert: %v", err)
		}
		due, err = st.DueReverts(ctx, now.Add(24*time.Hour))
		must(t, err)
		if len(due) != 0 {
			t.Fatal("in-flight revert duplicated", due)
		}
		_, err = st.SendOrders(ctx, p.ID, now)
		must(t, err)
		must(t, st.FinishOrder(ctx, p.ID, proto.OrderResult{OrderID: r.ID, Status: proto.OrderFailed, At: now}, now))
		now = now.Add(10 * time.Minute)
	}
	due, err = st.DueReverts(ctx, now.Add(24*time.Hour))
	must(t, err)
	if len(due) != 0 {
		t.Fatal("retry limit exceeded", due)
	}
	if err := st.ScheduleRevert(ctx, o.ID, now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("retry limit: %v", err)
	}
}

func testOrderRevertSuccess(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	p := actor(t, st, "actor", now)
	o := newOrder(t, st, now, "order", p)
	must(t, st.QueueOrder(ctx, o))
	_, err := st.SendOrders(ctx, p.ID, now)
	must(t, err)
	must(t, st.FinishOrder(ctx, p.ID, proto.OrderResult{OrderID: o.ID, Status: proto.OrderDone, At: now}, now))
	r := o
	r.ID, r.Action, r.Revert, r.RevertOf = "revert", "unisolate", true, o.ID
	envelope(t, &r)
	raceCalls(t, 8, func(i int) error {
		candidate := r
		candidate.ID = fmt.Sprint("revert-", i)
		b, err := json.Marshal(candidate.Order)
		if err != nil {
			return err
		}
		candidate.Envelope.Payload = b
		return st.QueueOrder(ctx, candidate)
	}, store.ErrConflict)
	rows, err := st.ListOrders(ctx, store.OrderFilter{State: "queued"})
	must(t, err)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	_, err = st.SendOrders(ctx, p.ID, now)
	must(t, err)
	must(t, st.FinishOrder(ctx, p.ID, proto.OrderResult{OrderID: rows[0].ID, Status: proto.OrderDone, At: now}, now))
	got, err := st.GetOrder(ctx, o.ID)
	must(t, err)
	if !got.Reverted || got.RevertAttempts != 1 || !got.RevertDueAt.IsZero() {
		t.Fatal(got)
	}
	proposal, err := st.GetProposal(ctx, o.ProposalID)
	must(t, err)
	if proposal.State != "reverted" {
		t.Fatal(proposal)
	}
}

func testOrderUncertainHandling(t *testing.T, open func(*testing.T) store.Store) {
	for _, mode := range []string{"reported", "sent-expiry", "queued-expiry"} {
		t.Run(mode, func(t *testing.T) {
			st, ctx, now := open(t), context.Background(), time.Now().UTC()
			p := actor(t, st, "actor", now)
			o := newOrder(t, st, now, "order", p)
			must(t, st.QueueOrder(ctx, o))
			if mode != "queued-expiry" {
				_, err := st.SendOrders(ctx, p.ID, now)
				must(t, err)
			}
			at := now
			if mode == "reported" {
				must(t, st.FinishOrder(ctx, p.ID, proto.OrderResult{OrderID: o.ID, Status: proto.OrderUncertain, At: now}, now))
			} else {
				at = o.NotAfter
				must(t, st.ExpireOrders(ctx, at))
			}
			got, err := st.GetOrder(ctx, o.ID)
			must(t, err)
			due, err := st.DueReverts(ctx, at)
			must(t, err)
			if mode == "queued-expiry" {
				if got.State != "expired" || len(due) != 0 || !got.RevertDueAt.IsZero() {
					t.Fatal(got, due)
				}
			} else if got.State != "uncertain" || len(due) != 1 || !got.RevertDueAt.Equal(at) {
				t.Fatal(got, due)
			}
		})
	}
}

func testKillSwitchCancelsQueuedOrders(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	p := actor(t, st, "actor", now)
	sent := newOrder(t, st, now, "sent", p)
	must(t, st.QueueOrder(ctx, sent))
	_, err := st.SendOrders(ctx, p.ID, now)
	must(t, err)
	must(t, st.FinishOrder(ctx, p.ID, proto.OrderResult{OrderID: sent.ID, Status: proto.OrderDone, At: now}, now))
	revert := sent
	revert.ID, revert.Action, revert.Revert, revert.RevertOf = "revert", "unisolate", true, sent.ID
	envelope(t, &revert)
	must(t, st.QueueOrder(ctx, revert))
	queued := newOrder(t, st, now, "queued", p)
	must(t, st.QueueOrder(ctx, queued))
	unqueued := newOrder(t, st, now, "unqueued", p)
	must(t, st.SetSetting(ctx, "decide.killswitch", "on"))
	got, err := st.GetOrder(ctx, queued.ID)
	must(t, err)
	if got.State != "cancelled" {
		t.Fatal(got)
	}
	proposal, err := st.GetProposal(ctx, queued.ProposalID)
	must(t, err)
	if proposal.State != "pending" || len(proposal.TargetSnapshot) != 0 {
		t.Fatal(proposal)
	}
	if err := st.QueueOrder(ctx, unqueued); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("queue with switch on: %v", err)
	}
	envs, err := st.SendOrders(ctx, p.ID, now)
	must(t, err)
	if len(envs) != 1 || !reflect.DeepEqual(envs[0], revert.Envelope) {
		t.Fatalf("switch must preserve revert delivery: %+v", envs)
	}
	must(t, st.SetSetting(ctx, "decide.killswitch", "off"))
	envs, err = st.SendOrders(ctx, p.ID, now)
	must(t, err)
	if len(envs) != 0 {
		t.Fatal("cancelled order revived", envs)
	}
}

func testOrderRetentionPreservesRecovery(t *testing.T, open func(*testing.T) store.Store) {
	for _, state := range []string{"queued", "sent", "uncertain", "revert-due", "done", "failed", "rejected"} {
		t.Run(state, func(t *testing.T) {
			st, ctx, now := open(t), context.Background(), time.Now().UTC()
			at := now.Add(-91 * 24 * time.Hour)
			peer := actor(t, st, "actor", at)
			o := newOrder(t, st, at, "order", peer)
			if state == "done" || state == "failed" || state == "rejected" {
				o.RevertAction = ""
			}
			must(t, st.QueueOrder(ctx, o))
			if state != "queued" {
				_, err := st.SendOrders(ctx, peer.ID, at)
				must(t, err)
			}
			switch state {
			case "uncertain":
				must(t, st.ExpireOrders(ctx, o.NotAfter))
			case "revert-due", "done", "failed", "rejected":
				status := proto.OrderStatus(state)
				if state == "revert-due" {
					status = proto.OrderDone
				}
				must(t, st.FinishOrder(ctx, peer.ID, proto.OrderResult{OrderID: o.ID, Status: status, At: at}, at))
			}
			must(t, st.PurgeProposals(ctx, now.Add(-90*24*time.Hour)))
			got, orderErr := st.GetOrder(ctx, o.ID)
			_, proposalErr := st.GetProposal(ctx, o.ProposalID)
			if state == "done" || state == "failed" || state == "rejected" {
				if !errors.Is(orderErr, store.ErrNotFound) || !errors.Is(proposalErr, store.ErrNotFound) {
					t.Fatalf("terminal history retained: %+v order=%v proposal=%v", got, orderErr, proposalErr)
				}
			} else {
				must(t, orderErr)
				must(t, proposalErr)
			}
		})
	}
}
