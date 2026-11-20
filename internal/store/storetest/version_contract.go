package storetest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func testRevertsOnlyDelivery(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	p := actor(t, st, "old", now)
	o := newOrder(t, st, now, "forward", p)
	must(t, st.QueueOrder(ctx, o))
	envs, err := st.SendOrders(ctx, p.ID, now, true)
	must(t, err)
	if len(envs) != 0 {
		t.Fatal("forward order delivered", envs)
	}
	got, err := st.GetOrder(ctx, o.ID)
	must(t, err)
	if got.State != "queued" {
		t.Fatal("withheld order changed", got)
	}
	_, err = st.SendOrders(ctx, p.ID, now, false)
	must(t, err)
	must(t, st.FinishOrder(ctx, p.ID, proto.OrderResult{Version: proto.Version, OrderID: o.ID, Status: proto.OrderDone, At: now}, now))
	must(t, st.ScheduleRevert(ctx, o.ID, now))
	r := store.Order{Order: proto.Order{Version: proto.Version, ID: "revert", Actor: p.Name, Action: "unisolate", Targets: o.Targets, Revert: true, RevertOf: o.ID, NotAfter: now.Add(time.Hour)}, ProposalID: o.ProposalID, ActorPeerID: p.ID, CreatedAt: now}
	envelope(t, &r)
	must(t, st.QueueOrder(ctx, r))
	envs, err = st.SendOrders(ctx, p.ID, now, true)
	must(t, err)
	if len(envs) != 1 {
		t.Fatal(envs)
	}
	var delivered proto.Order
	must(t, json.Unmarshal(envs[0].Payload, &delivered))
	if !delivered.Revert || delivered.RevertOf != o.ID {
		t.Fatal(delivered)
	}
}
