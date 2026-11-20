package storetest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func testSnapshotAtAutoAndApprovalAndMergeReset(t *testing.T, open func(t *testing.T) store.Store) {
	ctx := context.Background()
	db := open(t)
	keep, drop := decideDevice(t, db), decideDevice(t, db)
	now := time.Now().UTC()
	if e := db.InventoryTx(ctx, func(tx inventory.Tx) error {
		for i := range 40 {
			if e := tx.PutIdentifier(drop, proto.Identifier{Kind: "agent", Value: fmt.Sprint(i), Strength: proto.Strong}, "test", now); e != nil {
				return e
			}
		}
		for _, id := range []proto.Identifier{{Kind: "ip", Value: "192.0.2.1", Strength: proto.Strong}, {Kind: "hostname", Value: "host", Strength: proto.Strong}, {Kind: "weak", Value: "weak", Strength: proto.Weak}} {
			if e := tx.PutIdentifier(drop, id, "test", now); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	ids := []int64{}
	for _, state := range []string{"approved", "auto", "no-actor"} {
		input := store.Proposal{DeviceID: drop, VulnID: state, Action: "isolate", Tier: "auto", State: "auto", TTL: 60, CreatedAt: now}
		if state == "approved" {
			input.Tier = "approve"
			input.State = "pending"
		}
		p, _, e := db.UpsertProposal(ctx, input)
		if e != nil {
			t.Fatal(e)
		}
		if state == "approved" {
			if len(p.TargetSnapshot) != 0 {
				t.Fatal("pending already pinned")
			}
			if e = db.DecideProposal(ctx, p.ID, "approved", "admin", now); e != nil {
				t.Fatal(e)
			}
			p, _ = db.GetProposal(ctx, p.ID)
		}
		if len(p.TargetSnapshot) != 32 {
			t.Fatal(len(p.TargetSnapshot))
		}
		for _, id := range p.TargetSnapshot {
			if !store.StrongTarget(id) || id.Kind != "agent" {
				t.Fatal(id)
			}
		}
		if state == "no-actor" {
			if e = db.SetProposalOrderState(ctx, p.ID, "no-actor", "unavailable", now); e != nil {
				t.Fatal(e)
			}
		}
		ids = append(ids, p.ID)
	}
	if e := db.InventoryTx(ctx, func(tx inventory.Tx) error { return tx.Merge(keep, drop) }); e != nil {
		t.Fatal(e)
	}
	for _, id := range ids {
		p, e := db.GetProposal(ctx, id)
		if e != nil || p.DeviceID != keep || p.State != "pending" || p.Reason != "device identity changed; approve again" || len(p.TargetSnapshot) != 0 {
			t.Fatal(p, e)
		}
	}
}

func testApprovalAndNoActorExpireWithoutOrder(t *testing.T, open func(t *testing.T) store.Store) {
	ctx := context.Background()
	db := open(t)
	device := decideDevice(t, db)
	now := time.Now().UTC()
	for _, state := range []string{"approved", "no-actor"} {
		p, _, e := db.UpsertProposal(ctx, store.Proposal{DeviceID: device, VulnID: state, Action: "isolate", State: "pending", Tier: "approve", CreatedAt: now})
		if e != nil {
			t.Fatal(e)
		}
		if e = db.DecideProposal(ctx, p.ID, "approved", "admin", now); e != nil {
			t.Fatal(e)
		}
		if state == "no-actor" {
			if e = db.SetProposalOrderState(ctx, p.ID, state, "no actor", now.Add(6*24*time.Hour)); e != nil {
				t.Fatal(e)
			}
		}
		if e = db.ExpireProposals(ctx, now.Add(-time.Nanosecond)); e != nil {
			t.Fatal(e)
		}
		got, _ := db.GetProposal(ctx, p.ID)
		if got.State != state {
			t.Fatal("expired early", got)
		}
		if e = db.ExpireProposals(ctx, now); e != nil {
			t.Fatal(e)
		}
		got, _ = db.GetProposal(ctx, p.ID)
		if got.State != "expired" {
			t.Fatal(got)
		}
	}
}

// Insert historical records directly so each retention edge can be isolated.

func testMovedAutoProposalSurvivesMutableCollision(t *testing.T, open func(*testing.T) store.Store) {
	db := open(t)
	ctx := context.Background()
	keep, drop := decideDevice(t, db), decideDevice(t, db)
	for _, device := range []int64{keep, drop} {
		if _, _, e := db.UpsertProposal(ctx, store.Proposal{DeviceID: device, VulnID: "same", Action: "isolate", State: "auto", Tier: "auto", TTL: 60}); e != nil {
			t.Fatal(e)
		}
	}
	before, e := db.ListProposals(ctx, store.ProposalFilter{DeviceID: drop})
	if e != nil || len(before) != 1 {
		t.Fatal(e)
	}
	if e = db.InventoryTx(ctx, func(tx inventory.Tx) error { return tx.Merge(keep, drop) }); e != nil {
		t.Fatal(e)
	}
	p, e := db.GetProposal(ctx, before[0].ID)
	if e != nil || p.DeviceID != keep || p.State != "pending" || p.Reason != "device identity changed; approve again" {
		t.Fatal(p, e)
	}
}
