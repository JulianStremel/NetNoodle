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

func testTargetProvenanceIsPinnedAndSurvivesMerge(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	ctx := context.Background()
	device, keep := decideDevice(t, db), decideDevice(t, db)
	now := time.Now().UTC()
	mac := proto.Identifier{Kind: "mac", Value: "00:11:22:33:44:55", Strength: proto.Strong}
	put := func(source string) {
		t.Helper()
		if err := db.InventoryTx(ctx, func(tx inventory.Tx) error {
			if err := tx.PutIdentifier(device, proto.Identifier{Kind: "agent", Value: "own", Strength: proto.Strong}, "own", now); err != nil {
				return err
			}
			return tx.PutIdentifier(device, mac, source, now)
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("own")
	p, _, err := db.UpsertProposal(ctx, store.Proposal{DeviceID: device, VulnID: "auto", Action: "isolate", Tier: "auto", State: "auto", TTL: 60, CreatedAt: now})
	if err != nil || p.TargetReportedElsewhere["mac="+mac.Value] {
		t.Fatal(p, err)
	}
	put("scan")
	put("own") // Latest-source storage alone would now lose the scan evidence.
	_, sources, err := db.SnapshotTargets(ctx, device)
	if err != nil || !sources["mac="+mac.Value] {
		t.Fatal(sources, err)
	}
	p, _, err = db.UpsertProposal(ctx, store.Proposal{DeviceID: device, VulnID: "auto", Action: "isolate", Tier: "auto", State: "auto", TTL: 60, CreatedAt: now})
	if err != nil || p.TargetReportedElsewhere["mac="+mac.Value] {
		t.Fatal("reevaluation widened pinned evidence", p, err)
	}
	if err = db.SetProposalOrderState(ctx, p.ID, "pending", "review", now); err != nil {
		t.Fatal(err)
	}
	if err = db.DecideProposal(ctx, p.ID, "approved", "admin", now, true); err != nil {
		t.Fatal(err)
	}
	if err = db.InventoryTx(ctx, func(tx inventory.Tx) error { return tx.Merge(keep, device) }); err != nil {
		t.Fatal(err)
	}
	p, err = db.GetProposal(ctx, p.ID)
	if err != nil || p.State != "pending" || p.OverrideAgentOnly || len(p.TargetReportedElsewhere) != 0 {
		t.Fatal(p, err)
	}
	_, sources, err = db.SnapshotTargets(ctx, keep)
	if err != nil || !sources["mac="+mac.Value] {
		t.Fatal("merge lost independent reporter", sources, err)
	}
	if err = db.DecideProposal(ctx, p.ID, "approved", "admin", now, true); err != nil {
		t.Fatal(err)
	}
	if err = db.SetSetting(ctx, "decide.killswitch", "on"); err != nil {
		t.Fatal(err)
	}
	// Approved rows with no queued order stay approved; explicit invalidation
	// and rejection cannot retain an override from an earlier approval.
	if err = db.SetProposalOrderState(ctx, p.ID, "pending", "review", now); err != nil {
		t.Fatal(err)
	}
	if err = db.DecideProposal(ctx, p.ID, "rejected", "admin", now, true); err != nil {
		t.Fatal(err)
	}
	p, err = db.GetProposal(ctx, p.ID)
	if err != nil || p.OverrideAgentOnly {
		t.Fatal(p, err)
	}
}

func testAgentChildMACRequiresIndependentReporter(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	ctx := context.Background()
	device := decideDevice(t, db)
	now := time.Now()
	mac := proto.Identifier{Kind: "mac", Value: "00:11:22:33:44:55", Strength: proto.Strong}
	if err := db.InventoryTx(ctx, func(tx inventory.Tx) error {
		if err := tx.PutIdentifier(device, proto.Identifier{Kind: "agent.child", Value: "own/container", Strength: proto.Strong}, "own", now); err != nil {
			return err
		}
		return tx.PutIdentifier(device, mac, "own", now)
	}); err != nil {
		t.Fatal(err)
	}
	_, sources, err := db.SnapshotTargets(ctx, device)
	if err != nil || sources["mac="+mac.Value] {
		t.Fatal(sources, err)
	}
	if err := db.InventoryTx(ctx, func(tx inventory.Tx) error { return tx.PutIdentifier(device, mac, "another-agent", now) }); err != nil {
		t.Fatal(err)
	}
	_, sources, err = db.SnapshotTargets(ctx, device)
	if err != nil || !sources["mac="+mac.Value] {
		t.Fatal(sources, err)
	}
}

func testRecentDeviceClaimsExactDeviceAndWindow(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	since := now.Add(-30 * 24 * time.Hour)
	for _, ev := range []store.Event{
		{Type: "device.claimed", At: since, Actor: "boundary", Summary: "Agent boundary took over device #1"},
		{Type: "device.claimed", At: since.Add(-time.Second), Actor: "too-old", Data: `{"device_id":1}`},
		{Type: "device.claimed", At: now.Add(time.Second), Actor: "future", Data: `{"device_id":1}`},
		{Type: "device.claimed", At: now, Actor: "legacy-other", Summary: "Agent legacy-other took over device #10"},
		{Type: "device.claimed", At: now, Actor: "legacy", Summary: "Agent legacy took over device #1", Data: "invalid json"},
		{Type: "device.claimed", At: now, Actor: "structured", Data: `{"device_id":1}`},
		{Type: "device.new", At: now, Actor: "wrong-type", Data: `{"device_id":1}`},
	} {
		if err := db.AddEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	for n := range 1001 {
		if err := db.AddEvent(ctx, store.Event{Type: "unrelated", At: now, Summary: fmt.Sprint(n)}); err != nil {
			t.Fatal(err)
		}
	}
	claims, err := db.RecentDeviceClaims(ctx, 1, since, now)
	if err != nil || len(claims) != 3 {
		t.Fatal(claims, err)
	}
	if claims[0].Agent != "structured" || claims[1].Agent != "legacy" || claims[2].Agent != "boundary" || !claims[2].At.Equal(since) {
		t.Fatal(claims)
	}
}
