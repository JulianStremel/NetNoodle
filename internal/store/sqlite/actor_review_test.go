package sqlite

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func TestTargetProvenanceIsPinnedAndSurvivesMerge(t *testing.T) {
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

func TestActorReviewMigrationBackfillsIdentifierSources(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	device := decideDevice(t, db)
	p, _, err := db.UpsertProposal(ctx, store.Proposal{DeviceID: device, VulnID: "legacy", Action: "isolate", Tier: "approve", State: "pending", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.DecideProposal(ctx, p.ID, "approved", "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	// Reconstruct 0009, retaining real inventory rows.
	for _, sql := range []string{
		`DROP TABLE device_id_sources`,
		`DROP INDEX events_claims`,
		`ALTER TABLE proposals DROP COLUMN target_reported_elsewhere`,
		`ALTER TABLE proposals DROP COLUMN override_agent_only`,
		`DELETE FROM schema_migrations WHERE name='migrations/0010_actor_review.sql'`,
	} {
		if _, err := db.db.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	for _, id := range []struct{ kind, value, source string }{
		{"agent", "own", "own"}, {"mac", "aa:bb:cc:dd:ee:ff", "own"}, {"mac", "00:11:22:33:44:55", "unifi"},
	} {
		if _, err := db.db.Exec(`INSERT INTO device_ids VALUES (?,?,'strong',?,?,?,?)`, id.kind, id.value, device, id.source, ts(now), ts(now)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	p, err = db.GetProposal(ctx, p.ID)
	if err != nil || p.State != "pending" || len(p.TargetSnapshot) != 0 || p.OverrideAgentOnly || p.Reason != "target provenance changed; approve again" {
		t.Fatal(p, err)
	}
	_, sources, err := db.SnapshotTargets(ctx, device)
	if err != nil || sources["mac=aa:bb:cc:dd:ee:ff"] || !sources["mac=00:11:22:33:44:55"] {
		t.Fatal(sources, err)
	}
	if err = db.migrate(ctx); err != nil {
		t.Fatal("repeat migration", err)
	}
}

func TestAgentChildMACRequiresIndependentReporter(t *testing.T) {
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

func TestRecentDeviceClaimsExactDeviceAndWindow(t *testing.T) {
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
