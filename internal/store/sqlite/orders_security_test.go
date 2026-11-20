package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func TestSnapshotAtAutoAndApprovalAndMergeReset(t *testing.T) {
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

func TestApprovalAndNoActorExpireWithoutOrder(t *testing.T) {
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
func historyOrder(t *testing.T, db *DB, device int64, name, state string, at time.Time, revertAction string, reverted bool, due time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	p, _, e := db.UpsertProposal(ctx, store.Proposal{DeviceID: device, VulnID: name, State: "notify", Tier: "notify", CreatedAt: at})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.db.Exec(`UPDATE proposals SET state='failed' WHERE id=?`, p.ID); e != nil {
		t.Fatal(e)
	}
	payload, e := json.Marshal(proto.Order{Version: proto.Version, ID: name, Actor: "actor", Action: "isolate", NotAfter: at})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.db.Exec(`INSERT INTO orders(id,proposal_id,actor_peer_id,action,targets,params,ttl_s,revert,state,payload,sig,created_at,not_after,done_at,revert_action,reverted,revert_due_at) VALUES (?,?,1,'isolate','[]','{}',60,0,?,?,x'00',?,?,?,?,?,?)`, name, p.ID, state, payload, ts(at), ts(at), ts(at), revertAction, reverted, tsOrEmpty(due)); e != nil {
		t.Fatal(e)
	}
	return p.ID
}
func historyPeer(t *testing.T, db *DB) {
	t.Helper()
	if _, e := db.db.Exec(`INSERT INTO peers(id,name,role,token_hash,created_at) VALUES (1,'actor','actor',x'01',?)`, ts(time.Now())); e != nil {
		t.Fatal(e)
	}
}

func TestOrderRetentionPreservesPendingAndUncertain(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	dev := decideDevice(t, db)
	historyPeer(t, db)
	now := time.Now().UTC()
	old := now.Add(-91 * 24 * time.Hour)
	for _, tc := range []struct {
		name, state, revert string
		reverted            bool
		due                 time.Time
		keep                bool
	}{
		{"done", "done", "", false, time.Time{}, false},
		{"reverted", "done", "unisolate", true, time.Time{}, false},
		{"rejected", "rejected", "unisolate", false, time.Time{}, false},
		{"cancelled", "cancelled", "", false, time.Time{}, false},
		{"expired", "expired", "", false, time.Time{}, false},
		{"failed", "failed", "", false, time.Time{}, false},
		{"uncertain", "uncertain", "unisolate", false, time.Time{}, true},
		{"pending", "done", "unisolate", false, now.Add(time.Hour), true},
		{"manual", "done", "unisolate", false, time.Time{}, true},
		{"retry", "failed", "unisolate", false, now, true},
	} {
		id := historyOrder(t, db, dev, tc.name, tc.state, old, tc.revert, tc.reverted, tc.due)
		if e := db.PurgeProposals(ctx, now.Add(-90*24*time.Hour)); e != nil {
			t.Fatal(e)
		}
		_, e := db.GetOrder(ctx, tc.name)
		if tc.keep && e != nil || !tc.keep && !errors.Is(e, store.ErrNotFound) {
			t.Fatal(tc.name, e)
		}
		_, e = db.GetProposal(ctx, id)
		if tc.keep && e != nil || !tc.keep && !errors.Is(e, store.ErrNotFound) {
			t.Fatal("proposal", tc.name, e)
		}
	}
	historyOrder(t, db, dev, "recent", "done", now.Add(-89*24*time.Hour), "", false, time.Time{})
	if e := db.PurgeProposals(ctx, now.Add(-90*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e := db.GetOrder(ctx, "recent"); e != nil {
		t.Fatal("recent purged", e)
	}
}

func TestWorkerBatchLimitsAndIndexes(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	dev := decideDevice(t, db)
	historyPeer(t, db)
	now := time.Now().UTC()
	for i := range 201 {
		historyOrder(t, db, dev, fmt.Sprint("order", i), "queued", now.Add(-time.Hour), "", false, time.Time{})
	}
	exp, e := db.ExpiringOrders(ctx, now)
	if e != nil || len(exp) != 200 {
		t.Fatal(len(exp), e)
	}
	if e = db.ExpireOrders(ctx, now); e != nil {
		t.Fatal(e)
	}
	exp, e = db.ExpiringOrders(ctx, now)
	if e != nil || len(exp) != 1 {
		t.Fatal(len(exp), e)
	}
	if _, e = db.db.Exec(`UPDATE orders SET state='done',revert_action='unisolate',revert_due_at=?,reverted=0`, ts(now)); e != nil {
		t.Fatal(e)
	}
	due, e := db.DueReverts(ctx, now)
	if e != nil || len(due) != 200 {
		t.Fatal(len(due), e)
	}
	// A pending revert protects even an otherwise terminal original from retention.
	if _, e = db.db.Exec(`UPDATE orders SET state='uncertain',done_at=?`, ts(now.Add(-91*24*time.Hour))); e != nil {
		t.Fatal(e)
	}
	if e = db.PurgeProposals(ctx, now.Add(-90*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = db.db.QueryRow(`SELECT COUNT(*) FROM orders`).Scan(&count); e != nil || count != 201 {
		t.Fatal(count, e)
	}
	if _, e = db.db.Exec(`DELETE FROM orders; UPDATE proposals SET state='approved'`); e != nil {
		t.Fatal(e)
	}
	ps, e := db.PlanningProposals(ctx)
	if e != nil || len(ps) != 200 {
		t.Fatal(len(ps), e)
	}
	if _, e = db.db.Exec(`UPDATE proposals SET state='failed',updated_at=?`, ts(now.Add(-91*24*time.Hour))); e != nil {
		t.Fatal(e)
	}
	if e = db.PurgeProposals(ctx, now.Add(-90*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = db.db.QueryRow(`SELECT COUNT(*) FROM proposals`).Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	for _, index := range []string{"orders_state_expiry", "orders_revert_due"} {
		var sql string
		if e = db.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name=?`, index).Scan(&sql); e != nil {
			t.Fatal(index, e)
		}
	}
}

func TestSendOrdersChecksSwitchInsideTransaction(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	dev := decideDevice(t, db)
	historyPeer(t, db)
	now := time.Now().UTC()
	historyOrder(t, db, dev, "withheld", "queued", now.Add(time.Hour), "", false, time.Time{})
	// Set the setting directly to isolate SendOrders from cancellation on SetSetting.
	if _, e := db.db.Exec(`UPDATE settings SET value='on' WHERE key='decide.killswitch'`); e != nil {
		t.Fatal(e)
	}
	out, e := db.SendOrders(ctx, 1, now)
	if e != nil || len(out) != 0 {
		t.Fatal(out, e)
	}
	if _, e = db.db.Exec(`UPDATE orders SET revert=1,revert_of='original'`); e != nil {
		t.Fatal(e)
	}
	out, e = db.SendOrders(ctx, 1, now)
	if e != nil || len(out) != 1 {
		t.Fatal(out, e)
	}
}

func TestOrderRetentionBatchLimit(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	dev := decideDevice(t, db)
	historyPeer(t, db)
	now := time.Now().UTC()
	for i := range 201 {
		historyOrder(t, db, dev, fmt.Sprint("terminal", i), "done", now.Add(-91*24*time.Hour), "", false, time.Time{})
	}
	if e := db.PurgeProposals(ctx, now.Add(-90*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	var n int
	if e := db.db.QueryRow(`SELECT COUNT(*) FROM orders`).Scan(&n); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	if e := db.PurgeProposals(ctx, now.Add(-90*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e := db.db.QueryRow(`SELECT COUNT(*) FROM proposals`).Scan(&n); e != nil || n != 0 {
		t.Fatal(n, e)
	}
}

func TestMigration0009PreservesOrdersAndInvalidatesUnpinnedApprovals(t *testing.T) {
	handle, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	handle.SetMaxOpenConns(1)
	db := &DB{db: handle}
	defer db.Close()
	ctx := context.Background()
	if _, e = handle.Exec(`PRAGMA foreign_keys=ON; CREATE TABLE schema_migrations(name TEXT PRIMARY KEY,applied_at TEXT NOT NULL)`); e != nil {
		t.Fatal(e)
	}
	entries, e := migrations.ReadDir("migrations")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "0009") {
			continue
		}
		name := "migrations/" + entry.Name()
		b, e := migrations.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = handle.Exec(string(b)); e != nil {
			t.Fatal(name, e)
		}
		if _, e = handle.Exec(`INSERT INTO schema_migrations VALUES (?,?)`, name, ts(time.Now())); e != nil {
			t.Fatal(e)
		}
	}
	// Approval and pending rows for the same key were legal in 0008.
	device := decideDevice(t, db)
	now := time.Now().UTC()
	historyPeer(t, db)
	for _, state := range []string{"approved", "pending", "auto", "no-actor"} {
		vuln := state
		if state == "pending" {
			vuln = "approved"
		}
		if _, e = handle.Exec(`INSERT INTO proposals(device_id,vuln_id,purl,action,tier,state,reason,created_at,updated_at) VALUES (?,?,'','isolate','approve',?,'',?,?)`, device, vuln, state, ts(now), ts(now)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = handle.Exec(`INSERT INTO orders(id,proposal_id,actor_peer_id,action,targets,params,ttl_s,revert,state,payload,sig,created_at,not_after) VALUES ('existing',1,1,'isolate','[]','{}',60,0,'queued',?,x'00',?,?)`, []byte(`{"version":"v1","id":"existing"}`), ts(now), ts(now.Add(time.Hour))); e != nil {
		t.Fatal(e)
	}
	if e = db.migrate(ctx); e != nil {
		t.Fatal(e)
	}
	ps, e := db.ListProposals(ctx, store.ProposalFilter{})
	if e != nil || len(ps) != 4 {
		t.Fatal(ps, e)
	}
	for _, p := range ps {
		if p.State != "pending" || len(p.TargetSnapshot) != 0 {
			t.Fatal(p)
		}
	}
	o, e := db.GetOrder(ctx, "existing")
	if e != nil || o.State != "queued" {
		t.Fatal(o, e)
	}
}

func TestBlockedRevertBatchDoesNotStarveOtherOrders(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	dev := decideDevice(t, db)
	historyPeer(t, db)
	now := time.Now().UTC()
	for i := range 201 {
		historyOrder(t, db, dev, fmt.Sprintf("due-%03d", i), "done", now.Add(-time.Hour), "unisolate", false, now)
	}
	first, e := db.DueReverts(ctx, now)
	if e != nil || len(first) != 200 {
		t.Fatal(len(first), e)
	}
	for _, o := range first {
		if _, e = db.MarkRevertBlocked(ctx, o.ID); e != nil {
			t.Fatal(e)
		}
	}
	next, e := db.DueReverts(ctx, now)
	if e != nil || len(next) != 200 || next[0].ID != "due-200" {
		t.Fatal(next, e)
	}
}

func TestMovedAutoProposalSurvivesMutableCollision(t *testing.T) {
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
