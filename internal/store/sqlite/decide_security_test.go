package sqlite

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

func TestProposalUpsertReusesAllMutableStates(t *testing.T) {
	for _, old := range []string{"notify", "pending", "auto", "resolved", "expired"} {
		for _, next := range []string{"notify", "pending", "auto"} {
			t.Run(old+"/"+next, func(t *testing.T) {
				ctx := context.Background()
				db := open(t)
				id := decideDevice(t, db)
				now := time.Now().UTC()
				in := store.Proposal{DeviceID: id, VulnID: "v", Action: "snapshot", State: "notify", Tier: "notify", CreatedAt: now}
				p, _, err := db.UpsertProposal(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = db.db.Exec(`UPDATE proposals SET state=? WHERE id=?`, old, p.ID); err != nil {
					t.Fatal(err)
				}
				in.State, in.Tier, in.Reason = next, "auto", "changed"
				if next == "pending" {
					in.Tier = "approve"
				}
				in.CreatedAt = now.Add(time.Hour)
				in.DecidedBy = []string{"new-decider"}
				in.Params = map[string]any{"port": float64(42)}
				in.TTL = 3600
				q, fresh, err := db.UpsertProposal(ctx, in)
				wantFresh := old != "pending" && old != "auto" && next != "notify"
				wantCreated := now
				if old == "resolved" || old == "expired" {
					wantCreated = in.CreatedAt
				}
				if err != nil || q.ID != p.ID || fresh != wantFresh || q.State != next || q.Reason != "changed" || q.TTL != 3600 || len(q.DecidedBy) != 1 || q.DecidedBy[0] != "new-decider" || q.Params["port"] != float64(42) || !q.CreatedAt.Equal(wantCreated) || !q.UpdatedAt.Equal(in.CreatedAt) {
					t.Fatalf("upsert %+v fresh=%v err=%v", q, fresh, err)
				}
				for range 50 {
					q, fresh, err = db.UpsertProposal(ctx, in)
					if err != nil || fresh || q.ID != p.ID {
						t.Fatal(q, fresh, err)
					}
				}
				ps, err := db.ListProposals(ctx, store.ProposalFilter{})
				if err != nil || len(ps) != 1 {
					t.Fatal(ps, err)
				}
			})
		}
	}
}

func TestProposalResolutionAndRetention(t *testing.T) {
	ctx := context.Background()
	db := open(t)
	id := decideDevice(t, db)
	now := time.Now()
	for _, state := range []string{"notify", "pending", "auto", "approved", "rejected", "expired", "resolved"} {
		for _, age := range []int{1, 91} {
			p, _, err := db.UpsertProposal(ctx, store.Proposal{DeviceID: id, VulnID: fmt.Sprintf("%s-%d", state, age), State: "notify", Tier: "notify", CreatedAt: now.Add(-time.Duration(age) * 24 * time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.db.Exec(`UPDATE proposals SET state=? WHERE id=?`, state, p.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := db.PurgeProposals(ctx, now.Add(-90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	stats, err := db.ProposalStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"notify", "approved", "rejected", "expired", "resolved"} {
		if stats[state] != 1 {
			t.Fatal(stats)
		}
	}
	if stats["pending"] != 2 || stats["auto"] != 2 {
		t.Fatal(stats)
	}
	if err := db.ResolveProposals(ctx, id, []string{"notify-1"}); err != nil {
		t.Fatal(err)
	}
	stats, err = db.ProposalStats(ctx)
	if err != nil || stats["notify"] != 1 || stats["pending"] != 0 || stats["auto"] != 0 || stats["approved"] != 1 || stats["rejected"] != 1 || stats["resolved"] != 5 {
		t.Fatal(stats, err)
	}
	if err := db.ResolveProposals(ctx, id, nil); err != nil {
		t.Fatal(err)
	}
	stats, _ = db.ProposalStats(ctx)
	if stats["notify"] != 0 || stats["resolved"] != 6 {
		t.Fatal(stats)
	}
}

func TestDecideProposalRejectsExpiredDeadline(t *testing.T) {
	for _, decision := range []string{"approved", "rejected"} {
		for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			t.Run(fmt.Sprint(decision, delta), func(t *testing.T) {
				ctx := context.Background()
				db := open(t)
				now := time.Now().UTC()
				p, _, err := db.UpsertProposal(ctx, store.Proposal{DeviceID: decideDevice(t, db), VulnID: "v", State: "pending", Tier: "approve", CreatedAt: now})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = db.db.Exec(`UPDATE proposals SET expires_at=? WHERE id=?`, ts(now.Add(delta)), p.ID); err != nil {
					t.Fatal(err)
				}
				err = db.DecideProposal(ctx, p.ID, decision, "alice", now)
				if delta <= 0 && !errors.Is(err, store.ErrConflict) || delta > 0 && err != nil {
					t.Fatal(delta, err)
				}
				q, _ := db.GetProposal(ctx, p.ID)
				if delta <= 0 && (q.State != "pending" || q.DecidedUser != "") {
					t.Fatal(q)
				}
			})
		}
	}
}

func TestProposalMigrationConsolidatesExistingFlood(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	id := decideDevice(t, db)
	p, _, err := db.UpsertProposal(ctx, store.Proposal{DeviceID: id, VulnID: "v", State: "notify", Tier: "notify"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.db.Exec(`DROP INDEX proposals_mutable; DELETE FROM schema_migrations WHERE name='migrations/0007_proposal_keys.sql'`); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"approved", "rejected", "resolved", "expired", "notify", "notify"} {
		if _, err = db.db.Exec(`INSERT INTO proposals(device_id,vuln_id,purl,action,tier,state,reason,created_at,updated_at) SELECT device_id,vuln_id,purl,action,tier,?,reason,created_at,updated_at FROM proposals WHERE id=?`, state, p.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.db.Exec(`CREATE UNIQUE INDEX proposals_open ON proposals(device_id,vuln_id,action) WHERE state IN ('pending','approved','auto')`); err != nil {
		t.Fatal(err)
	}
	if err = db.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ps, err := db.ListProposals(ctx, store.ProposalFilter{})
	if err != nil || len(ps) != 3 || ps[0].State != "notify" {
		t.Fatal(ps, err)
	}
	if _, err = db.db.Exec(`INSERT INTO proposals(device_id,vuln_id,purl,action,tier,state,reason,created_at,updated_at) SELECT device_id,vuln_id,purl,action,tier,state,reason,created_at,updated_at FROM proposals WHERE id=?`, ps[0].ID); err == nil {
		t.Fatal("duplicate mutable key accepted")
	}
}
