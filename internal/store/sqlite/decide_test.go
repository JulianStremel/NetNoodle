package sqlite

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func decideDevice(t *testing.T, db *DB) int64 {
	t.Helper()
	var id int64
	e := db.InventoryTx(context.Background(), func(tx inventory.Tx) error {
		var e error
		id, e = tx.CreateDevice(inventory.Device{Kind: proto.KindHost, Name: "test", Seen: time.Now()})
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func TestProposalsLifecycle(t *testing.T) {
	ctx := context.Background()
	db := open(t)
	id := decideDevice(t, db)
	now := time.Now().UTC()
	input := store.Proposal{DeviceID: id, VulnID: "CVE-1", PURL: "pkg:generic/a@1", Action: "isolate", Tier: "approve", State: "pending", Reason: "kev", TTL: 86400, Params: map[string]any{"port": float64(22)}, DecidedBy: []string{"rules"}, CreatedAt: now}
	p, fresh, e := db.UpsertProposal(ctx, input)
	if e != nil || !fresh || p.ID == 0 || p.ExpiresAt.IsZero() {
		t.Fatalf("%+v %v %v", p, fresh, e)
	}
	input.Reason = "updated"
	input.CreatedAt = now.Add(time.Hour)
	q, fresh, e := db.UpsertProposal(ctx, input)
	if e != nil || fresh || q.ID != p.ID || q.Reason != "updated" || !q.CreatedAt.Equal(p.CreatedAt) || !q.ExpiresAt.Equal(p.ExpiresAt) {
		t.Fatalf("dedupe %+v %v %v", q, fresh, e)
	}
	if e = db.DecideProposal(ctx, p.ID, "approved", "alice", now); e != nil {
		t.Fatal(e)
	}
	if e = db.DecideProposal(ctx, p.ID, "rejected", "bob", now); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("decision conflict: %v", e)
	}
	input.Params = map[string]any{"port": float64(23)}
	input.TTL = 1
	q, _, e = db.UpsertProposal(ctx, input)
	if e != nil || q.State != "approved" || q.DecidedUser != "alice" || q.DecidedAt.IsZero() || q.TTL != 86400 || q.Params["port"] != float64(22) {
		t.Fatalf("reviewed scope changed: %+v %v", q, e)
	}
	input.Action = "block-port"
	input.CreatedAt = now.Add(-8 * 24 * time.Hour)
	expired, _, e := db.UpsertProposal(ctx, input)
	if e != nil {
		t.Fatal(e)
	}
	input.Action = "snapshot"
	input.Tier = "auto"
	input.State = "auto"
	auto, _, e := db.UpsertProposal(ctx, input)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.ExpireProposals(ctx, now.Add(-7*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	q, _ = db.GetProposal(ctx, expired.ID)
	if q.State != "expired" {
		t.Fatal(q)
	}
	q, _ = db.GetProposal(ctx, auto.ID)
	if q.State != "auto" {
		t.Fatal("auto expired")
	}
	q, _ = db.GetProposal(ctx, p.ID)
	if q.State != "approved" {
		t.Fatal("approved expired")
	}
	if e = db.ResolveProposals(ctx, id, []string{"CVE-1"}); e != nil {
		t.Fatal(e)
	}
	q, _ = db.GetProposal(ctx, auto.ID)
	if q.State != "auto" {
		t.Fatal("still-open finding resolved")
	}
	if e = db.ResolveProposals(ctx, id, nil); e != nil {
		t.Fatal(e)
	}
	q, _ = db.GetProposal(ctx, auto.ID)
	if q.State != "resolved" {
		t.Fatal(q)
	}
	q, _ = db.GetProposal(ctx, p.ID)
	if q.State != "approved" {
		t.Fatal(q)
	}
	input.Action = "snapshot"
	input.Tier = "approve"
	input.State = "pending"
	input.CreatedAt = now
	r, _, e := db.UpsertProposal(ctx, input)
	if e != nil || r.ID != auto.ID {
		t.Fatalf("reopened %+v %v", r, e)
	}
	if e = db.DecideProposal(ctx, r.ID, "rejected", "bob", now); e != nil {
		t.Fatal(e)
	}
	list, e := db.ListProposals(ctx, store.ProposalFilter{State: "rejected", DeviceID: id, Limit: 1})
	if e != nil || len(list) != 1 || list[0].DecidedUser != "bob" {
		t.Fatalf("filter %+v %v", list, e)
	}
	if _, e = db.GetProposal(ctx, 999); !errors.Is(e, store.ErrNotFound) {
		t.Fatal(e)
	}
}
func TestConcurrentProposalUpsertAndDecision(t *testing.T) {
	db := open(t)
	id := decideDevice(t, db)
	ctx := context.Background()
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			_, _, e := db.UpsertProposal(ctx, store.Proposal{DeviceID: id, VulnID: "v", Action: "isolate", Tier: "approve", State: "pending"})
			if e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	ps, e := db.ListProposals(ctx, store.ProposalFilter{})
	if e != nil || len(ps) != 1 {
		t.Fatalf("%+v %v", ps, e)
	}
	results := make(chan error, 2)
	for _, state := range []string{"approved", "rejected"} {
		wg.Go(func() { results <- db.DecideProposal(ctx, ps[0].ID, state, "user", time.Now()) })
	}
	wg.Wait()
	close(results)
	ok, conflict := 0, 0
	for e := range results {
		if e == nil {
			ok++
		} else if errors.Is(e, store.ErrConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatal(ok, conflict)
	}
}
func TestTagsSettingsAndMerge(t *testing.T) {
	ctx := context.Background()
	db := open(t)
	keep, drop := decideDevice(t, db), decideDevice(t, db)
	for _, tc := range []struct {
		id   int64
		tags []string
	}{{keep, []string{"protected", "lan"}}, {drop, []string{"auto", "lan"}}} {
		if e := db.SetTags(ctx, tc.id, tc.tags); e != nil {
			t.Fatal(e)
		}
	}
	if e := db.SetTags(ctx, drop, []string{"bad tag"}); e == nil {
		t.Fatal("invalid tag")
	}
	if e := db.SetTags(ctx, drop, []string{strings.Repeat("a", 33)}); e == nil {
		t.Fatal("long tag")
	}
	if e := db.SetTags(ctx, drop, make([]string, 33)); e == nil {
		t.Fatal("too many tags")
	}
	for _, id := range []int64{keep, drop} {
		for _, action := range []string{"isolate", "snapshot"} {
			p, _, e := db.UpsertProposal(ctx, store.Proposal{DeviceID: id, VulnID: "v", Action: action, Tier: "approve", State: "pending"})
			if e != nil {
				t.Fatal(e)
			}
			if id == drop && action == "isolate" {
				if e = db.DecideProposal(ctx, p.ID, "approved", "alice", time.Now()); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	if e := db.InventoryTx(ctx, func(tx inventory.Tx) error { return tx.Merge(keep, drop) }); e != nil {
		t.Fatal(e)
	}
	tags, e := db.Tags(ctx, keep)
	if e != nil || !reflect.DeepEqual(tags, []string{"auto", "lan", "protected"}) {
		t.Fatalf("tags %v %v", tags, e)
	}
	d, e := db.GetDevice(ctx, keep)
	if e != nil || !reflect.DeepEqual(d.Tags, tags) {
		t.Fatal(d, e)
	}
	ds, e := db.ListDevices(ctx)
	if e != nil || len(ds) != 1 || !reflect.DeepEqual(ds[0].Tags, tags) {
		t.Fatal(ds, e)
	}
	ps, e := db.ListProposals(ctx, store.ProposalFilter{})
	if e != nil || len(ps) != 3 {
		t.Fatal(ps, e)
	}
	open := 0
	approved := 0
	for _, p := range ps {
		if p.DeviceID != keep {
			t.Fatal("proposal did not move")
		}
		if p.State == "pending" || p.State == "approved" {
			open++
		}
		if p.State == "approved" {
			approved++
		}
	}
	if open != 3 || approved != 0 {
		t.Fatalf("open=%d approved=%d %+v", open, approved, ps)
	}
	if e = db.SetTags(ctx, keep, nil); e != nil {
		t.Fatal(e)
	}
	tags, _ = db.Tags(ctx, keep)
	if tags == nil || len(tags) != 0 {
		t.Fatal(tags)
	}
	if e = db.SetTags(ctx, drop, nil); !errors.Is(e, store.ErrNotFound) {
		t.Fatal(e)
	}
	if v, e := db.GetSetting(ctx, "decide.killswitch"); e != nil || v != "off" {
		t.Fatal(v, e)
	}
	if e = db.SetSetting(ctx, "decide.killswitch", "on"); e != nil {
		t.Fatal(e)
	}
	if v, e := db.GetSetting(ctx, "decide.killswitch"); e != nil || v != "on" {
		t.Fatal(v, e)
	}
}

func TestTagUnionLimitIsAtomic(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	keep, drop := decideDevice(t, db), decideDevice(t, db)
	for i, id := range []int64{keep, drop} {
		tags := []string{}
		for j := range 17 {
			tags = append(tags, fmt.Sprintf("tag-%d-%d", i, j))
		}
		if e := db.SetTags(ctx, id, tags); e != nil {
			t.Fatal(e)
		}
	}
	if e := db.InventoryTx(ctx, func(tx inventory.Tx) error { return tx.Merge(keep, drop) }); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("oversized union: %v", e)
	}
	for _, id := range []int64{keep, drop} {
		tags, e := db.Tags(ctx, id)
		if e != nil || len(tags) != 17 {
			t.Fatal(tags, e)
		}
	}
}
