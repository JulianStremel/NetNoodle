package storetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func ingestAgent(t *testing.T, st store.Store, name string, at time.Time, entity proto.Entity) inventory.Result {
	t.Helper()
	obs := proto.Observation{Version: proto.Version, Source: name, ObservedAt: at, Complete: true, Entities: []proto.Entity{entity}}
	must(t, inventory.PrepareAgent(&obs, name))
	result, err := inventory.IngestAs(context.Background(), st, obs, []byte("{}"), at, name)
	must(t, err)
	return result
}

func lookup(t *testing.T, st store.Store, kind, value string) int64 {
	t.Helper()
	var device int64
	must(t, st.InventoryTx(context.Background(), func(tx inventory.Tx) error {
		var err error
		device, _, err = tx.Lookup(kind, value)
		return err
	}))
	return device
}

func testAgentNoMergeOrStealing(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	macA, macB := strong("mac", "00:11:22:33:44:01"), strong("mac", "00:11:22:33:44:02")
	a := ingest(t, st, "scan", now, false, proto.Entity{Identifiers: []proto.Identifier{macA}}).Devices[0]
	b := ingest(t, st, "scan", now, false, proto.Entity{Identifiers: []proto.Identifier{macB}}).Devices[0]
	res := ingestAgent(t, st, "first", now, proto.Entity{Identifiers: []proto.Identifier{macA, macB}})
	if len(res.Merged) != 0 || len(res.Claimed) != 1 || res.Devices[0] != a {
		t.Fatal(res)
	}
	if lookup(t, st, "mac", macB.Value) != b {
		t.Fatal("agent stole another device's MAC")
	}
	other := ingestAgent(t, st, "second", now, proto.Entity{Identifiers: []proto.Identifier{macA}})
	if other.Devices[0] == a || len(other.Claimed) != 0 {
		t.Fatal("agent claimed an owned device", other)
	}
	if lookup(t, st, "mac", macA.Value) != a {
		t.Fatal("second agent stole MAC")
	}
	res = ingestAgent(t, st, "first", now.Add(time.Minute), proto.Entity{Identifiers: []proto.Identifier{macB}, Components: []proto.Component{{PURL: "pkg:generic/own@1", Name: "own", Version: "1"}}})
	if res.Devices[0] != a || len(res.Merged) != 0 || lookup(t, st, "mac", macB.Value) != b {
		t.Fatal(res)
	}
	devices, err := st.ListDevices(ctx)
	must(t, err)
	if len(devices) != 3 {
		t.Fatal(devices)
	}
	untouched, err := st.GetDevice(ctx, b)
	must(t, err)
	if len(untouched.Components) != 0 {
		t.Fatal("agent changed another device", untouched)
	}
}

func child(cid, mac string) proto.Entity {
	ids := []proto.Identifier{strong(inventory.ContainerIDKind, cid)}
	if mac != "" {
		ids = append(ids, strong("mac", mac))
	}
	return proto.Entity{Kind: proto.KindContainer, Identifiers: ids}
}

func testAgentChildrenScoping(t *testing.T, open func(*testing.T) store.Store) {
	st, now := open(t), time.Now().UTC()
	a := ingestAgent(t, st, "a", now, proto.Entity{}).Devices[0]
	b := ingestAgent(t, st, "b", now, proto.Entity{}).Devices[0]
	macA, macB := "bc:24:11:00:00:01", "bc:24:11:00:00:02"
	for _, tc := range []struct{ name, mac string }{{"a", macA}, {"b", macB}} {
		ingest(t, st, "proxmox", now, false, proto.Entity{Identifiers: []proto.Identifier{strong("agent", tc.name)}, Children: []proto.Entity{{Kind: proto.KindContainer, Identifiers: []proto.Identifier{strong("mac", tc.mac)}}}})
	}
	guestA, guestB := lookup(t, st, "mac", macA), lookup(t, st, "mac", macB)
	r := ingestAgent(t, st, "a", now, proto.Entity{Children: []proto.Entity{child("lxc/101", macA)}})
	if len(r.Claimed) != 1 || r.Claimed[0] != guestA || lookup(t, st, inventory.ChildKind, "a/lxc/101") != guestA {
		t.Fatal(r)
	}
	r = ingestAgent(t, st, "a", now, proto.Entity{Children: []proto.Entity{child("lxc/201", macB)}})
	if len(r.Claimed) != 0 || lookup(t, st, "mac", macB) != guestB {
		t.Fatal("claimed another host's guest", r)
	}
	a201 := lookup(t, st, inventory.ChildKind, "a/lxc/201")
	if a201 == 0 || a201 == guestB {
		t.Fatal("missing scoped child")
	}
	ingestAgent(t, st, "b", now, proto.Entity{Children: []proto.Entity{child("lxc/101", macA)}})
	b101 := lookup(t, st, inventory.ChildKind, "b/lxc/101")
	if b101 == 0 || b101 == guestA || lookup(t, st, "mac", macA) != guestA {
		t.Fatal("container ids crossed agent scope")
	}
	for _, tc := range []struct{ id, parent int64 }{{guestA, a}, {a201, a}, {b101, b}, {guestB, b}} {
		d, err := st.GetDevice(context.Background(), tc.id)
		must(t, err)
		if d.ParentID != tc.parent {
			t.Fatal(d)
		}
	}
}

func testAgentMaxHostChildren(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	host := ingestAgent(t, st, "host", now, proto.Entity{}).Devices[0]
	for start := 0; start < inventory.MaxHostChildren; start += inventory.MaxAgentChildren {
		var children []proto.Entity
		for i := start; i < min(start+inventory.MaxAgentChildren, inventory.MaxHostChildren); i++ {
			children = append(children, child(fmt.Sprint("lxc/", i), ""))
		}
		ingestAgent(t, st, "host", now, proto.Entity{Children: children})
	}
	r := ingestAgent(t, st, "host", now.Add(time.Minute), proto.Entity{Children: []proto.Entity{child("lxc/0", ""), child("lxc/overflow", "")}})
	if r.Skipped != 1 || len(r.Devices) != 2 {
		t.Fatal(r)
	}
	must(t, st.InventoryTx(ctx, func(tx inventory.Tx) error {
		n, err := tx.CountChildren(host)
		if err != nil {
			return err
		}
		if n != inventory.MaxHostChildren {
			return fmt.Errorf("children=%d want %d", n, inventory.MaxHostChildren)
		}
		return nil
	}))
	if lookup(t, st, inventory.ChildKind, "host/lxc/overflow") != 0 {
		t.Fatal("overflow child persisted")
	}
}

func testResolverMergeMovesTagsProposalsOrders(t *testing.T, open func(*testing.T) store.Store) {
	testUntaggedSourceMerge(t, open)
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	keepID := strong("mac", "00:11:22:33:44:55")
	keep := ingest(t, st, "scan", now, false, proto.Entity{Identifiers: []proto.Identifier{keepID}}).Devices[0]
	peer := actor(t, st, "actor", now)
	o := newOrder(t, st, now, "drop", peer)
	p, err := st.GetProposal(ctx, o.ProposalID)
	must(t, err)
	drop := p.DeviceID
	must(t, st.QueueOrder(ctx, o))
	must(t, st.SetTags(ctx, keep, []string{"lan", "protected"}))
	must(t, st.SetTags(ctx, drop, []string{"lan", "auto"}))
	// A source must not merge tagged devices (security review 2026-11-20):
	// the identifiers stay where they are and the refusal is reported.
	result := ingest(t, st, "scan", now.Add(time.Minute), false, proto.Entity{Identifiers: []proto.Identifier{keepID, strong("serial", "drop")}})
	if len(result.Merged) != 0 || len(result.MergeRefused) != 1 {
		t.Fatal(result)
	}
	if lookup(t, st, "serial", "drop") != drop || lookup(t, st, "mac", "00:11:22:33:44:55") != keep {
		t.Fatal("refused merge moved identifiers")
	}
	// The merge itself (operator decision) keeps every tag and the order history.
	must(t, st.InventoryTx(ctx, func(tx inventory.Tx) error { return tx.Merge(keep, drop) }))
	if _, err := st.GetDevice(ctx, drop); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("merged device still exists: %v", err)
	}
	tags, err := st.Tags(ctx, keep)
	must(t, err)
	if !reflect.DeepEqual(tags, []string{"auto", "lan", "protected"}) {
		t.Fatal(tags)
	}
	p, err = st.GetProposal(ctx, o.ProposalID)
	must(t, err)
	if p.DeviceID != keep || p.State != "ordered" {
		t.Fatal(p)
	}
	got, err := st.GetOrder(ctx, o.ID)
	must(t, err)
	if got.ProposalID != o.ProposalID || got.State != "queued" || !reflect.DeepEqual(got.Envelope, o.Envelope) {
		t.Fatalf("merge changed signed order history: %+v", got)
	}
	_, err = st.SendOrders(ctx, peer.ID, now.Add(time.Minute), false)
	must(t, err)
	must(t, st.FinishOrder(ctx, peer.ID, proto.OrderResult{OrderID: o.ID, Status: proto.OrderDone, At: now.Add(time.Minute)}, now.Add(time.Minute)))
}

func testInventoryTransactionRollback(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx := open(t), context.Background()
	sentinel := errors.New("rollback")
	err := st.InventoryTx(ctx, func(tx inventory.Tx) error {
		id, err := tx.CreateDevice(inventory.Device{Kind: proto.KindHost, Seen: time.Now()})
		if err != nil {
			return err
		}
		if err := tx.PutIdentifier(id, strong("serial", "rollback"), "scan", time.Now()); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if deviceCount(t, st) != 0 || lookup(t, st, "serial", "rollback") != 0 {
		t.Fatal("transaction did not roll back")
	}
}

func testResolverIdentifierProvenance(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	mac := strong("mac", "00:11:22:33:44:55")
	entity := proto.Entity{Identifiers: []proto.Identifier{mac}}
	id := ingestAgent(t, st, "owner", now, entity).Devices[0]
	_, evidence, err := st.SnapshotTargets(ctx, id)
	must(t, err)
	if evidence["mac="+mac.Value] {
		t.Fatal("agent's own report counted as independent evidence")
	}
	ingest(t, st, "scanner", now.Add(time.Minute), false, entity)
	ingestAgent(t, st, "owner", now.Add(2*time.Minute), entity)
	_, evidence, err = st.SnapshotTargets(ctx, id)
	must(t, err)
	if !evidence["mac="+mac.Value] {
		t.Fatal("later agent report erased scanner provenance")
	}
	d, err := st.GetDevice(ctx, id)
	must(t, err)
	devices, err := st.ListDevices(ctx)
	must(t, err)
	if len(devices) != 1 || !reflect.DeepEqual(devices[0].Sources, []string{"owner", "scanner"}) {
		t.Fatalf("source history: %+v", devices)
	}
	for _, identifier := range d.IDs {
		if identifier.Kind == "mac" && (!identifier.FirstSeen.Equal(now) || !identifier.LastSeen.Equal(now.Add(2*time.Minute))) {
			t.Fatal(identifier)
		}
	}
}

// testUntaggedSourceMerge: devices without tags or agent are still merged
// by a source whose entity holds strong identifiers of both.
func testUntaggedSourceMerge(t *testing.T, open func(*testing.T) store.Store) {
	st, now := open(t), time.Now().UTC()
	a := ingest(t, st, "scan", now, false, proto.Entity{Identifiers: []proto.Identifier{strong("mac", "00:11:22:33:44:01")}}).Devices[0]
	b := ingest(t, st, "unifi", now, false, proto.Entity{Identifiers: []proto.Identifier{strong("unifi.client", "c1")}}).Devices[0]
	r := ingest(t, st, "unifi", now.Add(time.Minute), false, proto.Entity{Identifiers: []proto.Identifier{strong("unifi.client", "c1"), strong("mac", "00:11:22:33:44:01")}})
	if len(r.Merged) != 1 || len(r.MergeRefused) != 0 || r.Devices[0] != min(a, b) {
		t.Fatal(r)
	}
}
