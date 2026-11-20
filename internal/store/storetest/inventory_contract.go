package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

var t0 = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

func strong(k, v string) proto.Identifier {
	return proto.Identifier{Kind: k, Value: v, Strength: proto.Strong}
}
func weak(k, v string) proto.Identifier {
	return proto.Identifier{Kind: k, Value: v, Strength: proto.Weak}
}

func ingest(t *testing.T, db store.Store, src string, at time.Time, complete bool, ents ...proto.Entity) inventory.Result {
	t.Helper()
	res, err := inventory.IngestAs(context.Background(), db, proto.Observation{
		Version: proto.Version, Source: src, ObservedAt: at, Complete: complete, Entities: ents,
	}, []byte("{}"), at, "")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func deviceCount(t *testing.T, db store.Store) int {
	t.Helper()
	d, err := db.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(d)
}

func testSameDeviceTwice(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	e := proto.Entity{Kind: proto.KindHost, Identifiers: []proto.Identifier{strong("mac", "00-1A-2B-00-00-01"), weak("ip", "10.0.0.5")}}
	r1 := ingest(t, db, "scan", t0, false, e)
	r2 := ingest(t, db, "scan", t0.Add(time.Minute), false, e)
	if len(r1.New) != 1 || len(r2.New) != 0 || r1.Devices[0] != r2.Devices[0] {
		t.Fatalf("r1=%+v r2=%+v", r1, r2)
	}
}

func testDHCPMoveCreatesNewDevice(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	ingest(t, db, "scan", t0, false, proto.Entity{Identifiers: []proto.Identifier{strong("mac", "00:1a:2b:00:00:01"), weak("ip", "10.0.0.5")}})
	r := ingest(t, db, "scan", t0.Add(time.Hour), false, proto.Entity{Identifiers: []proto.Identifier{strong("mac", "00:1a:2b:00:00:02"), weak("ip", "10.0.0.5")}})
	if len(r.New) != 1 {
		t.Fatalf("want new device for other MAC, got %+v", r)
	}
	d, _ := db.GetDevice(context.Background(), r.Devices[0])
	hasIP := false
	for _, id := range d.IDs {
		if id.Kind == "ip" && id.Value == "10.0.0.5" {
			hasIP = true
		}
	}
	if !hasIP {
		t.Fatal("IP did not move to the new device")
	}
}

func testWeakMatchThenStrong(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	// A scan from another subnet sees only the IP.
	r1 := ingest(t, db, "scan-remote", t0, false, proto.Entity{Identifiers: []proto.Identifier{weak("ip", "10.0.9.9")}})
	// The gateway knows the MAC for that IP.
	r2 := ingest(t, db, "unifi", t0, false, proto.Entity{Name: "printer", Identifiers: []proto.Identifier{strong("mac", "00:1a:2b:00:00:09"), weak("ip", "10.0.9.9")}})
	if len(r2.New) != 0 || r1.Devices[0] != r2.Devices[0] {
		t.Fatalf("weak match failed: r1=%+v r2=%+v", r1, r2)
	}
	d, _ := db.GetDevice(context.Background(), r1.Devices[0])
	if d.Name != "printer" {
		t.Fatalf("name = %q", d.Name)
	}
}

func testStrongCollisionMerges(t *testing.T, open func(t *testing.T) store.Store) {
	testAgentOwnedNotMerged(t, open)
	db := open(t)
	a := ingest(t, db, "scan", t0, false, proto.Entity{Identifiers: []proto.Identifier{strong("mac", "00:1a:2b:00:00:01")},
		Services: []proto.Service{{Port: 22, Proto: "tcp", Product: "openssh"}}})
	b := ingest(t, db, "agent:web1", t0, true, proto.Entity{Kind: proto.KindHost, Name: "web1", Identifiers: []proto.Identifier{strong("serial", "web1")},
		Components: []proto.Component{{PURL: "pkg:deb/debian/nginx@1.22.1", Name: "nginx", Version: "1.22.1"}}})
	if deviceCount(t, db) != 2 {
		t.Fatal("want 2 devices before merge")
	}
	// The agent reports its interfaces: now one entity has both strong ids.
	m := ingest(t, db, "agent:web1", t0.Add(time.Minute), true, proto.Entity{Kind: proto.KindHost, Identifiers: []proto.Identifier{strong("serial", "web1")},
		Interfaces: []proto.Interface{{Name: "eth0", MAC: "00:1a:2b:00:00:01", IPs: []string{"10.0.0.5"}}},
		Components: []proto.Component{{PURL: "pkg:deb/debian/nginx@1.22.1", Name: "nginx", Version: "1.22.1"}}})
	if len(m.Merged) != 1 || deviceCount(t, db) != 1 {
		t.Fatalf("merge: %+v, devices=%d", m, deviceCount(t, db))
	}
	keep := a.Devices[0]
	if b.Devices[0] < keep {
		keep = b.Devices[0]
	}
	d, err := db.GetDevice(context.Background(), keep)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "web1" || d.Kind != "host" || len(d.Components) != 1 || len(d.Services) != 1 {
		t.Fatalf("merged device = %+v", d)
	}
}

func testLocalMACIsWeak(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	docker := "02:42:ac:11:00:02" // locally administered, same on many hosts
	ingest(t, db, "agent:a", t0, false, proto.Entity{Identifiers: []proto.Identifier{strong("agent", "a"), strong("mac", docker)}})
	ingest(t, db, "agent:b", t0, false, proto.Entity{Identifiers: []proto.Identifier{strong("agent", "b"), strong("mac", docker)}})
	if n := deviceCount(t, db); n != 2 {
		t.Fatalf("docker MAC merged two hosts: %d devices", n)
	}
}

func testChildrenAndCompleteReports(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	ctx := context.Background()
	host := proto.Entity{
		Kind: proto.KindHost, Identifiers: []proto.Identifier{strong("agent", "pve1")},
		Components: []proto.Component{
			{PURL: "pkg:deb/debian/openssl@3.0.11", Name: "openssl", Version: "3.0.11"},
			{PURL: "pkg:deb/debian/curl@7.88.1", Name: "curl", Version: "7.88.1"},
		},
		Children: []proto.Entity{{Kind: proto.KindVM, Name: "vm100", Identifiers: []proto.Identifier{strong("proxmox.guest", "c1/100")}}},
	}
	r := ingest(t, db, "agent:pve1", t0, true, host)
	if len(r.New) != 2 {
		t.Fatalf("want host + vm, got %+v", r)
	}
	vm, _ := db.GetDevice(ctx, r.Devices[1])
	if vm.ParentID != r.Devices[0] {
		t.Fatalf("vm parent = %d, want %d", vm.ParentID, r.Devices[0])
	}

	host.Components = host.Components[:1] // curl removed
	ingest(t, db, "agent:pve1", t0.Add(time.Hour), true, host)
	d, _ := db.GetDevice(ctx, r.Devices[0])
	if len(d.Components) != 1 || d.Components[0].Name != "openssl" {
		t.Fatalf("complete report did not remove curl: %+v", d.Components)
	}
	if len(d.Children) != 1 {
		t.Fatalf("children = %+v", d.Children)
	}
}

func testParentPlaceholder(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	ctx := context.Background()
	r := ingest(t, db, "proxmox", t0, false, proto.Entity{Kind: proto.KindVM, Name: "vm101",
		Identifiers: []proto.Identifier{strong("proxmox.guest", "c1/101")},
		Parent:      []proto.Identifier{strong("proxmox.node", "c1/pve2")}})
	if len(r.New) != 2 {
		t.Fatalf("want placeholder + vm: %+v", r)
	}
	vm, _ := db.GetDevice(ctx, r.Devices[0])
	if vm.ParentID == 0 {
		t.Fatal("no parent")
	}
	// The node itself shows up later and fills the placeholder.
	r2 := ingest(t, db, "proxmox", t0, false, proto.Entity{Kind: proto.KindHost, Name: "pve2",
		Identifiers: []proto.Identifier{strong("proxmox.node", "c1/pve2")}})
	if len(r2.New) != 0 || r2.Devices[0] != vm.ParentID {
		t.Fatalf("node did not fill placeholder: %+v", r2)
	}
	n, _ := db.GetDevice(ctx, vm.ParentID)
	if n.Name != "pve2" || n.Kind != "host" {
		t.Fatalf("placeholder not filled: %+v", n)
	}
}

func testSkipsEntitiesWithoutIdentifiers(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	r := ingest(t, db, "x", t0, false,
		proto.Entity{Identifiers: []proto.Identifier{weak("ip", "127.0.0.1")}},
		proto.Entity{Identifiers: []proto.Identifier{strong("mac", "ff:ff:ff:ff:ff:ff")}})
	if r.Skipped != 2 || deviceCount(t, db) != 0 {
		t.Fatalf("r=%+v", r)
	}
}

// testAgentOwnedNotMerged: a source entity that connects an agent-owned
// device with another device does not merge them (security review
// 2026-11-20: source data can contain values that a device controls).
func testAgentOwnedNotMerged(t *testing.T, open func(t *testing.T) store.Store) {
	db := open(t)
	ingest(t, db, "scan", t0, false, proto.Entity{Identifiers: []proto.Identifier{strong("mac", "00:1a:2b:00:00:71")}})
	ingest(t, db, "agent:nas", t0, true, proto.Entity{Kind: proto.KindHost, Identifiers: []proto.Identifier{strong("agent", "nas")}})
	r := ingest(t, db, "homeassistant", t0.Add(time.Minute), false, proto.Entity{Identifiers: []proto.Identifier{strong("homeassistant.device", "ha/x"), strong("mac", "00:1a:2b:00:00:71"), strong("agent", "nas")}})
	if len(r.Merged) != 0 || len(r.MergeRefused) != 1 || deviceCount(t, db) != 2 {
		t.Fatalf("agent-owned device merged: %+v devices=%d", r, deviceCount(t, db))
	}
}
