package server

import (
	"slices"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func TestBuildGraph(t *testing.T) {
	ip := func(v string) proto.Identifier { return proto.Identifier{Kind: "ip", Value: v, Strength: proto.Weak} }
	devs := []store.DeviceRow{
		{ID: 1, Name: "pve1", Kind: "host", Identifiers: []proto.Identifier{ip("10.0.0.11"), {Kind: "agent", Value: "pve1"}}},
		{ID: 2, Name: "web", Kind: "vm", ParentID: 1, Identifiers: []proto.Identifier{ip("10.0.0.50"), ip("fe80::1"), ip("8.8.4.4")}},
		{ID: 3, Name: "dns", Kind: "container", ParentID: 1, Identifiers: []proto.Identifier{ip("10.0.1.53")}},
		{ID: 4, Name: "lonely", Kind: "host", ParentID: 99},
	}
	fs := []store.FindingRow{
		{Finding: store.Finding{DeviceID: 2, PURL: "pkg:deb/debian/nginx@1", VulnID: "CVE-1"}, Score: 7.5, KEV: true, EPSS: 0.5, Exposed: []string{"443/tcp"}},
		{Finding: store.Finding{DeviceID: 2, PURL: "pkg:deb/debian/curl@1", VulnID: "CVE-2"}, Score: 9.8},
	}
	svcs := []store.DeviceService{
		{DeviceID: 2, Service: proto.Service{Port: 443, Proto: "tcp", Address: "0.0.0.0", Component: "pkg:deb/debian/nginx@1"}},
		{DeviceID: 2, Service: proto.Service{Port: 9000, Proto: "tcp", Address: "127.0.0.1"}},
	}
	g := buildGraph(devs, fs, svcs, time.Now())
	by := map[string]GraphNode{}
	for _, n := range g.Nodes {
		by[n.Name] = n
	}
	web, dns, pve := by["web"], by["dns"], by["pve1"]
	// 7.5*0.7 + 0.5 + 2 (KEV) + 2 (internet listener) = 9.75 > 9.8*0.7 = 6.86
	if web.Risk < 9.74 || web.Risk > 9.76 || web.Exposed != 1 || web.Top[0].ID != "CVE-1" {
		t.Fatalf("web = %+v", web)
	}
	if !slices.Equal(pve.Children, []int64{2, 3}) || !slices.Equal(web.Related, []int64{1, 3}) || !slices.Equal(dns.Related, []int64{1, 2}) {
		t.Fatalf("relations: pve=%v web=%v dns=%v", pve.Children, web.Related, dns.Related)
	}
	if dns.RelatedRisk != web.Risk || pve.RelatedRisk != web.Risk || !pve.Agent {
		t.Fatalf("related risk: dns=%v pve=%v", dns.RelatedRisk, pve.RelatedRisk)
	}
	if by["lonely"].Parent != 0 {
		t.Fatal("dangling parent kept")
	}
	if !web.Services[0].Exposed || !web.Services[0].KEV || web.Services[0].Vulns != 1 || web.Services[0].Reach != reachInternet || web.Services[1].Exposed || web.Services[1].Reach != "" {
		t.Fatalf("services = %+v", web.Services)
	}
	if web.Reach != reachInternet || pve.Reach != reachLocal || g.Stats["reach.internet"] != 1 || g.Stats["reach.local"] != 3 {
		t.Fatalf("reach: web=%s pve=%s stats=%v", web.Reach, pve.Reach, g.Stats)
	}
	if len(g.Networks) != 3 || g.Networks[0].ID != "10.0.0.0/24" || !slices.Equal(g.Networks[0].Devices, []int64{1, 2}) {
		t.Fatalf("networks = %+v (link-local must be skipped)", g.Networks)
	}
}

func TestBuildGraphManyGuests(t *testing.T) {
	devs := []store.DeviceRow{{ID: 1, Name: "host", Kind: "host"}}
	for i := int64(2); i <= 10001; i++ {
		devs = append(devs, store.DeviceRow{ID: i, Kind: "container", ParentID: 1})
	}
	fs := []store.FindingRow{{Finding: store.Finding{DeviceID: 5000}, Score: 9.8}}
	start := time.Now()
	g := buildGraph(devs, fs, nil, time.Now())
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("10000 guests took %v", d)
	}
	total := 0
	for _, n := range g.Nodes {
		total += len(n.Related)
		if n.ID != 5000 && n.RelatedRisk == 0 {
			t.Fatalf("device %d does not see the risky sibling", n.ID)
		}
	}
	if total > 10001*(2*maxRelated+1) {
		t.Fatalf("related entries = %d", total)
	}
}

func TestFindingSituationListeners(t *testing.T) {
	d := store.DeviceDetail{ID: 1, Services: []store.ServiceRow{
		{Service: proto.Service{Port: 443, Proto: "tcp", Address: "0.0.0.0", Component: "pkg:deb/debian/nginx@1"}},
		{Service: proto.Service{Port: 443, Proto: "udp", Address: "::", Component: "pkg:deb/debian/nginx@1"}},
		{Service: proto.Service{Port: 8080, Proto: "tcp", Address: "127.0.0.1", Component: "pkg:deb/debian/nginx@1"}},
		{Service: proto.Service{Port: 22, Proto: "tcp", Address: "0.0.0.0", Component: "pkg:deb/debian/openssh-server@1"}},
	}}
	s := findingSituation(d, store.FindingRow{Finding: store.Finding{PURL: "pkg:deb/debian/nginx@1"}}, GraphNode{})
	if !slices.Equal(s.Device.Listeners, []string{"443/tcp", "443/udp"}) || !s.Device.Exposed {
		t.Fatalf("listeners = %v", s.Device.Listeners)
	}
}
