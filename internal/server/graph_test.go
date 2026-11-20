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
		{ID: 2, Name: "web", Kind: "vm", ParentID: 1, Identifiers: []proto.Identifier{ip("10.0.0.50"), ip("fe80::1")}},
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
	// 7.5*0.7 + 0.5 + 2 (KEV) + 1 (exposed) = 8.75 > 9.8*0.7 = 6.86
	if web.Risk < 8.74 || web.Risk > 8.76 || web.Exposed != 1 || web.Top[0].ID != "CVE-1" {
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
	if !web.Services[0].Exposed || !web.Services[0].KEV || web.Services[0].Vulns != 1 || web.Services[1].Exposed {
		t.Fatalf("services = %+v", web.Services)
	}
	if len(g.Networks) != 2 || g.Networks[0].ID != "10.0.0.0/24" || !slices.Equal(g.Networks[0].Devices, []int64{1, 2}) {
		t.Fatalf("networks = %+v (link-local must be skipped)", g.Networks)
	}
}
