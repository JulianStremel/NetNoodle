package server

import (
	"context"
	"encoding/json"
	"math"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func reachDevice(id int64, name string, ips ...string) store.DeviceRow {
	d := store.DeviceRow{ID: id, Name: name}
	for _, ip := range ips {
		d.Identifiers = append(d.Identifiers, proto.Identifier{Kind: "ip", Value: ip})
	}
	return d
}

func TestAddressReach(t *testing.T) {
	for _, tc := range []struct{ ip, want string }{
		{"8.8.8.8", reachInternet}, {"2606:4700:4700::1111", reachInternet}, {"::ffff:8.8.8.8", reachInternet},
		{"100.64.0.0", reachTunnel}, {"100.127.255.255", reachTunnel}, {"::ffff:100.64.1.1", reachTunnel},
		{"fd7a:115c:a1e0::1", reachTunnel}, {"100.63.255.255", reachInternet}, {"100.128.0.0", reachInternet},
		{"10.1.2.3", reachLocal}, {"172.16.0.1", reachLocal}, {"192.168.0.1", reachLocal},
		{"fc00::1", reachLocal}, {"fd7a:115c:a1e1::1", reachLocal}, {"169.254.1.1", reachLocal}, {"fe80::1", reachLocal},
		{"127.1.2.3", reachLocal}, {"::1", reachLocal}, {"::ffff:127.0.0.1", reachLocal},
		{"192.0.2.1", reachLocal}, {"198.51.100.1", reachLocal}, {"203.0.113.5", reachLocal},
		{"2001:db8::1", reachLocal}, {"3fff::1", reachLocal}, {"198.18.1.1", reachLocal},
		{"0.0.0.0", reachLocal}, {"::", reachLocal}, {"224.0.0.1", reachLocal}, {"255.255.255.255", reachLocal},
		{"::ffff:203.0.113.5", reachLocal}, {"fe80::1%eth0", reachLocal}, {"ff02::1", reachLocal},
		{"fd7a:115c:a1e0::1%tailscale0", reachTunnel},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			if got := addressReach(netip.MustParseAddr(tc.ip)); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestDeviceAndListenerReach(t *testing.T) {
	router := reachDevice(1, "vps1", "100.64.0.1")
	router.Attributes = map[string]string{"tailscale.routes": "10.0.10.0/24,fd01::/64,0.0.0.0/0,::/0,invalid", "tailscale.exit_node": "true"}
	routes := routedNetworks([]store.DeviceRow{router})
	routed := classifyDevice(reachDevice(2, "web", "10.0.10.20"), routes)
	if routed.level != reachTunnel || !routed.routed || !slices.Contains(routed.evidence, "in 10.0.10.0/24 routed by tailscale node vps1") {
		t.Fatalf("routed = %+v", routed)
	}
	if got := classifyDevice(reachDevice(3, "ipv6", "fd01::20"), routes); got.level != reachTunnel {
		t.Fatal(got)
	}
	if got := classifyDevice(reachDevice(3, "outside", "10.0.11.20"), routes); got.level != reachLocal {
		t.Fatal(got)
	}
	if got := classifyDevice(router, routes); got.level != reachTunnel {
		t.Fatalf("exit node without public IP = %+v", got)
	}
	if got := classifyDevice(store.DeviceRow{Attributes: map[string]string{"tailscale.exit_node": "true"}}, routes); got.level != reachLocal {
		t.Fatalf("exit flag alone = %+v", got)
	}
	router.Identifiers = append(router.Identifiers, proto.Identifier{Kind: "ip", Value: "8.8.4.4"})
	if got := classifyDevice(router, routes); got.level != reachInternet || !slices.Contains(got.evidence, "public address 8.8.4.4") {
		t.Fatal(got)
	}
	vpn := store.DeviceRow{Interfaces: []proto.Interface{{Name: "tailscale0", Kind: "vpn", IPs: []string{"10.0.9.9"}}}}
	if got := classifyDevice(vpn, nil); got.level != reachTunnel || !slices.Contains(got.evidence, "vpn interface tailscale0") {
		t.Fatal(got)
	}
	if got := classifyDevice(store.DeviceRow{Interfaces: []proto.Interface{{IPs: []string{"8.8.8.8"}}}}, nil); got.level != reachInternet {
		t.Fatal(got)
	}
	for _, tc := range []struct {
		addr string
		dev  deviceReach
		want string
	}{
		{"", routed, reachTunnel}, {"0.0.0.0", routed, reachTunnel}, {"::", deviceReach{level: reachInternet}, reachInternet},
		{"127.0.0.1", routed, ""}, {"[::1]", routed, ""}, {"::ffff:127.0.0.1", routed, ""}, {"localhost", routed, ""},
		{"8.8.8.8", routed, reachInternet}, {"100.64.0.5", deviceReach{level: reachLocal}, reachTunnel},
		{"10.0.10.20", routed, reachTunnel}, {"10.0.10.20", deviceReach{level: reachInternet}, reachLocal},
		{"fd7a:115c:a1e0::5", deviceReach{level: reachLocal}, reachTunnel},
		{"*", deviceReach{level: reachInternet}, reachInternet}, {"[::]", routed, reachTunnel},
		{"::ffff:0.0.0.0", routed, reachTunnel}, {"localhost", deviceReach{level: reachInternet}, ""},
		{"fd7a:115c:a1e0::1%tailscale0", deviceReach{level: reachLocal}, reachTunnel},
	} {
		if got := listenerReach(tc.addr, tc.dev); got != tc.want {
			t.Errorf("listener %q on %+v = %q want %q", tc.addr, tc.dev, got, tc.want)
		}
	}
}

func TestReachRiskAndSituation(t *testing.T) {
	for _, tc := range []struct {
		reach string
		want  float64
	}{{"", 5.6}, {reachLocal, 6.6}, {reachTunnel, 7.1}, {reachInternet, 7.6}} {
		if got := findingWeight(8, false, tc.reach, 0); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: %v", tc.reach, got)
		}
		if got := findingWeight(10, true, tc.reach, 1); got != 10 {
			t.Errorf("uncapped: %v", got)
		}
	}
	d := reachDevice(1, "vpn", "100.64.0.1", "8.8.8.8")
	d.Services = 3
	services := []store.DeviceService{
		{DeviceID: 1, Service: proto.Service{Port: 80, Proto: "tcp", Address: "10.0.0.1", Component: "private"}},
		{DeviceID: 1, Service: proto.Service{Port: 443, Proto: "tcp", Address: "::", Component: "public"}},
		{DeviceID: 1, Service: proto.Service{Port: 22, Proto: "tcp", Address: "100.64.0.1", Component: "tunnel"}},
		{DeviceID: 1, Service: proto.Service{Port: 8080, Proto: "tcp", Address: "127.0.0.1", Component: "loopback"}},
		{DeviceID: 1, Service: proto.Service{Port: 8081, Proto: "tcp", Address: "10.0.0.1", Component: "multiple"}},
		{DeviceID: 1, Service: proto.Service{Port: 8082, Proto: "tcp", Address: "8.8.8.8", Component: "multiple"}},
		{DeviceID: 1, Service: proto.Service{Port: 8083, Proto: "tcp", Address: "100.64.0.1", Component: "multiple"}},
	}
	for _, tc := range []struct {
		pkg, reach string
		weight     float64
	}{{"private", reachLocal, 6.6}, {"public", reachInternet, 7.6}, {"tunnel", reachTunnel, 7.1}, {"multiple", reachInternet, 7.6}, {"loopback", reachLocal, 5.6}, {"unexposed", reachLocal, 5.6}} {
		f := store.FindingRow{Finding: store.Finding{DeviceID: 1, PURL: tc.pkg}, Score: 8}
		g := buildGraph([]store.DeviceRow{d}, []store.FindingRow{f}, services, time.Now())
		if math.Abs(g.Nodes[0].Risk-tc.weight) > 1e-9 {
			t.Errorf("%s risk = %v", tc.pkg, g.Nodes[0].Risk)
		}
		detail := store.DeviceDetail{ID: 1}
		for _, svc := range services {
			detail.Services = append(detail.Services, store.ServiceRow{Service: svc.Service})
		}
		sit := findingSituation(detail, f, g.Nodes[0])
		if sit.Device.Reach != tc.reach || sit.Device.Exposed != (tc.pkg != "unexposed" && tc.pkg != "loopback") {
			t.Errorf("%s situation = %+v", tc.pkg, sit.Device)
		}
	}
}

func TestRoutedListenerRiskAndSituation(t *testing.T) {
	router := reachDevice(1, "vps1", "100.64.0.1")
	router.Attributes = map[string]string{"tailscale.routes": "10.0.10.0/24"}
	web := reachDevice(2, "web", "10.0.10.5")
	f := store.FindingRow{Finding: store.Finding{DeviceID: 2, PURL: "web"}, Score: 8}
	service := proto.Service{Port: 443, Proto: "tcp", Address: "10.0.10.5", Component: "web"}
	g := buildGraph([]store.DeviceRow{router, web}, []store.FindingRow{f}, []store.DeviceService{{DeviceID: 2, Service: service}}, time.Now())
	n := g.Nodes[1]
	if n.Reach != reachTunnel || n.Services[0].Reach != reachTunnel || math.Abs(n.Risk-7.1) > 1e-9 || n.Exposed != 1 || !n.Top[0].Exposed {
		t.Fatalf("routed node = %+v", n)
	}
	sit := findingSituation(store.DeviceDetail{ID: 2, Services: []store.ServiceRow{{Service: service}}}, f, n)
	if sit.Device.Reach != reachTunnel || !sit.Device.Exposed {
		t.Fatalf("routed situation = %+v", sit)
	}
}

func TestReachAPIs(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	ctx := context.Background()
	err := s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
		_, err := tx.CreateDevice(inventory.Device{Kind: proto.KindHost, Name: "router", Seen: time.Now(), Attributes: map[string]string{"tailscale.routes": "10.0.10.0/24"}, Interfaces: []proto.Interface{{Name: "tailscale0", Kind: "vpn"}}})
		if err != nil {
			return err
		}
		web, err := tx.CreateDevice(inventory.Device{Kind: proto.KindHost, Name: "web", Seen: time.Now(), Interfaces: []proto.Interface{{Name: "eth0", IPs: []string{"10.0.10.10"}}}})
		if err != nil {
			return err
		}
		for name, ip := range map[string]string{"public": "8.8.4.4", "local": "10.1.1.1"} {
			if _, err := tx.CreateDevice(inventory.Device{Kind: proto.KindHost, Name: name, Seen: time.Now(), Interfaces: []proto.Interface{{IPs: []string{ip}}}}); err != nil {
				return err
			}
		}
		return tx.PutServices(web, "test", []proto.Service{{Port: 443, Proto: "tcp", Address: "10.0.10.10", Component: "web"}}, true, time.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	devs, err := s.st.ListDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantReach := map[string]string{"router": reachTunnel, "web": reachTunnel, "public": reachInternet, "local": reachLocal}
	for _, d := range devs {
		r := httptest.NewRequest("GET", "/api/devices/"+strconv.FormatInt(d.ID, 10), nil)
		r.SetPathValue("id", strconv.FormatInt(d.ID, 10))
		w := httptest.NewRecorder()
		s.handleGetDevice(w, r)
		var detail struct {
			Reach    string   `json:"reach"`
			Evidence []string `json:"reach_evidence"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil || w.Code != 200 || detail.Reach != wantReach[d.Name] || detail.Evidence == nil {
			t.Fatalf("detail %d: %s %v", w.Code, w.Body, err)
		}
		if d.Name != "local" && len(detail.Evidence) == 0 {
			t.Fatalf("missing evidence for %s", d.Name)
		}
	}
	w := httptest.NewRecorder()
	s.handleGraph(w, httptest.NewRequest("GET", "/api/graph", nil))
	var graph Graph
	if err := json.Unmarshal(w.Body.Bytes(), &graph); err != nil || w.Code != 200 || graph.Stats["reach.tunnel"] != 2 || graph.Stats["reach.internet"] != 1 || graph.Stats["reach.local"] != 1 {
		t.Fatalf("graph: %s %v", w.Body, err)
	}
	for _, n := range graph.Nodes {
		if n.Reach != wantReach[n.Name] || n.ReachEvidence == nil {
			t.Fatalf("node = %+v", n)
		}
		if n.Name == "web" && (len(n.Services) != 1 || n.Services[0].Reach != reachTunnel) {
			t.Fatalf("services = %+v", n.Services)
		}
	}
	nodes, err := s.decisionContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		if d.Name != "web" {
			continue
		}
		detail, err := s.st.GetDevice(ctx, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		sit := findingSituation(detail, store.FindingRow{Finding: store.Finding{DeviceID: d.ID, PURL: "web"}}, nodes[d.ID])
		if sit.Device.Reach != reachTunnel || !sit.Device.Exposed {
			t.Fatalf("decision context lost routed reach: %+v", sit)
		}
	}
}

// TestWideRoutesIgnored: routes wider than /8 (IPv4) or /32 (IPv6) are not
// subnet routes and do not make devices tunnel-reachable (security review
// 2026-11-20).
func TestWideRoutesIgnored(t *testing.T) {
	router := reachDevice(1, "vps1", "100.64.0.1")
	router.Attributes = map[string]string{"tailscale.routes": "0.0.0.0/1,128.0.0.0/1,::/1,2000::/3"}
	routes := routedNetworks([]store.DeviceRow{router})
	if len(routes) != 0 {
		t.Fatal(routes)
	}
	if got := classifyDevice(reachDevice(2, "web", "10.0.10.20"), routes); got.routed {
		t.Fatal(got)
	}
}
