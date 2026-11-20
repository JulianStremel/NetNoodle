package server

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/JulianStremel/netnoodle/internal/store"
)

const (
	reachLocal    = "local"
	reachTunnel   = "tunnel"
	reachInternet = "internet"
)

var tailnetPrefixes = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

// Global unicast includes documentation and other special-use ranges. They
// cannot establish public reachability, including IPv4-mapped forms.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("2001:2::/48"), netip.MustParsePrefix("100::/64"),
}

func addressReach(ip netip.Addr) string {
	ip = ip.Unmap().WithZone("")
	for _, p := range tailnetPrefixes {
		if p.Contains(ip) {
			return reachTunnel
		}
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return reachLocal
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return reachLocal
		}
	}
	return reachInternet
}

func reachRank(r string) int {
	switch r {
	case reachInternet:
		return 2
	case reachTunnel:
		return 1
	}
	return 0
}

func maxReach(a, b string) string {
	if reachRank(b) > reachRank(a) {
		return b
	}
	if a == "" {
		return reachLocal
	}
	return a
}

type deviceReach struct {
	level    string
	evidence []string
	routed   bool
}

// Prefix lookup bounds the work per address even with many subnet routers.
type routeIndex map[netip.Prefix][]string

func routedNetworks(devs []store.DeviceRow) routeIndex {
	out := routeIndex{}
	for _, d := range devs {
		name := d.Name
		if name == "" {
			name = fmt.Sprintf("#%d", d.ID)
		}
		for _, raw := range strings.Split(d.Attributes["tailscale.routes"], ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(raw))
			// Exit routes do not expose every device.
			if err != nil || p.Bits() == 0 {
				continue
			}
			p = p.Masked()
			out[p] = append(out[p], "in "+p.String()+" routed by tailscale node "+name)
		}
	}
	return out
}

func deviceIPs(d store.DeviceRow) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, id := range d.Identifiers {
		if id.Kind == "ip" {
			add(id.Value)
		}
	}
	for _, in := range d.Interfaces {
		for _, ip := range in.IPs {
			add(ip)
		}
	}
	return out
}

func classifyDevice(d store.DeviceRow, routes routeIndex) deviceReach {
	r := deviceReach{level: reachLocal, evidence: []string{}}
	seen := map[string]bool{}
	add := func(e string) {
		if !seen[e] {
			r.evidence = append(r.evidence, e)
			seen[e] = true
		}
	}
	for _, in := range d.Interfaces {
		if in.Kind == "vpn" {
			r.level = maxReach(r.level, reachTunnel)
			add("vpn interface " + in.Name)
		}
	}
	for _, raw := range deviceIPs(d) {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		ip = ip.Unmap().WithZone("")
		level := addressReach(ip)
		r.level = maxReach(r.level, level)
		switch level {
		case reachInternet:
			add("public address " + ip.String())
		case reachTunnel:
			add("tailnet address " + ip.String())
		}
		for bits := ip.BitLen(); bits > 0; bits-- {
			for _, evidence := range routes[netip.PrefixFrom(ip, bits).Masked()] {
				r.routed = true
				r.level = maxReach(r.level, reachTunnel)
				add(evidence)
			}
		}
	}
	sort.Strings(r.evidence)
	return r
}

// Empty reach means a loopback listener, which has no exposure weight.
func listenerReach(address string, device deviceReach) string {
	address = strings.Trim(address, "[]")
	if address == "" || address == "*" {
		return maxReach(device.level, reachLocal)
	}
	if strings.EqualFold(address, "localhost") {
		return ""
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return reachLocal
	}
	ip = ip.Unmap().WithZone("")
	if ip.IsLoopback() {
		return ""
	}
	if ip.IsUnspecified() {
		return maxReach(device.level, reachLocal)
	}
	level := addressReach(ip)
	if level == reachLocal && device.routed {
		return reachTunnel
	}
	return level
}
