// nn-demo fills a new database with a made-up network: Proxmox nodes with
// guests, a DMZ, clients, IoT devices, packages, services and findings.
// Use it to try the web interface without real data:
//
//	nn-demo -data ./demo-data && nn-server -config demo.json   (data_dir ./demo-data)
//
// All names, addresses and findings are invented. The CVE IDs are real so
// that the links work, but they are not assigned by scanning anything.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
	_ "github.com/JulianStremel/netnoodle/internal/store/sqlite" // built-in store backend
)

type vuln struct {
	id      string
	score   float64
	kev     bool
	epss    float64
	fixed   string
	summary string
}

// catalog maps a package name to its demo vulnerabilities.
var catalog = map[string][]vuln{
	"libc6":          {{"CVE-2023-4911", 7.8, true, 0.73, "2.36-9+deb12u3", "glibc ld.so buffer overflow (Looney Tunables)"}, {"CVE-2024-2961", 8.8, false, 0.41, "2.36-9+deb12u7", "glibc iconv out-of-bounds write"}},
	"openssh-server": {{"CVE-2024-6387", 8.1, false, 0.62, "1:9.2p1-2+deb12u3", "OpenSSH signal handler race (regreSSHion)"}, {"CVE-2023-48795", 5.9, false, 0.96, "1:9.2p1-2+deb12u2", "SSH Terrapin prefix truncation"}},
	"nginx":          {{"CVE-2023-44487", 7.5, true, 0.94, "1.22.1-9+deb12u1", "HTTP/2 Rapid Reset denial of service"}, {"CVE-2022-41741", 7.8, false, 0.05, "1.22.1-1", "nginx mp4 module memory corruption"}},
	"openssl":        {{"CVE-2023-0286", 7.4, false, 0.17, "3.0.8-1", "X.400 address type confusion"}, {"CVE-2022-0778", 7.5, false, 0.12, "1.1.1n-0+deb11u1", "BN_mod_sqrt infinite loop"}},
	"curl":           {{"CVE-2023-38545", 9.8, false, 0.27, "7.88.1-10+deb12u3", "SOCKS5 heap buffer overflow"}, {"CVE-2023-38546", 3.7, false, 0.01, "7.88.1-10+deb12u3", "cookie injection with none file"}},
	"xz-utils":       {{"CVE-2024-3094", 10, false, 0.86, "5.4.1-0.2", "xz/liblzma backdoor"}},
	"postgresql-15":  {{"CVE-2023-39417", 8.8, false, 0.02, "15.4-0+deb12u1", "extension script SQL injection"}},
	"php8.2":         {{"CVE-2024-4577", 9.8, true, 0.94, "8.2.20-1", "PHP-CGI argument injection"}},
	"exim4":          {{"CVE-2023-42115", 9.8, false, 0.12, "4.96-15+deb12u2", "AUTH out-of-bounds write"}},
	"sudo":           {{"CVE-2023-22809", 7.8, false, 0.03, "1.9.13p3-1", "sudoedit arbitrary file write"}},
	"bind9":          {{"CVE-2023-50387", 7.5, false, 0.64, "1:9.18.24-1", "DNSSEC KeyTrap CPU exhaustion"}},
	"grafana":        {{"CVE-2021-43798", 7.5, true, 0.97, "8.3.1", "Grafana directory traversal"}},
	"log4j-core":     {{"CVE-2021-44228", 10, true, 0.97, "2.15.0", "Log4Shell JNDI remote code execution"}},
	"windows":        {{"CVE-2024-38063", 9.8, false, 0.08, "10.0.22631.4037", "Windows TCP/IP IPv6 remote code execution"}, {"CVE-2025-21333", 7.8, true, 0.04, "10.0.22631.4751", "Hyper-V NT Kernel Integration VSP elevation of privilege"}},
	"pve-manager":    {{"CVE-2024-21545", 9.0, false, 0.02, "8.2.5", "Proxmox VE arbitrary file read via API"}},
}

type pkg struct {
	name, version, purlType string
	patched                 bool // newer than every fix in the catalog
}

func (p pkg) purl() string {
	switch p.purlType {
	case "maven":
		return "pkg:maven/org.apache.logging.log4j/" + p.name + "@" + p.version
	case "generic":
		return "pkg:generic/" + p.name + "@" + p.version
	case "windows":
		return "pkg:generic/microsoft/windows@" + p.version + "?release=23H2&type=client"
	}
	return "pkg:deb/debian/" + p.name + "@" + p.version + "?distro=debian-12"
}

var base = []pkg{{"libc6", "2.36-9+deb12u1", "deb", false}, {"openssh-server", "1:9.2p1-2", "deb", false}, {"openssl", "3.0.7-1", "deb", false},
	{"curl", "7.88.1-10", "deb", false}, {"sudo", "1.9.13p3-1", "deb", false}, {"bash", "5.2.15-2", "deb", false}, {"coreutils", "9.1-1", "deb", false}, {"xz-utils", "5.4.1-0.2", "deb", false}}

type svc struct {
	port  int
	proto string
	pkg   string
	addr  string
}

type host struct {
	name, kind string
	ip         string
	agent      bool
	pkgs       []pkg
	svcs       []svc
	children   []host
	attrs      map[string]string
}

var (
	rng    = rand.New(rand.NewPCG(42, 7))
	macSeq = 0
)

func mac() string {
	macSeq++
	return fmt.Sprintf("bc:24:11:%02x:%02x:%02x", macSeq>>16&0xff, macSeq>>8&0xff, macSeq&0xff)
}

func with(extra ...pkg) []pkg {
	out := append([]pkg{}, base...)
	// Most hosts are patched: each base package is up to date with 75 %.
	// One in four hosts is fully patched.
	clean := rng.IntN(4) == 0
	for i := range out {
		if clean || rng.IntN(4) != 0 {
			out[i].patched, out[i].version = true, out[i].version+"+u9"
		}
	}
	return append(out, extra...)
}

func sshd() svc { return svc{22, "tcp", "openssh-server", "0.0.0.0"} }

func network() []host {
	pve := func(name, ip string, guests ...host) host {
		return host{name: name, kind: "host", ip: ip, agent: true,
			pkgs:     with(pkg{"pve-manager", "8.1.4", "generic", false}),
			svcs:     []svc{sshd(), {8006, "tcp", "pve-manager", "0.0.0.0"}, {3128, "tcp", "", "0.0.0.0"}},
			children: guests, attrs: map[string]string{"os.name": "Proxmox VE 8.1"}}
	}
	vm := func(name, ip string, pkgs []pkg, svcs ...svc) host {
		return host{name: name, kind: "vm", ip: ip, agent: true, pkgs: pkgs, svcs: append([]svc{sshd()}, svcs...)}
	}
	lxc := func(name, ip string, pkgs []pkg, svcs ...svc) host {
		return host{name: name, kind: "container", ip: ip, agent: rng.IntN(4) != 0, pkgs: pkgs, svcs: svcs}
	}
	hs := []host{
		pve("pve1", "10.0.10.11",
			vm("web01", "10.0.10.50", with(pkg{"nginx", "1.22.1-9", "deb", false}), svc{80, "tcp", "nginx", "0.0.0.0"}, svc{443, "tcp", "nginx", "0.0.0.0"}),
			vm("db01", "10.0.10.51", with(pkg{"postgresql-15", "15.3-0+deb12u1", "deb", false}), svc{5432, "tcp", "postgresql-15", "0.0.0.0"}),
			lxc("dns01", "10.0.10.53", with(pkg{"bind9", "1:9.18.19-1", "deb", false}), svc{53, "udp", "bind9", "0.0.0.0"}, svc{53, "tcp", "bind9", "0.0.0.0"}),
			lxc("git", "10.0.10.54", with(pkg{"gitea", "1.21.0", "generic", false}), svc{3000, "tcp", "gitea", "0.0.0.0"}),
			vm("monitoring", "10.0.10.55", with(pkg{"grafana", "8.2.0", "generic", false}), svc{3000, "tcp", "grafana", "0.0.0.0"}, svc{9090, "tcp", "", "127.0.0.1"}),
			vm("search", "10.0.10.56", with(pkg{"log4j-core", "2.14.1", "maven", false}), svc{9200, "tcp", "log4j-core", "0.0.0.0"}),
		),
		pve("pve2", "10.0.10.12",
			vm("k8s-1", "10.0.10.61", with(), svc{6443, "tcp", "", "0.0.0.0"}, svc{10250, "tcp", "", "0.0.0.0"}),
			vm("k8s-2", "10.0.10.62", with(), svc{10250, "tcp", "", "0.0.0.0"}),
			vm("k8s-3", "10.0.10.63", with(), svc{10250, "tcp", "", "0.0.0.0"}),
			vm("nextcloud", "10.0.10.70", with(pkg{"php8.2", "8.2.7-1", "deb", false}, pkg{"nginx", "1.22.1-9+deb12u1", "deb", false}), svc{443, "tcp", "nginx", "0.0.0.0"}, svc{9000, "tcp", "php8.2", "127.0.0.1"}),
			lxc("backup", "10.0.10.80", with(), svc{8007, "tcp", "", "0.0.0.0"}),
			lxc("homeassistant", "10.0.10.81", with(), svc{8123, "tcp", "", "0.0.0.0"}),
		),
		pve("pve3", "10.0.10.13",
			lxc("unifi", "10.0.10.90", with(), svc{8443, "tcp", "", "0.0.0.0"}),
			lxc("pihole", "10.0.10.91", with(), svc{53, "udp", "", "0.0.0.0"}, svc{80, "tcp", "", "0.0.0.0"}),
		),
		// DMZ.
		{name: "rproxy", kind: "vm", ip: "172.16.0.10", agent: true, pkgs: with(pkg{"nginx", "1.22.1-9", "deb", false}),
			svcs: []svc{sshd(), {80, "tcp", "nginx", "0.0.0.0"}, {443, "tcp", "nginx", "0.0.0.0"}}},
		{name: "mail", kind: "vm", ip: "172.16.0.20", agent: true, pkgs: with(pkg{"exim4", "4.96-15", "deb", false}),
			svcs: []svc{sshd(), {25, "tcp", "exim4", "0.0.0.0"}, {587, "tcp", "exim4", "0.0.0.0"}}},
		{name: "vpn", kind: "network-device", ip: "172.16.0.1", svcs: []svc{{443, "tcp", "", ""}, {51820, "udp", "", ""}}},
	}
	// Clients.
	for i := 1; i <= 9; i++ {
		ver := "10.0.22631.4890"
		if rng.IntN(3) == 0 {
			ver = "10.0.22631.3880"
		}
		hs = append(hs, host{name: fmt.Sprintf("ws-%02d", i), kind: "host", ip: fmt.Sprintf("10.0.20.%d", 100+i), agent: true,
			pkgs: []pkg{{"windows", ver, "windows", false}}, svcs: []svc{{135, "tcp", "", "0.0.0.0"}, {445, "tcp", "", "0.0.0.0"}}})
	}
	for i, n := range []string{"phone-anna", "phone-ben", "tablet", "laptop-guest", "switch-core", "ap-floor1", "ap-floor2"} {
		k := "unknown"
		if i >= 4 {
			k = "network-device"
		}
		hs = append(hs, host{name: n, kind: k, ip: fmt.Sprintf("10.0.20.%d", 200+i)})
	}
	// IoT.
	for i, n := range []string{"cam-door", "cam-garden", "cam-garage", "printer", "tv", "thermostat", "nas"} {
		h := host{name: n, kind: "network-device", ip: fmt.Sprintf("192.168.50.%d", 20+i), svcs: []svc{{80, "tcp", "", ""}}}
		if n == "nas" {
			h.svcs = append(h.svcs, svc{445, "tcp", "", ""}, svc{5000, "tcp", "", ""})
		}
		if strings.HasPrefix(n, "cam") {
			h.svcs = append(h.svcs, svc{554, "tcp", "", ""})
		}
		hs = append(hs, h)
	}
	return hs
}

func entity(h host) proto.Entity {
	m := mac()
	e := proto.Entity{
		Kind: proto.EntityKind(h.kind), Name: h.name, Attributes: h.attrs,
		Identifiers: []proto.Identifier{
			{Kind: "mac", Value: m, Strength: proto.Strong},
			{Kind: "ip", Value: h.ip, Strength: proto.Weak},
			{Kind: "hostname", Value: h.name, Strength: proto.Weak},
		},
		Interfaces: []proto.Interface{{Name: "eth0", MAC: m, IPs: []string{h.ip}}},
	}
	if h.agent {
		e.Identifiers = append(e.Identifiers, proto.Identifier{Kind: inventory.AgentKind, Value: h.name, Strength: proto.Strong})
	}
	purls := map[string]string{}
	for _, p := range h.pkgs {
		purls[p.name] = p.purl()
		e.Components = append(e.Components, proto.Component{PURL: p.purl(), Name: p.name, Version: p.version, Confidence: proto.High})
	}
	for _, s := range h.svcs {
		e.Services = append(e.Services, proto.Service{Port: s.port, Proto: s.proto, Address: s.addr, Process: s.pkg, Component: purls[s.pkg], Confidence: proto.High})
	}
	for _, c := range h.children {
		e.Children = append(e.Children, entity(c))
	}
	return e
}

// findings returns the demo findings of a host: every catalog entry of an
// installed package whose fixed version differs from the installed one.
func findings(h host) []store.Finding {
	var out []store.Finding
	for _, p := range h.pkgs {
		for _, v := range catalog[p.name] {
			if p.patched || p.version == v.fixed {
				continue
			}
			if p.name == "windows" && p.version == "10.0.22631.4890" && v.id == "CVE-2024-38063" {
				continue
			}
			out = append(out, store.Finding{PURL: p.purl(), VulnID: v.id, Fixed: v.fixed, Confidence: "high"})
		}
	}
	return out
}

func walk(hs []host, fn func(host)) {
	for _, h := range hs {
		fn(h)
		walk(h.children, fn)
	}
}

func run() error {
	dir := flag.String("data", "./demo-data", "data directory of nn-server (must not contain a database)")
	flag.Parse()
	db := filepath.Join(*dir, "netnoodle.db")
	if _, err := os.Stat(db); err == nil {
		return fmt.Errorf("%s exists; nn-demo writes only into a new data directory", db)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, registry.Spec{Type: "sqlite"}, *dir)
	if err != nil {
		return err
	}
	defer st.Close()

	now := time.Now()
	hs := network()
	var es []proto.Entity
	for _, h := range hs {
		es = append(es, entity(h))
	}
	obs := proto.Observation{Version: proto.Version, Source: "demo", ObservedAt: now, Entities: es}
	if _, err := inventory.Ingest(ctx, st, obs, nil, now); err != nil {
		return err
	}

	var vs []intel.Vuln
	for _, list := range catalog {
		for _, v := range list {
			vs = append(vs, intel.Vuln{ID: v.id, Summary: v.summary, Score: v.score, KEV: v.kev, EPSS: v.epss, EPSSPct: v.epss,
				Refs: []string{"https://nvd.nist.gov/vuln/detail/" + v.id}})
		}
	}
	if err := st.PutVulns(ctx, vs, now); err != nil {
		return err
	}
	devs, err := st.ListDevices(ctx)
	if err != nil {
		return err
	}
	byName := map[string]int64{}
	for _, d := range devs {
		byName[d.Name] = d.ID
	}
	total := 0
	var ferr error
	walk(hs, func(h host) {
		fs := findings(h)
		if len(fs) == 0 || ferr != nil {
			return
		}
		id := byName[h.name]
		for i := range fs {
			fs[i].DeviceID = id
		}
		total += len(fs)
		_, ferr = st.SyncFindings(ctx, id, "demo", fs, now)
	})
	if ferr != nil {
		return ferr
	}
	fmt.Printf("demo data: %d devices, %d findings in %s\n", len(devs), total, db)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nn-demo:", err)
		os.Exit(1)
	}
}
