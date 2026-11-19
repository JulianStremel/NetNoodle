// Package scan is a non-intrusive subnet scanner. It finds hosts with TCP
// connections (an open or a refused port means "host is up"), reads short
// banners, HTTP Server headers and TLS certificates, and takes MAC
// addresses from the local ARP table. It does not need raw sockets or root.
package scan

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netnoodle/internal/proto"
)

// DefaultPorts is a small list of common service ports.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 993, 1883,
	3306, 3389, 5000, 5432, 5900, 6379, 8000, 8006, 8080, 8123, 8443, 8888, 9000, 9100, 9443,
}

var tlsPorts = map[int]bool{443: true, 636: true, 993: true, 995: true, 5986: true, 8006: true, 8443: true, 9443: true}
var httpPorts = map[int]bool{80: true, 5000: true, 8000: true, 8080: true, 8123: true, 8888: true, 9000: true}

// Config controls a scan.
type Config struct {
	CIDRs       []string      `json:"cidrs"`
	Ports       []int         `json:"ports,omitempty"`
	Timeout     time.Duration `json:"-"`
	Concurrency int           `json:"concurrency,omitempty"`
	MaxHosts    int           `json:"max_hosts,omitempty"`
	NoDNS       bool          `json:"no_dns,omitempty"`
	NoBanners   bool          `json:"no_banners,omitempty"`
}

// Scanner runs scans. Dial and ARP can be replaced in tests.
type Scanner struct {
	cfg   Config
	addrs []netip.Addr
	Dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	ARP   func() (map[string]string, error) // ip -> mac
	DNS   func(ctx context.Context, ip string) ([]string, error)
}

// New validates the config and expands the address ranges.
func New(cfg Config) (*Scanner, error) {
	if len(cfg.Ports) == 0 {
		cfg.Ports = DefaultPorts
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 800 * time.Millisecond
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 128
	}
	if cfg.MaxHosts <= 0 {
		cfg.MaxHosts = 4096
	}
	for _, p := range cfg.Ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("bad port %d", p)
		}
	}
	addrs, err := expand(cfg.CIDRs, cfg.MaxHosts)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{}
	return &Scanner{
		cfg:   cfg,
		addrs: addrs,
		Dial:  d.DialContext,
		ARP:   readARP,
		DNS:   net.DefaultResolver.LookupAddr,
	}, nil
}

// Hosts returns the number of addresses to scan.
func (s *Scanner) Hosts() int { return len(s.addrs) }

// expand turns CIDRs and single addresses into a host list. For IPv4
// prefixes the network and broadcast addresses are skipped.
func expand(cidrs []string, max int) ([]netip.Addr, error) {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		var p netip.Prefix
		if strings.Contains(c, "/") {
			var err error
			p, err = netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("bad range %q: %w", c, err)
			}
			p = p.Masked()
		} else {
			a, err := netip.ParseAddr(c)
			if err != nil {
				return nil, fmt.Errorf("bad address %q: %w", c, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is6() && p.Bits() < 112 {
			return nil, fmt.Errorf("range %q is too large (IPv6 needs /112 or smaller)", c)
		}
		first, last := p.Addr(), lastAddr(p)
		skipEnds := p.Addr().Is4() && p.Bits() <= 30
		for a := first; ; a = a.Next() {
			if !(skipEnds && (a == first || a == last)) && !seen[a] {
				if len(out) >= max {
					return nil, fmt.Errorf("more than %d addresses; reduce the ranges or raise max_hosts", max)
				}
				seen[a] = true
				out = append(out, a)
			}
			if a == last || !a.IsValid() {
				break
			}
		}
	}
	return out, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 1 << (7 - j)
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

type portResult struct {
	open    bool
	refused bool
	svc     proto.Service
}

// Scan scans all addresses and returns one entity per live host.
func (s *Scanner) Scan(ctx context.Context) ([]proto.Entity, error) {
	type hostRes struct {
		addr netip.Addr
		svcs []proto.Service
	}
	jobs := make(chan netip.Addr)
	results := make(chan hostRes)
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				alive := false
				var svcs []proto.Service
				for _, port := range s.cfg.Ports {
					if ctx.Err() != nil {
						return
					}
					r := s.probe(ctx, a, port)
					if r.open {
						svcs = append(svcs, r.svc)
					}
					alive = alive || r.open || r.refused
				}
				if alive {
					results <- hostRes{a, svcs}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, a := range s.addrs {
			select {
			case jobs <- a:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	var live []hostRes
	for r := range results {
		live = append(live, r)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(live, func(i, j int) bool { return live[i].addr.Less(live[j].addr) })

	arp := map[string]string{}
	if s.ARP != nil {
		if m, err := s.ARP(); err == nil {
			arp = m
		}
	}

	ents := make([]proto.Entity, 0, len(live))
	for _, h := range live {
		ip := h.addr.String()
		e := proto.Entity{
			Kind:        proto.KindUnknown,
			Identifiers: []proto.Identifier{{Kind: "ip", Value: ip, Strength: proto.Weak}},
			Services:    h.svcs,
		}
		if mac := arp[ip]; mac != "" {
			e.Identifiers = append(e.Identifiers, proto.Identifier{Kind: "mac", Value: mac, Strength: proto.Strong})
			e.Interfaces = []proto.Interface{{MAC: mac, IPs: []string{ip}}}
		}
		if !s.cfg.NoDNS && s.DNS != nil {
			dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			names, _ := s.DNS(dctx, ip)
			cancel()
			if len(names) > 0 {
				n := strings.TrimSuffix(names[0], ".")
				e.Name = n
				e.Identifiers = append(e.Identifiers, proto.Identifier{Kind: "hostname", Value: n, Strength: proto.Weak})
			}
		}
		ents = append(ents, e)
	}
	return ents, nil
}

func (s *Scanner) probe(ctx context.Context, a netip.Addr, port int) portResult {
	addr := net.JoinHostPort(a.String(), strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	conn, err := s.Dial(dctx, "tcp", addr)
	cancel()
	if err != nil {
		return portResult{refused: isRefused(err)}
	}
	defer conn.Close()
	svc := proto.Service{Port: port, Proto: "tcp", Address: a.String(), Confidence: proto.Low}
	if !s.cfg.NoBanners {
		grab(conn, a, port, &svc)
	}
	return portResult{open: true, svc: svc}
}

// grab reads what a service shows without sending more than a HEAD
// request or a TLS handshake.
func grab(conn net.Conn, a netip.Addr, port int, svc *proto.Service) {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	switch {
	case tlsPorts[port]:
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: a.String()}) // read-only fingerprinting
		if err := tc.Handshake(); err != nil {
			return
		}
		cs := tc.ConnectionState()
		if len(cs.PeerCertificates) > 0 {
			c := cs.PeerCertificates[0]
			svc.Banner = fmt.Sprintf("tls subject=%q issuer=%q not_after=%s", c.Subject.CommonName, c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"))
		}
		if server := httpHead(tc, a, port); server != "" {
			svc.Banner = strings.TrimSpace("server=" + server + " " + svc.Banner)
			svc.Product, svc.Version = ParseProductVersion(server)
		}
	case httpPorts[port]:
		if server := httpHead(conn, a, port); server != "" {
			svc.Banner = "server=" + server
			svc.Product, svc.Version = ParseProductVersion(server)
		}
	default:
		buf := make([]byte, 256)
		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, _ := io.ReadAtLeast(conn, buf, 1)
		if n > 0 {
			line := strings.SplitN(string(buf[:n]), "\n", 2)[0]
			svc.Banner = strings.TrimSpace(line)
			svc.Product, svc.Version = ParseBanner(svc.Banner)
		}
	}
}

func httpHead(c net.Conn, a netip.Addr, port int) string {
	host := a.String()
	if a.Is6() {
		host = "[" + host + "]"
	}
	if _, err := fmt.Fprintf(c, "HEAD / HTTP/1.0\r\nHost: %s:%d\r\nUser-Agent: nn-scan\r\n\r\n", host, port); err != nil {
		return ""
	}
	r := bufio.NewReader(io.LimitReader(c, 8192))
	status, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/") {
		return ""
	}
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || err != nil {
			return ""
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(k, "server") {
			return strings.TrimSpace(v)
		}
	}
}

var (
	sshRE     = regexp.MustCompile(`^SSH-[\d.]+-([A-Za-z]+)[_-]([\w.]+)`)
	genericRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9-]*)[/ _]v?(\d+(?:\.\d+)+[a-z0-9]*)`)
)

// ParseBanner extracts a product and version from a line banner.
func ParseBanner(b string) (product, version string) {
	if m := sshRE.FindStringSubmatch(b); m != nil {
		return strings.ToLower(m[1]), m[2]
	}
	return ParseProductVersion(b)
}

// ParseProductVersion reads "nginx/1.22.1" or "Apache/2.4.57 (Debian)".
func ParseProductVersion(s string) (product, version string) {
	if m := genericRE.FindStringSubmatch(s); m != nil {
		return strings.ToLower(m[1]), m[2]
	}
	if f := strings.Fields(s); len(f) > 0 {
		return strings.ToLower(strings.SplitN(f[0], "/", 2)[0]), ""
	}
	return "", ""
}

var errNoARP = errors.New("no ARP table on this platform")
