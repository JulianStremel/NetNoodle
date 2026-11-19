package scan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExpand(t *testing.T) {
	a, err := expand([]string{"10.0.0.0/30", "10.0.0.1", "192.168.1.7"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, x := range a {
		got = append(got, x.String())
	}
	if strings.Join(got, ",") != "10.0.0.1,10.0.0.2,192.168.1.7" {
		t.Fatalf("got %v", got)
	}
	if _, err := expand([]string{"10.0.0.0/16"}, 100); err == nil {
		t.Fatal("too large range accepted")
	}
	if _, err := expand([]string{"2001:db8::/64"}, 1<<20); err == nil {
		t.Fatal("huge IPv6 range accepted")
	}
	if a, _ := expand([]string{"10.0.0.8/31"}, 10); len(a) != 2 {
		t.Fatalf("/31 = %v", a)
	}
}

func TestParse(t *testing.T) {
	cases := []struct{ in, p, v string }{
		{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", "openssh", "9.2p1"},
		{"SSH-2.0-dropbear_2022.83", "dropbear", "2022.83"},
		{"220 (vsFTPd 3.0.3)", "vsftpd", "3.0.3"},
		{"nginx/1.22.1", "nginx", "1.22.1"},
		{"Apache/2.4.57 (Debian)", "apache", "2.4.57"},
		{"Microsoft-IIS/10.0", "microsoft-iis", "10.0"},
		{"cloudflare", "cloudflare", ""},
	}
	for _, c := range cases {
		p, v := ParseBanner(c.in)
		if p != c.p || v != c.v {
			t.Errorf("%q: got %q %q, want %q %q", c.in, p, v, c.p, c.v)
		}
	}
}

func TestARPParsers(t *testing.T) {
	proc := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"10.0.0.1         0x1         0x2         00:1a:2b:3c:4d:5e     *        eth0\n" +
		"10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	m, err := parseProcARP(strings.NewReader(proc))
	if err != nil || len(m) != 1 || m["10.0.0.1"] != "00:1a:2b:3c:4d:5e" {
		t.Fatalf("proc: %v %v", m, err)
	}
	win := "Schnittstelle: 10.0.0.20 --- 0xb\n  Internetadresse      Physische Adresse     Typ\n" +
		"  10.0.0.1              00-1a-2b-3c-4d-5e     dynamisch\n  10.0.0.255            ff-ff-ff-ff-ff-ff     statisch\n"
	if m := parseArpA(win); len(m) != 1 || m["10.0.0.1"] != "00:1a:2b:3c:4d:5e" {
		t.Fatalf("windows: %v", m)
	}
	bsd := "? (10.0.0.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]\n"
	if m := parseArpA(bsd); m["10.0.0.1"] != "00:1a:2b:3c:4d:5e" {
		t.Fatalf("bsd: %v", m)
	}
}

func TestScanLocalHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.22.1")
	}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	httpPorts[port] = true
	defer delete(httpPorts, port)

	s, err := New(Config{CIDRs: []string{"127.0.0.1"}, Ports: []int{port}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s.ARP = func() (map[string]string, error) { return map[string]string{"127.0.0.1": "00:1a:2b:3c:4d:5e"}, nil }
	s.DNS = func(context.Context, string) ([]string, error) { return []string{"box.lan."}, nil }
	ents, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("entities = %+v", ents)
	}
	e := ents[0]
	if e.Name != "box.lan" || len(e.Services) != 1 || e.Services[0].Product != "nginx" || e.Services[0].Version != "1.22.1" {
		t.Fatalf("entity = %+v", e)
	}
	if len(e.Identifiers) != 3 {
		t.Fatalf("identifiers = %+v", e.Identifiers)
	}
}

func TestRefusedMeansAlive(t *testing.T) {
	// Find a closed port: listen, take the port, close.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	s, _ := New(Config{CIDRs: []string{"127.0.0.1"}, Ports: []int{port}, NoDNS: true})
	r := s.probe(context.Background(), netip.MustParseAddr("127.0.0.1"), port)
	if r.open || !r.refused {
		t.Fatalf("probe closed port = %+v", r)
	}
}
