package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

const fixture = `{"devices":[
 {"nodeId":"node1","hostname":"vps1","name":"vps1.example.ts.net","addresses":["100.64.0.1","fd7a:115c:a1e0::1"],"os":"linux","clientVersion":"1.76.1-tabcdef","updateAvailable":true,"tags":["tag:router","tag:prod"],"lastSeen":"2026-11-20T09:00:00Z","enabledRoutes":["10.0.10.0/24","fd01::/64","0.0.0.0/0","::/0"],"keyExpiryDisabled":true,"authorized":true,"blocksIncoming":false},
 {"nodeId":"node2","name":"laptop.example.ts.net","addresses":["100.64.0.2"],"os":"windows","clientVersion":"bad-version","tags":["tag:prod"],"enabledRoutes":[],"authorized":false,"blocksIncoming":true}
]}`

func tlsSource(t *testing.T, h http.HandlerFunc, tags []string) (*Source, *httptest.Server) {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	raw, _ := json.Marshal(Settings{URL: ts.URL, Tailnet: "example.com", APIKey: "secret-key", IncludeTags: tags})
	src, err := New("ts", raw)
	if err != nil {
		t.Fatal(err)
	}
	s := src.(*Source)
	// Trust only the fixture certificate, retaining production redirect policy
	// and timeout. There is no insecure TLS setting in the source.
	s.c.Transport = ts.Client().Transport
	return s, ts
}

func TestPollTLS(t *testing.T) {
	s, _ := tlsSource(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v2/tailnet/example.com/devices" || r.URL.RawQuery != "fields=all" || r.Header.Get("Authorization") != "Bearer secret-key" {
			t.Errorf("request = %s %s", r.Method, r.URL)
		}
		fmt.Fprint(w, fixture)
	}, nil)
	if s.c.Timeout != 30*time.Second || s.Name() != "ts" {
		t.Fatal("source defaults")
	}
	calls := 0
	var obs proto.Observation
	if err := s.Poll(context.Background(), func(o proto.Observation) error { calls++; obs = o; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || obs.Version != proto.Version || obs.Source != "ts" || obs.ObservedAt.IsZero() || len(obs.Entities) != 2 {
		t.Fatalf("observation = %+v", obs)
	}
	router, laptop := obs.Entities[0], obs.Entities[1]
	if router.Kind != proto.KindHost || router.Name != "vps1" || laptop.Name != "laptop" {
		t.Fatal(router, laptop)
	}
	if !reflect.DeepEqual(router.Identifiers, []proto.Identifier{
		{Kind: "tailscale.node", Value: "node1", Strength: proto.Strong},
		{Kind: "hostname", Value: "vps1", Strength: proto.Weak},
		{Kind: "ip", Value: "100.64.0.1", Strength: proto.Weak},
		{Kind: "ip", Value: "fd7a:115c:a1e0::1", Strength: proto.Weak},
	}) {
		t.Fatal(router.Identifiers)
	}
	if !reflect.DeepEqual(router.Interfaces, []proto.Interface{{Name: "tailscale0", Kind: "vpn", VPN: "tailscale", IPs: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}}}) {
		t.Fatal(router.Interfaces)
	}
	want := map[string]string{"tailscale.os": "linux", "tailscale.client_version": "1.76.1-tabcdef", "tailscale.update_available": "true", "tailscale.tags": "tag:router,tag:prod", "tailscale.last_seen": "2026-11-20T09:00:00Z", "tailscale.routes": "10.0.10.0/24,fd01::/64", "tailscale.exit_node": "true", "tailscale.key_expiry_disabled": "true", "tailscale.authorized": "true", "tailscale.blocks_incoming": "false"}
	if !reflect.DeepEqual(router.Attributes, want) {
		t.Fatal(router.Attributes)
	}
	if len(router.Components) != 1 || router.Components[0].PURL != "pkg:golang/tailscale.com@v1.76.1" || router.Components[0].Version != "v1.76.1" || len(laptop.Components) != 0 {
		t.Fatal(router.Components, laptop.Components)
	}
}

func TestTagsAndEmitError(t *testing.T) {
	s, _ := tlsSource(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, fixture) }, []string{"tag:router"})
	sentinel := errors.New("emit failed")
	err := s.Poll(context.Background(), func(o proto.Observation) error {
		if len(o.Entities) != 1 || o.Entities[0].Name != "vps1" {
			t.Fatal(o)
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	s.s.IncludeTags = []string{"tag:missing"}
	if err := s.Poll(context.Background(), func(o proto.Observation) error {
		if len(o.Entities) != 0 {
			t.Fatal(o)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSettings(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"api_key":"secret-key","api_key_file":"x"}`, `{"api_key_file":"missing-file"}`,
		`{"api_key":"secret-key","url":"http://localhost"}`, `{"api_key":"secret-key","url":"https://secret-key@host"}`,
		`{"api_key":"secret-key","url":"https://host/?secret-key"}`, `{"api_key":"secret-key","url":"https://host/#secret-key"}`,
		`{"api_key":"secret-key","tailnet":"../secret-key"}`, `{"api_key":"secret-key","include_tags":[""]}`,
		`{"api_key":"secret-key","insecure_skip_verify":true}`, `{"api_key":"secret-key","secret-key":true}`,
		`{"api_key":"secret-key\r\n"}`, `{"api_key":" "}`,
		`{"api_key":"secret-key"} {}`, `{"api_key":"secret-key","tailnet":".."}`,
		`{"api_key":"secret-key","url":"https://"}`, `{"api_key":"secret-key","include_tags":[` + fmt.Sprintf("%q", strings.Repeat("t", 257)) + `]}`,
	} {
		_, err := New("ts", json.RawMessage(raw))
		if err == nil || strings.Contains(err.Error(), "secret-key") {
			t.Errorf("settings error = %v for %s", err, raw)
		}
	}
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte("secret-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"api_key_file": file})
	src, err := New("ts", raw)
	if err != nil {
		t.Fatal(err)
	}
	s := src.(*Source)
	if s.s.Tailnet != "-" || s.s.URL != "https://api.tailscale.com" || s.s.APIKey != "secret-key" {
		t.Fatal("bad defaults or file key")
	}
}

func TestRedactionRedirectsAndCaps(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"HTTP error", "secret-key", 403}, {"bad JSON", `{"devices": "secret-key"}`, 200},
		{"redirect", "secret-key", 302}, {"oversized", strings.Repeat(" ", maxBody+1), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redirected := false
			s, _ := tlsSource(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirected" {
					redirected = true
					fmt.Fprint(w, fixture)
					return
				}
				w.Header().Set("Location", "/redirected?secret-key")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}, nil)
			err := s.Poll(context.Background(), func(proto.Observation) error { t.Fatal("emitted failed poll"); return nil })
			if err == nil || strings.Contains(err.Error(), "secret-key") || redirected {
				t.Fatalf("error=%v redirected=%v", err, redirected)
			}
		})
	}
	s, ts := tlsSource(t, func(w http.ResponseWriter, r *http.Request) {}, nil)
	ts.Close()
	if err := s.Poll(context.Background(), func(proto.Observation) error { return nil }); err == nil || strings.Contains(err.Error(), "secret-key") {
		t.Fatal(err)
	}
	for _, n := range []int{maxDevices, maxDevices + 1} {
		t.Run(fmt.Sprint("devices", n), func(t *testing.T) {
			devs := make([]device, n)
			for i := range devs {
				devs[i].NodeID = fmt.Sprint(i)
			}
			s, _ := tlsSource(t, func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"devices": devs})
			}, nil)
			err := s.Poll(context.Background(), func(o proto.Observation) error {
				if len(o.Entities) != n {
					t.Fatal(len(o.Entities))
				}
				return nil
			})
			if (err != nil) != (n > maxDevices) {
				t.Fatal(err)
			}
		})
	}
}

func TestEntityCapsAndVersions(t *testing.T) {
	s := &Source{}
	d := device{NodeID: "n", Hostname: strings.Repeat("a", 300), OS: strings.Repeat("a", 300), Tags: []string{strings.Repeat("a", 300)}}
	e, err := s.entity(d)
	if err != nil || len(e.Name) != 256 || len(e.Attributes["tailscale.os"]) != 256 || len(e.Attributes["tailscale.tags"]) != 256 {
		t.Fatal(e, err)
	}
	for _, n := range []int{64, 65} {
		d.EnabledRoutes = make([]string, n)
		for i := range d.EnabledRoutes {
			d.EnabledRoutes[i] = "10.0.0.0/24"
		}
		_, err := s.entity(d)
		if (err != nil) != (n > 64) {
			t.Fatalf("%d routes: %v", n, err)
		}
	}
	for _, routes := range [][]string{{"secret-key"}, {strings.Repeat("x", maxFieldBytes+1)}} {
		d.EnabledRoutes = routes
		if _, err := s.entity(d); err == nil || strings.Contains(err.Error(), "secret-key") {
			t.Fatalf("invalid route error = %v", err)
		}
	}
	d.EnabledRoutes = nil
	for i := range 64 {
		d.EnabledRoutes = append(d.EnabledRoutes, fmt.Sprintf("10.%d.0.0/16", i))
	}
	if _, err := s.entity(d); err == nil {
		t.Fatal("accepted route field longer than 256 bytes")
	}
	for _, tc := range []struct{ in, want string }{{"1.76.1-t123", "v1.76.1"}, {"1.76.1", "v1.76.1"}, {"1.76", ""}, {"01.76.1", ""}, {"v1.76.1", ""}, {"1.2.3oops", ""}} {
		if got := clientVersion(tc.in); got != tc.want {
			t.Errorf("%s = %s", tc.in, got)
		}
	}
}
