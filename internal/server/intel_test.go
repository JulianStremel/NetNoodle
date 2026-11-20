package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
	"github.com/JulianStremel/netnoodle/internal/store/sqlite"
)

// fakeMatcher reports vulns for packages by name.
type fakeMatcher struct {
	vulns map[string][]intel.Vuln // package name -> vulns
	fail  bool
}

func (m *fakeMatcher) Name() string { return "fake" }
func (m *fakeMatcher) Match(_ context.Context, comps []proto.Component) ([]intel.Hit, error) {
	if m.fail {
		return nil, errors.New("feed down")
	}
	var hits []intel.Hit
	for _, c := range comps {
		for _, v := range m.vulns[c.Name] {
			hits = append(hits, intel.Hit{Component: c, Vuln: v, Fixed: "9.9", Confidence: proto.High})
		}
	}
	return hits, nil
}

type fakeKEV struct{}

func (fakeKEV) Name() string                    { return "kev" }
func (fakeKEV) Refresh(_ context.Context) error { return nil }
func (fakeKEV) Enrich(v *intel.Vuln) {
	for _, c := range v.CVEs() {
		if c == "CVE-2024-6387" {
			v.KEV = true
		}
	}
}

func TestMatchFlow(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pw, _ := EnsureAdmin(ctx, st)
	s := New(DefaultConfig(), st, fstest.MapFS{"index.html": {Data: []byte("x")}}, "fp", slog.New(slog.NewTextHandler(io.Discard, nil)))
	fm := &fakeMatcher{vulns: map[string][]intel.Vuln{
		"openssh-server": {{ID: "DEBIAN-CVE-2024-6387", Aliases: []string{"CVE-2024-6387"}, Score: 8.1, Summary: "regreSSHion"}},
		"bash":           {{ID: "DEBIAN-CVE-2022-0001", Score: 3.3}},
	}}
	s.SetIntel([]intel.Matcher{fm}, []intel.Enricher{fakeKEV{}})

	obs := proto.Observation{Version: "v1", Source: "web1", ObservedAt: time.Now(), Complete: true, Entities: []proto.Entity{{
		Kind: proto.KindHost, Name: "web1",
		Identifiers: []proto.Identifier{{Kind: "agent", Value: "web1", Strength: proto.Strong}},
		Components: []proto.Component{
			{PURL: "pkg:deb/debian/openssh-server@9.2p1-2", Name: "openssh-server", Version: "9.2p1-2"},
			{PURL: "pkg:deb/debian/bash@5.2", Name: "bash", Version: "5.2"},
		},
		Services: []proto.Service{
			{Port: 22, Proto: "tcp", Address: "0.0.0.0", Component: "pkg:deb/debian/openssh-server@9.2p1-2"},
		},
	}}}
	raw, _ := json.Marshal(obs)
	if err := inventory.PrepareAgent(&obs, "web1"); err != nil {
		t.Fatal(err)
	}
	res, err := s.ingestAs(ctx, obs, raw, "web1")
	if err != nil {
		t.Fatal(err)
	}
	dev := res.Devices[0]
	if len(s.intel.queue) != 1 {
		t.Fatalf("ingest queued %d matches, want 1", len(s.intel.queue))
	}
	if err := s.MatchDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}

	rows, err := st.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("findings = %+v", rows)
	}
	top := rows[0]
	if top.VulnID != "DEBIAN-CVE-2024-6387" || !top.KEV || len(top.Exposed) != 1 || top.Exposed[0] != "22/tcp" ||
		top.Package != "openssh-server" || top.Fixed != "9.9" || top.DeviceName != "web1" {
		t.Fatalf("top finding = %+v", top)
	}
	stats, _ := st.FindingStats(ctx)
	if stats.Open != 2 || stats.High != 1 || stats.Low != 1 || stats.KEV != 1 || stats.Exposed != 1 || stats.Devices != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	devs, _ := st.ListDevices(ctx)
	if devs[0].Findings != 2 || devs[0].MaxScore != 8.1 || devs[0].KEV != 1 {
		t.Fatalf("device row = %+v", devs[0])
	}

	// A failing matcher leaves the findings alone.
	fm.fail = true
	if err := s.MatchDevice(ctx, dev); err == nil {
		t.Fatal("want error")
	}
	if rows, _ := st.ListFindings(ctx, store.FindingFilter{}); len(rows) != 2 {
		t.Fatalf("findings after failed match = %d", len(rows))
	}

	// bash is fixed: its finding is resolved, the other stays open.
	fm.fail = false
	delete(fm.vulns, "bash")
	if err := s.MatchDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	open, _ := st.ListFindings(ctx, store.FindingFilter{})
	resolved, _ := st.ListFindings(ctx, store.FindingFilter{State: "resolved"})
	if len(open) != 1 || len(resolved) != 1 || resolved[0].ResolvedAt.IsZero() {
		t.Fatalf("open = %d, resolved = %+v", len(open), resolved)
	}

	// One summary event for the first match only.
	evs, _ := st.ListEvents(ctx, 50)
	n := 0
	for _, e := range evs {
		if e.Type == "finding.new" {
			n++
			if e.Summary != "2 new vulnerabilities on web1" {
				t.Errorf("event summary = %q", e.Summary)
			}
		}
	}
	if n != 1 {
		t.Fatalf("finding.new events = %d", n)
	}

	// API: login, list findings with filters, overview.
	ts := httptest.NewTLSServer(s.Handler())
	defer ts.Close()
	c := ts.Client()
	c.Jar, _ = cookiejar.New(nil)
	post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"`+pw+`"}`)
	var list []store.FindingRow
	if code := doJSON(t, c, "GET", ts.URL+"/api/findings?kev=1&min_score=7", "", "", &list); code != 200 || len(list) != 1 {
		t.Fatalf("api findings = %d %+v", code, list)
	}
	if code := doJSON(t, c, "GET", ts.URL+"/api/findings?state=bogus", "", "", nil); code != 400 {
		t.Fatalf("bad state = %d", code)
	}
	var ov struct {
		Devices  int
		Findings store.FindingStats
		Intel    IntelStatus
	}
	if code := doJSON(t, c, "GET", ts.URL+"/api/overview", "", "", &ov); code != 200 || ov.Devices != 1 || ov.Findings.Open != 1 || len(ov.Intel.Matchers) != 1 {
		t.Fatalf("overview = %d %+v", code, ov)
	}
	anon := &http.Client{Transport: ts.Client().Transport}
	if code := get(t, anon, ts.URL+"/api/findings"); code != 401 {
		t.Fatalf("findings without login = %d", code)
	}
}
