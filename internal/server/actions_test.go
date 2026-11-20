package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	_ "github.com/JulianStremel/netnoodle/internal/decide/guards"
	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func installDecide(t *testing.T, s *Server, specs []registry.Spec) {
	t.Helper()
	ds, e := registry.BuildAll(decide.Deciders, specs)
	if e != nil {
		t.Fatal(e)
	}
	gs, e := registry.BuildAll(decide.Guards, DefaultGuards)
	if e != nil {
		t.Fatal(e)
	}
	s.SetDecide(ds, gs)
}
func TestActionsEndToEnd(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	ctx := context.Background()
	installDecide(t, s, DefaultDeciders)
	fm := &fakeMatcher{vulns: map[string][]intel.Vuln{"openssh": {{ID: "CVE-2026-1234", Score: 9.8, KEV: true}}}}
	s.SetIntel([]intel.Matcher{fm}, nil)
	if code := doJSON(t, c, "POST", ts.URL+"/api/login", "", `{"user":"admin","password":"`+pw+`"}`, nil); code != 200 {
		t.Fatal(code)
	}
	anon := &http.Client{Transport: ts.Client().Transport}
	token := enrollPeer(t, c, anon, ts.URL, "agent", "m5-host")
	report := `{"version":"v1","source":"x","observed_at":"2026-11-20T10:00:00Z","complete":true,"entities":[{"kind":"host","name":"m5-host","identifiers":[{"kind":"ip","value":"10.1.2.3","strength":"weak"}],"components":[{"purl":"pkg:generic/openssh@1","name":"openssh","version":"1","confidence":"high"}],"services":[{"port":22,"proto":"tcp","address":"0.0.0.0","component":"pkg:generic/openssh@1"}]}]}`
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", token, report, nil); code != 200 {
		t.Fatal(code)
	}
	devs := devices(t, c, ts.URL)
	if len(devs) != 1 {
		t.Fatal(devs)
	}
	id := devs[0].ID
	if e := s.MatchDevice(ctx, id); e != nil {
		t.Fatal(e)
	}
	list := func(state string) []store.Proposal {
		t.Helper()
		var ps []store.Proposal
		if code := doJSON(t, c, "GET", ts.URL+"/api/proposals?state="+state, "", "", &ps); code != 200 {
			t.Fatal(code)
		}
		return ps
	}
	ps := list("pending")
	if len(ps) != 1 || ps[0].Action != "isolate" || ps[0].TTL != 86400 {
		t.Fatalf("pending %+v", ps)
	}
	proposalID := ps[0].ID
	if code := doJSON(t, c, "POST", fmt.Sprintf("%s/api/proposals/%d/approve", ts.URL, proposalID), "", `{}`, nil); code != 200 {
		t.Fatal(code)
	}
	ps = list("approved")
	if len(ps) != 1 || ps[0].DecidedUser != "admin" || ps[0].DecidedAt.IsZero() {
		t.Fatal(ps)
	}
	if code := doJSON(t, c, "POST", fmt.Sprintf("%s/api/proposals/%d/reject", ts.URL, proposalID), "", `{}`, nil); code != 409 {
		t.Fatal("second decision", code)
	}
	auto := []registry.Spec{{Type: "rules", Name: "custom", Settings: json.RawMessage(`{"rules":[{"name":"auto-kev","when":{"kev":true},"then":{"tier":"auto","action":"snapshot","ttl":"1h"}}]}`)}}
	installDecide(t, s, auto)
	tags := func(raw string) {
		t.Helper()
		if code := doJSON(t, c, "PUT", fmt.Sprintf("%s/api/devices/%d/tags", ts.URL, id), "", raw, nil); code != 200 {
			t.Fatal(code)
		}
	}
	tags(`{"tags":["auto"]}`)
	if code := doJSON(t, c, "PUT", ts.URL+"/api/decide/settings", "", `{"killswitch":true}`, nil); code != 200 {
		t.Fatal(code)
	}
	// Exercise the background endpoint and wait for its observed completion.
	if code := doJSON(t, c, "POST", ts.URL+"/api/proposals/reevaluate", "", `{}`, nil); code != 202 {
		t.Fatal(code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.decide.mu.Lock()
		busy := s.decide.reevaluating
		s.decide.mu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reevaluation did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ps = list("pending")
	if len(ps) != 1 || ps[0].Action != "snapshot" {
		t.Fatalf("kill switch %+v", ps)
	}
	if code := doJSON(t, c, "PUT", ts.URL+"/api/decide/settings", "", `{"killswitch":false}`, nil); code != 200 {
		t.Fatal(code)
	}
	if e := s.reevaluate(ctx); e != nil {
		t.Fatal(e)
	}
	ps = list("auto")
	if len(ps) != 1 || ps[0].Action != "snapshot" {
		t.Fatalf("auto %+v", ps)
	}
	tags(`{"tags":["auto","protected"]}`)
	if e := s.reevaluate(ctx); e != nil {
		t.Fatal(e)
	}
	if len(list("auto")) != 0 {
		t.Fatal("protected device has auto proposal")
	}
	ps = list("pending")
	if len(ps) != 1 {
		t.Fatal(ps)
	}
	// Device rows, details, graph and settings all expose the operator context.
	var rows []store.DeviceRow
	doJSON(t, c, "GET", ts.URL+"/api/devices", "", "", &rows)
	if len(rows[0].Tags) != 2 {
		t.Fatal(rows)
	}
	var detail store.DeviceDetail
	doJSON(t, c, "GET", fmt.Sprintf("%s/api/devices/%d", ts.URL, id), "", "", &detail)
	if len(detail.Tags) != 2 {
		t.Fatal(detail)
	}
	var graph Graph
	doJSON(t, c, "GET", ts.URL+"/api/graph", "", "", &graph)
	if len(graph.Nodes[0].Tags) != 2 {
		t.Fatal(graph)
	}
	var settings struct {
		Killswitch    bool
		Rules, Guards []string
	}
	doJSON(t, c, "GET", ts.URL+"/api/decide/settings", "", "", &settings)
	if settings.Killswitch || len(settings.Rules) != 1 || settings.Rules[0] != "auto-kev" || len(settings.Guards) != 4 {
		t.Fatal(settings)
	}
	// A matcher failure must preserve open proposals, then a fixed finding closes them.
	fm.fail = true
	if e := s.MatchDevice(ctx, id); e == nil {
		t.Fatal("matcher error missing")
	}
	if len(list("pending")) != 1 {
		t.Fatal("failed matcher resolved proposal")
	}
	fm.fail = false
	fm.vulns = nil
	if e := s.MatchDevice(ctx, id); e != nil {
		t.Fatal(e)
	}
	if len(list("pending")) != 0 || len(list("approved")) != 0 || len(list("resolved")) != 2 {
		t.Fatalf("resolution %+v", list("all"))
	}
	events, e := s.st.ListEvents(ctx, 100)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, ev := range events {
		found = found || ev.Type == "proposal.pending"
	}
	if !found {
		t.Fatal("missing pending event")
	}
}
func TestActionsAuthAndValidation(t *testing.T) {
	ts, c, pw, _ := newTestServerS(t)
	for _, tc := range []struct{ method, path, body string }{{"GET", "/api/proposals", ""}, {"POST", "/api/proposals/reevaluate", "{}"}, {"POST", "/api/proposals/1/approve", "{}"}, {"POST", "/api/proposals/1/reject", "{}"}, {"GET", "/api/decide/settings", ""}, {"PUT", "/api/decide/settings", `{"killswitch":true}`}, {"PUT", "/api/devices/1/tags", `{"tags":[]}`}} {
		if code := doJSON(t, c, tc.method, ts.URL+tc.path, "", tc.body, nil); code != 401 {
			t.Fatalf("%s: %d", tc.path, code)
		}
	}
	doJSON(t, c, "POST", ts.URL+"/api/login", "", `{"user":"admin","password":"`+pw+`"}`, nil)
	for _, path := range []string{"/api/proposals?state=bogus", "/api/proposals?device=bad", "/api/proposals?limit=0", "/api/proposals?limit=20001"} {
		if code := doJSON(t, c, "GET", ts.URL+path, "", "", nil); code != 400 {
			t.Fatal(path, code)
		}
	}
	for _, body := range []string{`{}`, `{"killswitch":"on"}`, `{"killswitch":true,"extra":1}`} {
		if code := doJSON(t, c, "PUT", ts.URL+"/api/decide/settings", "", body, nil); code != 400 {
			t.Fatal(body, code)
		}
	}
	if code := doJSON(t, c, "PUT", ts.URL+"/api/devices/1/tags", "", `{"tags":["Protected"]}`, nil); code != 400 {
		t.Fatal(code)
	}
	if code := doJSON(t, c, "PUT", ts.URL+"/api/devices/1/tags", "", `{"tags":[]}`, nil); code != 404 {
		t.Fatal(code)
	}
	if res := post(t, c, ts.URL+"/api/proposals/1/approve", "text/plain", `{}`); res.StatusCode != 415 {
		t.Fatal(res.StatusCode)
	}
}
func TestDecideConfigDefaults(t *testing.T) {
	cfg, e := LoadConfig("")
	if e != nil || len(cfg.Deciders) != 1 || len(cfg.Guards) != 4 {
		t.Fatal(cfg, e)
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if e = os.WriteFile(p, []byte(`{"deciders":[],"guards":[]}`), 0600); e != nil {
		t.Fatal(e)
	}
	cfg, e = LoadConfig(p)
	if e != nil || len(cfg.Deciders) != 0 || len(cfg.Guards) != 0 {
		t.Fatal(cfg, e)
	}
	if _, e = registry.BuildAll(decide.Deciders, DefaultDeciders); e != nil {
		t.Fatal(e)
	}
	if _, e = registry.BuildAll(decide.Guards, DefaultGuards); e != nil {
		t.Fatal(e)
	}
}
