package server

import (
	"context"
	"encoding/json"
	"github.com/JulianStremel/netnoodle/internal/updater"
	"github.com/JulianStremel/netnoodle/internal/version"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupUpdate(t *testing.T) (string, *http.Client, string, *Server) {
	t.Helper()
	ts, c, pw, s := newTestServerS(t)
	old := version.Version
	version.Version = "v1.2.3"
	t.Cleanup(func() { version.Version = old })
	s.cfg.Update = DefaultUpdateConfig()
	s.cfg.Update.Enabled = true
	s.cfg.Update.SharedDir = t.TempDir()
	for _, d := range []string{"requests", "status"} {
		if e := os.Mkdir(filepath.Join(s.cfg.Update.SharedDir, d), 0755); e != nil {
			t.Fatal(e)
		}
	}
	a := updater.Available{Version: "v1.3.0", Channel: "stable", Digest: "sha256:abc", CheckedAt: time.Now().UTC(), KeepDays: 7, NotesURL: "https://github.com/test/releases/v1.3.0"}
	if e := updater.WriteJSON(s.cfg.Update.SharedDir, a, "status", "available.json"); e != nil {
		t.Fatal(e)
	}
	login, _ := json.Marshal(map[string]string{"user": "admin", "password": pw})
	if code := post(t, c, ts.URL+"/api/login", "application/json", string(login)).StatusCode; code != 200 {
		t.Fatal(code)
	}
	return ts.URL, c, pw, s
}
func TestUpdateAPIAuthStepUpAndRefusals(t *testing.T) {
	url, c, pw, s := setupUpdate(t)
	plain := *c
	plain.Jar = nil
	if code := get(t, &plain, url+"/api/update"); code != 401 {
		t.Fatal(code)
	}
	if code := post(t, &plain, url+"/api/update", "application/json", `{"when":"now","password":"x"}`).StatusCode; code != 401 {
		t.Fatal(code)
	}
	if code := post(t, c, url+"/api/update", "application/json", `{"when":"now","password":"wrong"}`).StatusCode; code != 403 {
		t.Fatal(code)
	}
	body, _ := json.Marshal(map[string]string{"when": "now", "password": pw})
	for _, mode := range []string{"disabled", "pinned", "older", "pending"} {
		t.Run(mode, func(t *testing.T) {
			s.cfg.Update.Enabled = true
			s.cfg.Update.Channel = "stable"
			version.Version = "v1.2.3"
			switch mode {
			case "disabled":
				s.cfg.Update.Enabled = false
			case "pinned":
				s.cfg.Update.Channel = "pinned"
			case "older":
				version.Version = "v2.0.0"
			case "pending":
				if e := os.WriteFile(filepath.Join(s.cfg.Update.SharedDir, "requests", "pending-request.json"), []byte("{}"), 0644); e != nil {
					t.Fatal(e)
				}
			}
			if code := post(t, c, url+"/api/update", "application/json", string(body)).StatusCode; code != 409 {
				t.Fatal(code)
			}
		})
	}
	s.cfg.Update.Enabled = true
	s.cfg.Update.Channel = "stable"
	version.Version = "v1.2.3"
	_ = os.Remove(filepath.Join(s.cfg.Update.SharedDir, "requests", "pending-request.json"))
	hash, e := HashPassword("operator-pass")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.st.CreateUser(context.Background(), "operator", hash); e != nil {
		t.Fatal(e)
	}
	if code := post(t, c, url+"/api/login", "application/json", `{"user":"operator","password":"operator-pass"}`).StatusCode; code != 200 {
		t.Fatal(code)
	}
	if code := get(t, c, url+"/api/update"); code != 403 {
		t.Fatal(code)
	}
	if code := post(t, c, url+"/api/update", "application/json", string(body)).StatusCode; code != 403 {
		t.Fatal(code)
	}
}
func TestUpdateRequestAtomicAndLimitedToRequests(t *testing.T) {
	url, c, pw, s := setupUpdate(t)
	body, _ := json.Marshal(map[string]string{"when": "now", "password": pw})
	var result updater.Request
	if code := doJSON(t, c, "POST", url+"/api/update", "", string(body), &result); code != 202 {
		t.Fatal(code)
	}
	if e := result.Validate(); e != nil {
		t.Fatal(e)
	}
	if result.RequestedBy != "admin" || result.Version != "v1.3.0" {
		t.Fatal(result)
	}
	var written updater.Request
	if e := updater.ReadJSON(s.cfg.Update.SharedDir, &written, "requests", result.ID+".json"); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(filepath.Join(s.cfg.Update.SharedDir, "requests"))
	if e != nil || len(entries) != 1 || entries[0].Name() != result.ID+".json" {
		t.Fatal(entries, e)
	}
	if e = s.writeUpdateRequest(context.Background(), updater.Request{ID: "../../escape", Channel: "stable"}); e == nil {
		t.Fatal("accepted unsafe path")
	}
	if _, e = os.Stat(filepath.Join(s.cfg.Update.SharedDir, "state")); !os.IsNotExist(e) {
		t.Fatal("server wrote host state")
	}
	entries, _ = os.ReadDir(filepath.Join(s.cfg.Update.SharedDir, "status"))
	if len(entries) != 1 || entries[0].Name() != "available.json" {
		t.Fatal("server wrote status")
	}
	if code := post(t, c, url+"/api/update", "application/json", string(body)).StatusCode; code != 409 {
		t.Fatal(code)
	}
}
func TestUpdateStatusHostileJSONAndHealth(t *testing.T) {
	url, c, _, s := setupUpdate(t)
	for _, content := range []string{`{"version":"v1.3.0","command":"evil"}`, strings.Repeat(" ", updater.MaxJSON+1), `{} {}`, `{"version":"v1.3.0","channel":"stable","checked_at":"2026-11-20T00:00:00Z","keep_days":7,"notes_url":"javascript:alert(1)"}`} {
		if e := os.WriteFile(filepath.Join(s.cfg.Update.SharedDir, "status", "available.json"), []byte(content), 0644); e != nil {
			t.Fatal(e)
		}
		if code := get(t, c, url+"/api/update"); code != 503 {
			t.Fatal(code)
		}
	}
	if e := os.Remove(filepath.Join(s.cfg.Update.SharedDir, "status", "available.json")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(s.cfg.Update.SharedDir, "status", "hostile-status.json"), []byte(`{"id":"hostile-status","state":"done","evil":true}`), 0644); e != nil {
		t.Fatal(e)
	}
	if code := get(t, c, url+"/api/update"); code != 503 {
		t.Fatal(code)
	}
	var health map[string]string
	if code := doJSON(t, c, "GET", url+"/v1/health", "", "", &health); code != 200 || health["version"] != version.Version {
		t.Fatal(code, health)
	}
}
func TestAutoWindowOnceAndEvents(t *testing.T) {
	_, _, _, s := setupUpdate(t)
	ctx := context.Background()
	s.cfg.Update.Auto = true
	now := time.Date(2026, 11, 22, 2, 59, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if e := s.PollUpdates(ctx); e != nil {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(filepath.Join(s.cfg.Update.SharedDir, "requests"))
	if len(entries) != 0 {
		t.Fatal(entries)
	}
	now = now.Add(time.Minute)
	if e := s.PollUpdates(ctx); e != nil {
		t.Fatal(e)
	}
	entries, _ = os.ReadDir(filepath.Join(s.cfg.Update.SharedDir, "requests"))
	if len(entries) != 1 {
		t.Fatal(entries)
	}
	var req updater.Request
	if e := updater.ReadJSON(s.cfg.Update.SharedDir, &req, "requests", entries[0].Name()); e != nil {
		t.Fatal(e)
	}
	if req.RequestedBy != "auto" {
		t.Fatal(req)
	}
	if e := os.Remove(filepath.Join(s.cfg.Update.SharedDir, "requests", entries[0].Name())); e != nil {
		t.Fatal(e)
	}
	st := updater.Status{ID: req.ID, State: "rolled-back", RequestedBy: "auto", Error: "migrated health timeout"}
	if e := updater.WriteJSON(s.cfg.Update.SharedDir, st, "status", req.ID+".json"); e != nil {
		t.Fatal(e)
	}
	if e := s.PollUpdates(ctx); e != nil {
		t.Fatal(e)
	}
	if e := s.PollUpdates(ctx); e != nil {
		t.Fatal(e)
	}
	entries, _ = os.ReadDir(filepath.Join(s.cfg.Update.SharedDir, "requests"))
	if len(entries) != 0 {
		t.Fatal("automatic retry after failure")
	}
	ev, e := s.st.ListEvents(ctx, 200)
	if e != nil {
		t.Fatal(e)
	}
	failed := 0
	for _, event := range ev {
		if event.Type == "update.failed" {
			failed++
			if !strings.Contains(event.Data, `"severity":"critical"`) {
				t.Fatal(event)
			}
		}
	}
	if failed != 1 {
		t.Fatal(ev)
	}
}
func TestScheduleAndWindowValidation(t *testing.T) {
	url, c, pw, s := setupUpdate(t)
	now := time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	body, _ := json.Marshal(map[string]string{"when": "window", "password": pw})
	var req updater.Request
	if code := doJSON(t, c, "POST", url+"/api/update", "", string(body), &req); code != 202 {
		t.Fatal(code)
	}
	if e := s.PollUpdates(context.Background()); e != nil {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(filepath.Join(s.cfg.Update.SharedDir, "requests"))
	if len(entries) != 0 {
		t.Fatal(entries)
	}
	now = now.Add(24 * time.Hour)
	if e := s.PollUpdates(context.Background()); e != nil {
		t.Fatal(e)
	}
	entries, _ = os.ReadDir(filepath.Join(s.cfg.Update.SharedDir, "requests"))
	if len(entries) != 1 || entries[0].Name() != req.ID+".json" {
		t.Fatal(entries)
	}
	for _, window := range []string{"Sun 03:00-05:00", "Mon 00:00-23:59"} {
		cfg := DefaultUpdateConfig()
		cfg.Window = window
		if e := cfg.Validate(); e != nil {
			t.Fatal(e)
		}
	}
	for _, window := range []string{"Sun 05:00-03:00", "Sun 25:00-26:00", "Any 03:00-05:00", "Sun 03:00-03:00", "Sun 03:00-05:60"} {
		cfg := DefaultUpdateConfig()
		cfg.Window = window
		if e := cfg.Validate(); e == nil {
			t.Fatal(window)
		}
	}
	cfg := DefaultUpdateConfig()
	for _, tc := range []struct {
		day, h, m int
		open      bool
	}{{22, 2, 59, false}, {22, 3, 0, true}, {22, 4, 59, true}, {22, 5, 0, false}, {23, 3, 0, false}} {
		if cfg.windowOpen(time.Date(2026, 11, tc.day, tc.h, tc.m, 0, 0, time.UTC)) != tc.open {
			t.Fatal(tc)
		}
	}
}
func TestRollbackAPI(t *testing.T) {
	url, c, pw, s := setupUpdate(t)
	now := s.now()
	target := updater.Status{ID: "successful-update", State: "done", FromVersion: "v1.1.0", ToVersion: version.Version, FinishedAt: now, KeepUntil: now.Add(7 * 24 * time.Hour)}
	if e := updater.WriteJSON(s.cfg.Update.SharedDir, target, "status", target.ID+".json"); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]string{"id": target.ID, "password": "wrong"})
	if code := post(t, c, url+"/api/update/rollback", "application/json", string(body)).StatusCode; code != 403 {
		t.Fatal(code)
	}
	body, _ = json.Marshal(map[string]string{"id": target.ID, "password": pw})
	var req updater.Request
	if code := doJSON(t, c, "POST", url+"/api/update/rollback", "", string(body), &req); code != 202 || req.Kind != "rollback" || req.To != target.ID {
		t.Fatal(code, req)
	}
	if e := os.Remove(filepath.Join(s.cfg.Update.SharedDir, "requests", req.ID+".json")); e != nil {
		t.Fatal(e)
	}
	target.KeepUntil = now.Add(-time.Second)
	if e := updater.WriteJSON(s.cfg.Update.SharedDir, target, "status", target.ID+".json"); e != nil {
		t.Fatal(e)
	}
	if code := post(t, c, url+"/api/update/rollback", "application/json", string(body)).StatusCode; code != 409 {
		t.Fatal(code)
	}
}

func TestAutoPublishFailureRetriesSameIntent(t *testing.T) {
	_, _, _, s := setupUpdate(t)
	s.cfg.Update.Auto = true
	s.now = func() time.Time { return time.Date(2026, 11, 22, 3, 0, 0, 0, time.UTC) }
	ctx := context.Background()
	dir := filepath.Join(s.cfg.Update.SharedDir, "requests")
	if e := os.Remove(dir); e != nil {
		t.Fatal(e)
	}
	if e := s.PollUpdates(ctx); e == nil {
		t.Fatal("expected missing request directory failure")
	}
	value, e := s.st.GetSetting(ctx, "update.scheduled")
	if e != nil || value == "" {
		t.Fatal("lost auto intent", e)
	}
	var r updater.Request
	if e = updater.Decode([]byte(value), &r); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(dir, 0755); e != nil {
		t.Fatal(e)
	}
	if e = s.PollUpdates(ctx); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 || entries[0].Name() != r.ID+".json" {
		t.Fatal(entries, e)
	}
}
