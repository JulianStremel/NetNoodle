package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/store"
	"github.com/JulianStremel/netnoodle/internal/updater"
	"github.com/JulianStremel/netnoodle/internal/version"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type UpdateConfig struct {
	Enabled   bool   `json:"enabled"`
	SharedDir string `json:"shared_dir,omitempty"`
	Channel   string `json:"channel"`
	Auto      bool   `json:"auto"`
	Window    string `json:"window"`
}

func DefaultUpdateConfig() UpdateConfig {
	return UpdateConfig{SharedDir: "/var/lib/netnoodle/updater", Channel: "stable", Window: "Sun 03:00-05:00"}
}

var updateWindow = regexp.MustCompile(`^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) ([0-1][0-9]|2[0-3]):([0-5][0-9])-([0-1][0-9]|2[0-3]):([0-5][0-9])$`)

func (c UpdateConfig) Validate() error {
	if c.Channel != "stable" && c.Channel != "latest" && c.Channel != "pinned" {
		return fmt.Errorf("invalid channel")
	}
	if !filepath.IsAbs(c.SharedDir) && !strings.HasPrefix(c.SharedDir, "/") {
		return fmt.Errorf("shared_dir must be absolute")
	}
	m := updateWindow.FindStringSubmatch(c.Window)
	if m == nil || m[2]+m[3] >= m[4]+m[5] {
		return fmt.Errorf("window must be like Sun 03:00-05:00, with end after start")
	}
	return nil
}
func (c UpdateConfig) windowOpen(now time.Time) bool {
	m := updateWindow.FindStringSubmatch(c.Window)
	if m == nil || now.Weekday().String()[:3] != m[1] {
		return false
	}
	h, _ := strconv.Atoi(m[2])
	min, _ := strconv.Atoi(m[3])
	endH, _ := strconv.Atoi(m[4])
	endM, _ := strconv.Atoi(m[5])
	n := now.Hour()*60 + now.Minute()
	return n >= h*60+min && n < endH*60+endM
}

type updateView struct {
	Current string `json:"current_version"`
	UpdateConfig
	Available   *updater.Available `json:"available"`
	Newer       bool               `json:"newer"`
	Downgrade   bool               `json:"downgrade_warning"`
	Pending     bool               `json:"pending"`
	HostPending bool               `json:"-"`
	Scheduled   *updater.Request   `json:"scheduled,omitempty"`
	Statuses    []updater.Status   `json:"statuses"`
}

func (s *Server) updateSnapshot(ctx context.Context) (updateView, error) {
	v := updateView{Current: version.Version, UpdateConfig: s.cfg.Update, Statuses: []updater.Status{}}
	// The API never exposes the host's directory configuration.
	v.SharedDir = ""
	var a updater.Available
	e := updater.ReadJSON(s.cfg.Update.SharedDir, &a, "status", "available.json")
	if e == nil {
		if _, ok := updater.Compare(a.Version, a.Version); !ok || a.Channel != "stable" && a.Channel != "latest" || a.CheckedAt.IsZero() || a.KeepDays < 1 || a.KeepDays > 365 {
			return v, fmt.Errorf("invalid available status")
		}
		if a.NotesURL != "" {
			u, e := url.Parse(a.NotesURL)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
				return v, fmt.Errorf("unsafe release notes URL")
			}
		}
		v.Available = &a
		v.Newer = a.Channel == s.cfg.Update.Channel && updater.Newer(a.Version, version.Version)
		cmp, known := updater.Compare(a.Version, version.Version)
		v.Downgrade = a.Channel == s.cfg.Update.Channel && known && cmp < 0
	} else if !os.IsNotExist(e) {
		return v, e
	}
	dir, e := updater.SafePath(s.cfg.Update.SharedDir, "status")
	if e != nil {
		return v, e
	}
	entries, e := os.ReadDir(dir)
	if e != nil && !os.IsNotExist(e) {
		return v, e
	}
	for _, f := range entries {
		if f.Name() == "available.json" {
			continue
		}
		id := strings.TrimSuffix(f.Name(), ".json")
		if !strings.HasSuffix(f.Name(), ".json") || !updater.ValidID(id) {
			continue
		}
		var st updater.Status
		if e := updater.ReadJSON(s.cfg.Update.SharedDir, &st, "status", f.Name()); e != nil {
			return v, e
		}
		if st.ID != id || len(st.Steps) > 512 {
			return v, fmt.Errorf("invalid update status")
		}
		v.Statuses = append(v.Statuses, st)
		if !updater.Terminal(st.State) {
			v.Pending = true
		}
	}
	sort.Slice(v.Statuses, func(i, j int) bool { return statusTime(v.Statuses[i]).After(statusTime(v.Statuses[j])) })
	dir, e = updater.SafePath(s.cfg.Update.SharedDir, "requests")
	if e != nil {
		return v, e
	}
	entries, e = os.ReadDir(dir)
	if e != nil && !os.IsNotExist(e) {
		return v, e
	}
	for _, f := range entries {
		if strings.HasSuffix(f.Name(), ".json") && updater.ValidID(strings.TrimSuffix(f.Name(), ".json")) {
			v.Pending = true
		}
	}
	v.HostPending = v.Pending
	scheduled, e := s.st.GetSetting(ctx, "update.scheduled")
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		return v, e
	}
	if scheduled != "" {
		var r updater.Request
		if e = updater.Decode([]byte(scheduled), &r); e != nil {
			return v, e
		}
		if e = r.Validate(); e != nil {
			return v, e
		}
		v.Scheduled = &r
		v.Pending = true
	}
	return v, nil
}
func statusTime(s updater.Status) time.Time {
	if len(s.Steps) > 0 {
		return s.Steps[len(s.Steps)-1].At
	}
	return s.FinishedAt
}
func adminUpdate(w http.ResponseWriter, r *http.Request) bool {
	u, ok := userFrom(r.Context())
	if !ok || u.Name != "admin" {
		writeErr(w, 403, "administrator required")
		return false
	}
	return true
}
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if !adminUpdate(w, r) {
		return
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	v, e := s.updateSnapshot(r.Context())
	if e != nil {
		writeErr(w, 503, "cannot read updater status")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) updateStepUp(w http.ResponseWriter, r *http.Request, password string) bool {
	if !adminUpdate(w, r) {
		return false
	}
	ip := clientIP(r)
	if !s.limiter.reserve(ip, s.now()) {
		writeErr(w, 429, "too many failed logins, wait a few minutes")
		return false
	}
	select {
	case s.bcryptSem <- struct{}{}:
	case <-r.Context().Done():
		return false
	case <-time.After(10 * time.Second):
		writeErr(w, 503, "busy, try again")
		return false
	}
	u, _ := userFrom(r.Context())
	_, ok := s.checkLogin(r.Context(), u.Name, password)
	<-s.bcryptSem
	if !ok {
		writeErr(w, 403, "incorrect password")
		return false
	}
	s.limiter.release(ip)
	return true
}
func updateID() string {
	var b [16]byte
	_, e := rand.Read(b[:])
	if e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func (s *Server) handleRequestUpdate(w http.ResponseWriter, r *http.Request) {
	if !adminUpdate(w, r) {
		return
	}
	var req struct {
		When     string `json:"when"`
		Password string `json:"password"`
	}
	if readJSON(r, &req) != nil || (req.When != "now" && req.When != "window") {
		writeErr(w, 400, "invalid update request")
		return
	}
	if !s.updateStepUp(w, r, req.Password) {
		return
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	v, e := s.updateSnapshot(r.Context())
	if e != nil {
		writeErr(w, 503, "cannot read updater status")
		return
	}
	if !s.cfg.Update.Enabled || s.cfg.Update.Channel == "pinned" || !v.Newer || v.Pending {
		writeErr(w, 409, "update disabled, pinned, unavailable or already pending")
		return
	}
	user, _ := userFrom(r.Context())
	request := updater.Request{ID: updateID(), Kind: "update", Channel: s.cfg.Update.Channel, Version: v.Available.Version, RequestedBy: user.Name, RequestedAt: s.now().UTC()}
	if req.When == "window" && !s.cfg.Update.windowOpen(s.now()) {
		b, _ := json.Marshal(request)
		e = s.st.SetSetting(r.Context(), "update.scheduled", string(b))
	} else {
		e = s.writeUpdateRequest(r.Context(), request)
	}
	if e != nil {
		writeErr(w, 500, "cannot write update request")
		return
	}
	if req.When == "window" && !s.cfg.Update.windowOpen(s.now()) {
		if e = s.updateRequested(r.Context(), request, "Update scheduled for "+s.cfg.Update.Window); e != nil {
			writeErr(w, 500, "cannot record update request")
			return
		}
	}
	writeJSON(w, 202, request)
}
func (s *Server) handleRollbackUpdate(w http.ResponseWriter, r *http.Request) {
	if !adminUpdate(w, r) {
		return
	}
	var req struct {
		ID       string `json:"id"`
		Password string `json:"password"`
	}
	if readJSON(r, &req) != nil || !updater.ValidID(req.ID) {
		writeErr(w, 400, "invalid rollback id")
		return
	}
	if !s.updateStepUp(w, r, req.Password) {
		return
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	v, e := s.updateSnapshot(r.Context())
	if e != nil {
		writeErr(w, 503, "cannot read updater status")
		return
	}
	if !s.cfg.Update.Enabled || s.cfg.Update.Channel == "pinned" || v.Pending {
		writeErr(w, 409, "rollback disabled, pinned or update pending")
		return
	}
	var target *updater.Status
	// Only the most recent successful update is eligible for web rollback.
	for i := range v.Statuses {
		st := &v.Statuses[i]
		if st.State == "done" {
			if st.Kind != "rollback" {
				target = st
			}
			break
		}
	}
	if target == nil || target.ID != req.ID || !target.KeepUntil.After(s.now()) || target.ToVersion != version.Version {
		writeErr(w, 409, "rollback is unavailable or expired")
		return
	}
	user, _ := userFrom(r.Context())
	request := updater.Request{ID: updateID(), Kind: "rollback", To: req.ID, Channel: s.cfg.Update.Channel, RequestedBy: user.Name, RequestedAt: s.now().UTC()}
	if e = s.writeUpdateRequest(r.Context(), request); e != nil {
		writeErr(w, 500, "cannot write rollback request")
		return
	}
	writeJSON(w, 202, request)
}
func (s *Server) updateEvent(ctx context.Context, state, id, actor, title string) {
	severity := "info"
	if state == "failed" {
		severity = "critical"
	}
	data, _ := json.Marshal(map[string]string{"request_id": id, "severity": severity})
	s.emit(ctx, notify.Event{Type: "update." + state, Severity: severity, Title: title, Link: "#/system"}, actor, string(data))
}
func (s *Server) writeUpdateRequest(ctx context.Context, r updater.Request) error {
	if e := r.Validate(); e != nil {
		return e
	}
	if e := s.updateRequested(ctx, r, "Server update requested"); e != nil {
		return e
	}
	// No writes to status/ or state/. Parents must be provisioned by the host;
	// the server cannot create directories outside requests/.
	if e := updater.WriteJSON(s.cfg.Update.SharedDir, r, "requests", r.ID+".json"); e != nil {
		return e
	}
	return nil
}

func (s *Server) updateRequested(ctx context.Context, r updater.Request, title string) error {
	key := "update.requested." + r.ID
	seen, e := s.st.GetSetting(ctx, key)
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		return e
	}
	if seen != "" {
		return nil
	}
	s.updateEvent(ctx, "requested", r.ID, r.RequestedBy, title)
	return s.st.SetSetting(ctx, key, "yes")
}

// PollUpdates also consumes host completion events while updates are disabled.
// Event IDs persist in the existing settings store across container replacement.
func (s *Server) PollUpdates(ctx context.Context) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	v, e := s.updateSnapshot(ctx)
	if e != nil {
		return e
	}
	for _, st := range v.Statuses {
		if !updater.Terminal(st.State) && st.Error == "" {
			continue
		}
		typ := "failed"
		if st.State == "done" {
			typ = "done"
		}
		key := "update.event." + st.ID
		seen, e := s.st.GetSetting(ctx, key)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return e
		}
		if seen == typ {
			continue
		}
		s.updateEvent(ctx, typ, st.ID, st.RequestedBy, "Server update "+st.State+": "+st.Error)
		if e := s.st.SetSetting(ctx, key, typ); e != nil {
			return e
		}
	}
	if !s.cfg.Update.Enabled || s.cfg.Update.Channel == "pinned" || !s.cfg.Update.windowOpen(s.now()) {
		return nil
	}
	if v.Scheduled != nil {
		if v.HostPending {
			return nil
		}
		if v.Scheduled.Channel != s.cfg.Update.Channel || !updater.Newer(v.Scheduled.Version, version.Version) {
			s.updateEvent(ctx, "failed", v.Scheduled.ID, v.Scheduled.RequestedBy, "Scheduled update is no longer newer or channel changed")
			return s.st.SetSetting(ctx, "update.scheduled", "")
		}
		// A scheduled request survives restarts in SQLite. Reuse its ID so a crash
		// after rename but before clearing the setting cannot make a second request.
		r := *v.Scheduled
		r.RequestedAt = s.now().UTC()
		if r.RequestedBy == "auto" {
			if e = s.st.SetSetting(ctx, "update.auto.version", r.Version); e != nil {
				return e
			}
		}
		if e = s.writeUpdateRequest(ctx, r); e != nil {
			return e
		}
		return s.st.SetSetting(ctx, "update.scheduled", "")
	}
	if !s.cfg.Update.Auto || v.Pending || !v.Newer {
		return nil
	}
	attempted, e := s.st.GetSetting(ctx, "update.auto.version")
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		return e
	}
	if attempted == v.Available.Version {
		return nil
	}
	r := updater.Request{ID: updateID(), Kind: "update", Channel: s.cfg.Update.Channel, Version: v.Available.Version, RequestedBy: "auto", RequestedAt: s.now().UTC()}
	// Persist the same request ID before publishing. A filesystem failure or a
	// crash retries this intent, while a completed failure never loops.
	b, _ := json.Marshal(r)
	if e = s.st.SetSetting(ctx, "update.scheduled", string(b)); e != nil {
		return e
	}
	if e = s.st.SetSetting(ctx, "update.auto.version", r.Version); e != nil {
		return e
	}
	if e = s.writeUpdateRequest(ctx, r); e != nil {
		return e
	}
	return s.st.SetSetting(ctx, "update.scheduled", "")
}
func (s *Server) RunUpdates(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		if e := s.PollUpdates(ctx); e != nil && ctx.Err() == nil {
			s.log.Warn("updater status", "err", e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
