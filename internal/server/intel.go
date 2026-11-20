package server

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

// intelState holds the threat-intelligence plug-ins and the match queue.
type intelState struct {
	mu        sync.Mutex
	matchers  []intel.Matcher
	enrichers []intel.Enricher
	queue     chan int64
	pending   map[int64]bool
	kick      chan struct{}
	feeds     map[string]*FeedStatus
	lastMatch time.Time
	lastErr   string
}

// FeedStatus is the state of one enricher feed.
type FeedStatus struct {
	Name      string    `json:"name"`
	LastOK    time.Time `json:"last_ok,omitzero"`
	LastError string    `json:"last_error,omitempty"`
}

// IntelStatus is shown on the overview page.
type IntelStatus struct {
	Matchers  []string     `json:"matchers"`
	Feeds     []FeedStatus `json:"feeds"`
	LastMatch time.Time    `json:"last_match,omitzero"`
	LastError string       `json:"last_error,omitempty"`
	Queued    int          `json:"queued"`
}

func newIntelState() *intelState {
	return &intelState{
		queue:   make(chan int64, 4096),
		pending: map[int64]bool{},
		kick:    make(chan struct{}, 1),
		feeds:   map[string]*FeedStatus{},
	}
}

// SetIntel installs the matchers and enrichers built from the config.
func (s *Server) SetIntel(ms []intel.Matcher, es []intel.Enricher) {
	s.intel.mu.Lock()
	defer s.intel.mu.Unlock()
	s.intel.matchers, s.intel.enrichers = ms, es
	for _, e := range es {
		s.intel.feeds[e.Name()] = &FeedStatus{Name: e.Name()}
	}
	for _, m := range ms {
		if _, ok := m.(intel.Refresher); ok {
			s.intel.feeds[m.Name()] = &FeedStatus{Name: m.Name()}
		}
		// A matcher that loads its data in the background asks for a
		// new match of all devices when the data is ready.
		if r, ok := m.(interface{ OnReady(func()) }); ok {
			r.OnReady(func() {
				if ids, err := s.st.DevicesWithComponents(context.Background()); err == nil {
					s.enqueueMatch(ids...)
				}
			})
		}
	}
}

func (s *Server) intelPlugins() ([]intel.Matcher, []intel.Enricher) {
	s.intel.mu.Lock()
	defer s.intel.mu.Unlock()
	return s.intel.matchers, s.intel.enrichers
}

// enqueueMatch schedules devices for matching. It never blocks.
func (s *Server) enqueueMatch(ids ...int64) {
	in := s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.matchers) == 0 {
		return
	}
	for _, id := range ids {
		if in.pending[id] {
			continue
		}
		select {
		case in.queue <- id:
			in.pending[id] = true
		default:
			s.log.Warn("match queue full", "device", id)
		}
	}
}

func hasComponents(es []proto.Entity) bool {
	for _, e := range es {
		if len(e.Components) > 0 || hasComponents(e.Children) {
			return true
		}
	}
	return false
}

// RunIntel refreshes the feeds, re-matches all devices on each refresh, and
// matches devices queued by ingest. It returns when ctx ends.
func (s *Server) RunIntel(ctx context.Context, every time.Duration) {
	go s.matchWorker(ctx)
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.intel.kick:
		}
		s.refreshFeeds(ctx)
		if ids, err := s.st.DevicesWithComponents(ctx); err == nil {
			s.enqueueMatch(ids...)
		}
		t.Reset(every)
	}
}

// KickIntel starts a refresh now.
func (s *Server) KickIntel() {
	select {
	case s.intel.kick <- struct{}{}:
	default:
	}
}

func (s *Server) refreshFeeds(ctx context.Context) {
	ms, es := s.intelPlugins()
	type feed interface {
		Name() string
		intel.Refresher
	}
	var feeds []feed
	for _, m := range ms {
		if r, ok := m.(feed); ok {
			feeds = append(feeds, r)
		}
	}
	for _, e := range es {
		feeds = append(feeds, e)
	}
	for _, e := range feeds {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err := e.Refresh(rctx)
		cancel()
		s.intel.mu.Lock()
		f := s.intel.feeds[e.Name()]
		if err != nil {
			f.LastError = err.Error()
		} else {
			f.LastOK, f.LastError = s.now(), ""
		}
		s.intel.mu.Unlock()
		if err != nil && ctx.Err() == nil {
			s.log.Warn("feed refresh", "feed", e.Name(), "err", err)
			s.event(ctx, "intel.error", e.Name(), "feed refresh failed: "+err.Error())
		}
	}
}

func (s *Server) matchWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-s.intel.queue:
			s.intel.mu.Lock()
			delete(s.intel.pending, id)
			s.intel.mu.Unlock()
			err := s.MatchDevice(ctx, id)
			s.intel.mu.Lock()
			s.intel.lastMatch = s.now()
			if err != nil {
				s.intel.lastErr = err.Error()
			} else {
				s.intel.lastErr = ""
			}
			s.intel.mu.Unlock()
			if err != nil && ctx.Err() == nil {
				s.log.Warn("match", "device", id, "err", err)
			}
		}
	}
}

// maxHitsPerDevice limits the findings of one matcher for one device. Real
// devices have a few thousand at most; more comes from a hostile report.
const maxHitsPerDevice = 50000

// MatchDevice runs all matchers for one device and stores the findings.
// A matcher that fails leaves the device's earlier findings unchanged.
func (s *Server) MatchDevice(ctx context.Context, id int64) error {
	ms, es := s.intelPlugins()
	comps, err := s.st.DeviceComponents(ctx, id)
	if err != nil {
		return err
	}
	var errs []string
	openedRows := []store.FindingRow{}
	openedKeys := map[[2]string]bool{}
	for _, m := range ms {
		mctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		hits, err := m.Match(mctx, comps)
		cancel()
		if err != nil {
			errs = append(errs, m.Name()+": "+err.Error())
			continue
		}
		if len(hits) > maxHitsPerDevice {
			errs = append(errs, fmt.Sprintf("%s: %d hits, more than %d; findings not changed", m.Name(), len(hits), maxHitsPerDevice))
			continue
		}
		vulns := map[string]intel.Vuln{}
		var fs []store.Finding
		for _, h := range hits {
			v, ok := vulns[h.Vuln.ID]
			if !ok {
				v = h.Vuln
				for _, e := range es {
					e.Enrich(&v)
				}
				vulns[v.ID] = v
			}
			fs = append(fs, store.Finding{PURL: h.Component.PURL, VulnID: v.ID, Fixed: h.Fixed, Confidence: string(h.Confidence)})
		}
		list := make([]intel.Vuln, 0, len(vulns))
		for _, v := range vulns {
			list = append(list, v)
		}
		now := s.now()
		if err := s.st.PutVulns(ctx, list, now); err != nil {
			return err
		}
		opened, err := s.st.SyncFindings(ctx, id, m.Name(), fs, now)
		if err != nil {
			return err
		}
		for _, f := range opened {
			k := [2]string{f.PURL, f.VulnID}
			if !openedKeys[k] && len(openedRows) < maxEvaluationsPerDevice {
				v := vulns[f.VulnID]
				openedRows = append(openedRows, store.FindingRow{Finding: f, Aliases: v.Aliases, Summary: v.Summary, Score: v.Score, Vector: v.Vector, KEV: v.KEV, EPSS: v.EPSS, EPSSPct: v.EPSSPct, Facts: v.Facts})
			}
			openedKeys[k] = true
		}
		if len(opened) > 0 {
			s.findingsEvent(ctx, id, m.Name(), opened, vulns)
		}
	}
	if err := s.resolveDeviceProposals(ctx, id); err != nil {
		return err
	}
	if len(openedRows) > 0 {
		nodes, e := s.decisionContext(ctx)
		if e != nil {
			return e
		}
		batch := newProposalBatch()
		e = s.evaluateFindings(ctx, openedRows, nodes, batch)
		s.emitProposalBatch(ctx, batch)
		if e != nil {
			return e
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// findingsEvent sends one summary event per device and match.
func (s *Server) findingsEvent(ctx context.Context, id int64, source string, opened []store.Finding, vulns map[string]intel.Vuln) {
	counts := map[string]int{}
	kev := 0
	seen := map[string]bool{}
	for _, f := range opened {
		if seen[f.VulnID] {
			continue
		}
		seen[f.VulnID] = true
		v := vulns[f.VulnID]
		counts[intel.Label(v.Score)]++
		if v.KEV {
			kev++
		}
	}
	var parts []string
	worst := "info"
	for _, l := range []string{"critical", "high", "medium", "low", "unknown"} {
		if counts[l] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[l], l))
			if worst == "info" && l != "unknown" {
				worst = l
			}
		}
	}
	if kev > 0 {
		parts = append([]string{fmt.Sprintf("%d known exploited", kev)}, parts...)
		worst = "critical"
	}
	name := "device #" + strconv.FormatInt(id, 10)
	if d, err := s.st.GetDevice(ctx, id); err == nil && d.Name != "" {
		name = d.Name
	}
	s.emit(ctx, notify.Event{
		Type:     "finding.new",
		Severity: worst,
		Title:    fmt.Sprintf("%d new vulnerabilities on %s", len(seen), name),
		Detail:   strings.Join(parts, ", "),
		Link:     "#/findings?device=" + strconv.FormatInt(id, 10),
		Fields:   map[string]string{"device": name, "source": source},
	}, source, "")
}

// Status returns the intel status for the overview.
func (s *Server) intelStatus() IntelStatus {
	in := s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	st := IntelStatus{LastMatch: in.lastMatch, LastError: in.lastErr, Queued: len(in.queue), Matchers: []string{}, Feeds: []FeedStatus{}}
	for _, m := range in.matchers {
		st.Matchers = append(st.Matchers, m.Name())
	}
	for _, f := range in.feeds {
		st.Feeds = append(st.Feeds, *f)
	}
	sort.Slice(st.Feeds, func(i, j int) bool { return st.Feeds[i].Name < st.Feeds[j].Name })
	return st
}

// --- operator API ---

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.FindingFilter{State: q.Get("state"), KEV: q.Get("kev") == "1"}
	if v := q.Get("device"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad device")
			return
		}
		f.DeviceID = id
	}
	if v := q.Get("min_score"); v != "" {
		x, err := strconv.ParseFloat(v, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad min_score")
			return
		}
		f.MinScore = x
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad limit")
			return
		}
		f.Limit = n
	}
	switch f.State {
	case "", "open", "resolved", "all":
	default:
		writeErr(w, http.StatusBadRequest, "state must be open, resolved or all")
		return
	}
	rows, err := s.st.ListFindings(r.Context(), f)
	if err != nil {
		s.log.Error("list findings", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devs, err := s.st.ListDevices(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	kinds := map[string]int{}
	agents := 0
	for _, d := range devs {
		kinds[d.Kind]++
		for _, id := range d.Identifiers {
			if id.Kind == "agent" {
				agents++
				break
			}
		}
	}
	peers, err := s.st.ListPeers(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	roles := map[string]int{}
	for _, p := range peers {
		if !p.Disabled {
			roles[p.Role]++
		}
	}
	stats, err := s.st.FindingStats(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	ev, _ := s.st.ListEvents(ctx, 10)
	if ev == nil {
		ev = []store.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"devices":         len(devs),
		"device_kinds":    kinds,
		"agent_devices":   agents,
		"peers":           roles,
		"findings":        stats,
		"intel":           s.intelStatus(),
		"events":          ev,
		"tls_fingerprint": s.fingerprint,
	})
}

func (s *Server) handleIntelRefresh(w http.ResponseWriter, r *http.Request) {
	s.KickIntel()
	u, _ := userFrom(r.Context())
	s.event(r.Context(), "intel.refresh", u.Name, "manual feed refresh and re-match")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}
