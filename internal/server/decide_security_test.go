package server

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func seedDecisionDevice(t *testing.T, s *Server, findings int) int64 {
	t.Helper()
	ctx := context.Background()
	now := s.now()
	var id int64
	err := s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
		var err error
		id, err = tx.CreateDevice(inventory.Device{Name: "host", Kind: proto.KindHost, Seen: now})
		if err != nil {
			return err
		}
		if err = tx.PutIdentifier(id, proto.Identifier{Kind: "ip", Value: "10.1.2.3", Strength: proto.Weak}, "test", now); err != nil {
			return err
		}
		return tx.PutComponents(id, "test", []proto.Component{{PURL: "pkg:generic/a@1", Name: "a", Version: "1"}}, true, now)
	})
	if err != nil {
		t.Fatal(err)
	}
	vs := []intel.Vuln{}
	fs := []store.Finding{}
	for i := range findings {
		v := fmt.Sprintf("CVE-%d", i)
		vs = append(vs, intel.Vuln{ID: v, Score: 9})
		fs = append(fs, store.Finding{PURL: "pkg:generic/a@1", VulnID: v, Confidence: "high"})
	}
	if err = s.st.PutVulns(ctx, vs, now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.st.SyncFindings(ctx, id, "fake", fs, now); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestKillSwitchWithoutConfiguredGuards(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	ctx := context.Background()
	id := seedDecisionDevice(t, s, 2)
	ds, err := registry.BuildAll(decide.Deciders, []registry.Spec{{Type: "rules", Settings: []byte(`{"rules":[{"name":"auto","then":{"tier":"auto","action":"snapshot","ttl":"1h"}}]}`)}})
	if err != nil {
		t.Fatal(err)
	}
	s.SetDecide(ds, nil)
	if err = s.reevaluate(ctx); err != nil {
		t.Fatal(err)
	}
	ps, _ := s.st.ListProposals(ctx, store.ProposalFilter{State: "auto"})
	if len(ps) != 2 {
		t.Fatal(ps)
	}
	doJSON(t, c, "POST", ts.URL+"/api/login", "", `{"user":"admin","password":"`+pw+`"}`, nil)
	if code := doJSON(t, c, "PUT", ts.URL+"/api/decide/settings", "", `{"killswitch":true}`, nil); code != 200 {
		t.Fatal(code)
	}
	for _, p := range ps {
		q, err := s.st.GetProposal(ctx, p.ID)
		if err != nil || q.State != "pending" || q.Tier != "approve" || q.Reason != "kill switch" || q.ExpiresAt.IsZero() {
			t.Fatal(q, err)
		}
	}
	var settings struct {
		Killswitch    bool
		Stats         map[string]int
		Rules, Guards []string
	}
	if code := doJSON(t, c, "GET", ts.URL+"/api/decide/settings", "", "", &settings); code != 200 || !settings.Killswitch || settings.Stats["pending"] != 2 || settings.Stats["auto"] != 0 || len(settings.Guards) != 0 || len(settings.Rules) != 1 {
		t.Fatal(code, settings)
	}
	// A newly evaluated key must also be downgraded, with no kill-switch guard.
	if _, _, err = s.st.UpsertProposal(ctx, store.Proposal{DeviceID: id, VulnID: "CVE-extra", State: "notify", Tier: "notify"}); err != nil {
		t.Fatal(err)
	}
	f := store.FindingRow{Finding: store.Finding{DeviceID: id, VulnID: "CVE-new", PURL: "pkg:generic/a@1"}}
	if err = s.evaluateFindings(ctx, []store.FindingRow{f}, nil, newProposalBatch()); err != nil {
		t.Fatal(err)
	}
	ps, _ = s.st.ListProposals(ctx, store.ProposalFilter{State: "pending"})
	if len(ps) != 3 || ps[0].Reason != "kill switch" {
		t.Fatal(ps)
	}
	events, _ := s.st.ListEvents(ctx, 100)
	found := false
	for _, event := range events {
		if event.Type == "decide.killswitch" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing switch event")
	}
	if err = s.reevaluate(ctx); err != nil {
		t.Fatal(err)
	}
	ps, _ = s.st.ListProposals(ctx, store.ProposalFilter{State: "auto"})
	if len(ps) != 0 {
		t.Fatal(ps)
	}
}

type decisionCountingStore struct {
	store.Store
	devices, findings atomic.Int64
	beforeDevice      func()
}

func (st *decisionCountingStore) ListDevices(ctx context.Context) ([]store.DeviceRow, error) {
	st.devices.Add(1)
	return st.Store.ListDevices(ctx)
}
func (st *decisionCountingStore) ListFindings(ctx context.Context, f store.FindingFilter) ([]store.FindingRow, error) {
	st.findings.Add(1)
	return st.Store.ListFindings(ctx, f)
}
func (st *decisionCountingStore) GetDevice(ctx context.Context, id int64) (store.DeviceDetail, error) {
	if st.beforeDevice != nil {
		st.beforeDevice()
	}
	return st.Store.GetDevice(ctx, id)
}

func TestDecisionContextCacheAndTagInvalidation(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	id := seedDecisionDevice(t, s, 1)
	st := &decisionCountingStore{Store: s.st}
	s.st = st
	now := time.Now()
	s.now = func() time.Time { return now }
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := s.decisionContext(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if st.devices.Load() != 1 || st.findings.Load() != 1 {
		t.Fatal(st.devices.Load(), st.findings.Load())
	}
	now = now.Add(29 * time.Second)
	if _, err := s.decisionContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.devices.Load() != 1 {
		t.Fatal("cache expired early")
	}
	now = now.Add(time.Second)
	if _, err := s.decisionContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.devices.Load() != 2 {
		t.Fatal("cache did not expire")
	}
	doJSON(t, c, "POST", ts.URL+"/api/login", "", `{"user":"admin","password":"`+pw+`"}`, nil)
	if code := doJSON(t, c, "PUT", fmt.Sprintf("%s/api/devices/%d/tags", ts.URL, id), "", `{"tags":["protected"]}`, nil); code != http.StatusOK {
		t.Fatal(code)
	}
	nodes, err := s.decisionContext(context.Background())
	if err != nil || st.devices.Load() != 3 || len(nodes[id].Tags) != 1 || nodes[id].Tags[0] != "protected" {
		t.Fatal(nodes, err, st.devices.Load())
	}
}

type waitingMatcher struct{ entered, release chan struct{} }

func (m waitingMatcher) Name() string { return "waiting" }
func (m waitingMatcher) Match(ctx context.Context, _ []proto.Component) ([]intel.Hit, error) {
	close(m.entered)
	select {
	case <-m.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestMatcherDoesNotHoldDecisionLock(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	id := seedDecisionDevice(t, s, 0)
	m := waitingMatcher{make(chan struct{}), make(chan struct{})}
	s.SetIntel([]intel.Matcher{m}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.MatchDevice(ctx, id) }()
	select {
	case <-m.entered:
	case <-ctx.Done():
		t.Fatal("matcher did not start")
	}
	free := s.decide.run.TryLock()
	if free {
		s.decide.run.Unlock()
	}
	close(m.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !free {
		t.Fatal("matcher held the decision lock")
	}
}

func TestReevaluationReleasesLockBetweenFindings(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	seedDecisionDevice(t, s, 205)
	seedDecisionDevice(t, s, 1)
	s.SetDecide([]decide.Decider{&captureDecider{}}, nil)
	checks := 0
	st := &decisionCountingStore{Store: s.st, beforeDevice: func() {
		checks++
		if !s.decide.run.TryLock() {
			t.Error("reevaluation held decision lock outside evaluation")
		} else {
			s.decide.run.Unlock()
		}
	}}
	s.st = st
	if err := s.reevaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if checks != 2 {
		t.Fatal("devices checked", checks)
	}
}

func TestProposalSectionsAndUnboundedCounts(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	ctx := context.Background()
	id := seedDecisionDevice(t, s, 0)
	for i := range 515 {
		state, tier := "notify", "notify"
		if i == 0 {
			state, tier = "pending", "approve"
		}
		if i == 1 {
			state, tier = "auto", "auto"
		}
		if _, _, err := s.st.UpsertProposal(ctx, store.Proposal{DeviceID: id, VulnID: fmt.Sprintf("v%d", i), State: state, Tier: tier}); err != nil {
			t.Fatal(err)
		}
	}
	doJSON(t, c, "POST", ts.URL+"/api/login", "", `{"user":"admin","password":"`+pw+`"}`, nil)
	for _, state := range []string{"pending", "auto", "notify,approved,rejected,expired,resolved"} {
		var ps []store.Proposal
		if code := doJSON(t, c, "GET", ts.URL+"/api/proposals?state="+state+"&limit=500", "", "", &ps); code != 200 {
			t.Fatal(code)
		}
		if state == "pending" || state == "auto" {
			if len(ps) != 1 || ps[0].State != state {
				t.Fatal(state, ps)
			}
		} else if len(ps) != 500 {
			t.Fatal("history rows", len(ps))
		}
	}
	var settings struct{ Stats map[string]int }
	if code := doJSON(t, c, "GET", ts.URL+"/api/decide/settings", "", "", &settings); code != 200 {
		t.Fatal(code)
	}
	if settings.Stats["pending"] != 1 || settings.Stats["auto"] != 1 || settings.Stats["notify"] != 513 {
		t.Fatal(settings)
	}
}

type maintenanceProposalStore struct {
	store.Store
	cutoff time.Time
	cancel context.CancelFunc
}

func (st *maintenanceProposalStore) PurgeProposals(ctx context.Context, before time.Time) error {
	st.cutoff = before
	err := st.Store.PurgeProposals(ctx, before)
	st.cancel()
	return err
}

func TestMaintenancePurgesOldProposalHistory(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	id := seedDecisionDevice(t, s, 0)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, _, err := s.st.UpsertProposal(ctx, store.Proposal{DeviceID: id, VulnID: "old", State: "notify", Tier: "notify", CreatedAt: now.Add(-91 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	st := &maintenanceProposalStore{Store: s.st, cancel: cancel}
	s.st = st
	s.RunMaintenance(ctx, 7*24*time.Hour)
	if !st.cutoff.Equal(now.Add(-90 * 24 * time.Hour)) {
		t.Fatal(st.cutoff)
	}
	ps, err := s.st.ListProposals(context.Background(), store.ProposalFilter{})
	if err != nil || len(ps) != 0 {
		t.Fatal(ps, err)
	}
}
