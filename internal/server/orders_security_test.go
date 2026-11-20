package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	_ "github.com/JulianStremel/netnoodle/internal/decide/guards"
	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func TestPlannerPinnedIdentity(t *testing.T) {
	for _, mode := range []string{"intersection", "changed", "weak"} {
		t.Run(mode, func(t *testing.T) {
			ts, _, s, _ := setupOrders(t)
			ctx := context.Background()
			c, _ := enrollOrderActor(t, s, ts, "pinned")
			helloActor(t, c, logCaps(t))
			dev := orderDevice(t, s)
			if mode == "weak" { // Even a strong-labelled IP is never a valid target.
				if e := s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
					if e := tx.PutIdentifier(dev, proto.Identifier{Kind: "ip", Value: "192.0.2.1", Strength: proto.Strong}, "test", s.now()); e != nil {
						return e
					}
					other, e := tx.CreateDevice(inventory.Device{Name: "other", Seen: s.now()})
					if e != nil {
						return e
					}
					return tx.PutIdentifier(other, proto.Identifier{Kind: "mac", Value: "00:11:22:33:44:55", Strength: proto.Strong}, "test", s.now())
				}); e != nil {
					t.Fatal(e)
				}
			}
			p := orderProposal(t, s, dev, "pin", "isolate", 60)
			saved, e := s.st.GetProposal(ctx, p.ID)
			if e != nil {
				t.Fatal(e)
			}
			want := 1
			if mode == "weak" {
				want = 0
			}
			if len(saved.TargetSnapshot) != want {
				t.Fatal(saved.TargetSnapshot)
			}
			if e = s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
				if e := tx.PutIdentifier(dev, proto.Identifier{Kind: "mac", Value: "00:11:22:33:44:66", Strength: proto.Strong}, "test", s.now()); e != nil {
					return e
				}
				if mode != "changed" {
					return nil
				}
				other, e := tx.CreateDevice(inventory.Device{Name: "replacement", Seen: s.now()})
				if e != nil {
					return e
				}
				return tx.PutIdentifier(other, proto.Identifier{Kind: "mac", Value: "00:11:22:33:44:55", Strength: proto.Strong}, "test", s.now())
			}); e != nil {
				t.Fatal(e)
			}
			plan(t, s)
			if mode == "intersection" {
				o := pollOrder(t, c)
				if len(o.Targets) != 1 || o.Targets[0].Value != "00:11:22:33:44:55" {
					t.Fatal(o.Targets)
				}
			} else {
				saved, _ = s.st.GetProposal(ctx, p.ID)
				if saved.State != "pending" || saved.Reason != "device identity changed; approve again" || len(saved.TargetSnapshot) != 0 {
					t.Fatal(saved)
				}
				var envs []orders.Envelope
				if e = c.Do(ctx, "GET", "/v1/orders?wait=0", nil, &envs); e != nil || len(envs) != 0 {
					t.Fatal(envs, e)
				}
			}
		})
	}
}

func TestPlannerRechecksAutoGuards(t *testing.T) {
	ts, _, s, _ := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "auto")
	helloActor(t, c, logCaps(t))
	dev := orderDevice(t, s)
	// Store a real finding so the planner must evaluate the current device context.
	if e := s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
		return tx.PutComponents(dev, "test", []proto.Component{{PURL: "pkg:generic/a@1", Name: "a", Version: "1"}}, true, s.now())
	}); e != nil {
		t.Fatal(e)
	}
	s.SetIntel([]intel.Matcher{&fakeMatcher{vulns: map[string][]intel.Vuln{"a": {{ID: "auto-v"}}}}}, nil)
	if e := s.MatchDevice(ctx, dev); e != nil {
		t.Fatal(e)
	}
	p, _, e := s.st.UpsertProposal(ctx, store.Proposal{DeviceID: dev, VulnID: "auto-v", PURL: "pkg:generic/a@1", Action: "isolate", State: "auto", Tier: "auto", TTL: 60, CreatedAt: s.now()})
	if e != nil {
		t.Fatal(e)
	}
	g, e := decide.Guards.Build("protected", "protected", nil)
	if e != nil {
		t.Fatal(e)
	}
	s.SetDecide(nil, []decide.Guard{g})
	if e = s.st.SetTags(ctx, dev, []string{"protected"}); e != nil {
		t.Fatal(e)
	}
	plan(t, s)
	got, _ := s.st.GetProposal(ctx, p.ID)
	if got.State != "pending" || !strings.Contains(got.Reason, "protected") || len(got.TargetSnapshot) != 0 {
		t.Fatal(got)
	}
}

func TestLateResultsAndPrecaution(t *testing.T) {
	for _, mode := range []string{"sent", "expired", "uncertain", "too late", "future at", "old at", "failed"} {
		t.Run(mode, func(t *testing.T) {
			ts, _, s, now := setupOrders(t)
			ctx := context.Background()
			c, _ := enrollOrderActor(t, s, ts, "late")
			other, _ := enrollOrderActor(t, s, ts, "other")
			helloActor(t, c, logCaps(t))
			dev := orderDevice(t, s)
			action := "snapshot"
			if mode != "expired" {
				action = "isolate"
			}
			p := orderProposal(t, s, dev, "late", action, 3600)
			plan(t, s)
			o := pollOrder(t, c)
			sent := *now
			*now = now.Add(11 * time.Minute)
			if mode == "uncertain" || mode == "expired" || mode == "failed" {
				plan(t, s)
			}
			if mode == "uncertain" || mode == "failed" {
				saved, _ := s.st.GetOrder(ctx, o.ID)
				if saved.State != "uncertain" || saved.RevertAttempts != 1 {
					t.Fatal(saved)
				}
				got, _ := s.st.GetProposal(ctx, p.ID)
				if got.State != "failed" || got.Reason != "no result from actor; revert sent as precaution" {
					t.Fatal(got)
				}
				revert := pollOrder(t, c)
				if !revert.Revert || revert.RevertOf != o.ID {
					t.Fatal(revert)
				}
			}
			if mode == "expired" {
				saved, _ := s.st.GetOrder(ctx, o.ID)
				if saved.State != "expired" {
					t.Fatal(saved.State)
				}
			}
			if mode == "too late" {
				*now = o.NotAfter.Add(24*time.Hour + time.Nanosecond)
			}
			at := sent.Add(2 * time.Minute)
			if mode == "future at" {
				at = now.Add(time.Hour)
			}
			if mode == "old at" {
				at = sent.Add(-time.Hour)
			}
			r := proto.OrderResult{Version: proto.Version, OrderID: o.ID, Status: proto.OrderDone, At: at, Message: "done"}
			if mode == "failed" {
				r.Status = proto.OrderFailed
			}
			if e := other.Do(ctx, "POST", "/v1/orders/result", r, nil); e == nil || !strings.Contains(e.Error(), "404") {
				t.Fatal("owner", e)
			}
			e := c.Do(ctx, "POST", "/v1/orders/result", r, nil)
			if mode == "too late" {
				if e == nil || !strings.Contains(e.Error(), "409") {
					t.Fatal(e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			saved, _ := s.st.GetOrder(ctx, o.ID)
			if saved.State != string(r.Status) {
				t.Fatal(saved.State)
			}
			if mode != "expired" && mode != "failed" {
				expected := at
				if expected.Before(sent) {
					expected = sent
				}
				if expected.After(*now) {
					expected = *now
				}
				if !saved.RevertDueAt.Equal(expected.Add(time.Hour)) {
					t.Fatal(saved.RevertDueAt, expected)
				}
			}
			if e = c.Do(ctx, "POST", "/v1/orders/result", r, nil); e != nil {
				t.Fatal("identical retry", e)
			}
			r.Message = "different"
			if e = c.Do(ctx, "POST", "/v1/orders/result", r, nil); e == nil || !strings.Contains(e.Error(), "409") {
				t.Fatal("different retry", e)
			}
		})
	}
}

func TestKillSwitchCancelsQueuedAndPreservesRevert(t *testing.T) {
	ts, _, s, _ := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "switch")
	helloActor(t, c, logCaps(t))
	dev := orderDevice(t, s)
	orderProposal(t, s, dev, "executed", "isolate", 60)
	plan(t, s)
	original := pollOrder(t, c)
	finish(t, s, c, original, proto.OrderDone)
	if e := s.st.ScheduleRevert(ctx, original.ID, s.now()); e != nil {
		t.Fatal(e)
	}
	p := orderProposal(t, s, dev, "queued", "isolate", 60)
	plan(t, s)
	auto, _, e := s.st.UpsertProposal(ctx, store.Proposal{DeviceID: dev, VulnID: "noactor", Action: "isolate", State: "auto", Tier: "auto", TTL: 60, CreatedAt: s.now()})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.st.SetProposalOrderState(ctx, auto.ID, "no-actor", "no actor", s.now()); e != nil {
		t.Fatal(e)
	}
	if e = s.st.SetSetting(ctx, "decide.killswitch", "on"); e != nil {
		t.Fatal(e)
	}
	got, _ := s.st.GetProposal(ctx, p.ID)
	if got.State != "pending" || got.Reason != "kill switch" {
		t.Fatal(got)
	}
	got, _ = s.st.GetProposal(ctx, auto.ID)
	if got.State != "pending" {
		t.Fatal(got)
	}
	os, _ := s.st.ListOrders(ctx, store.OrderFilter{ProposalID: p.ID})
	if len(os) != 1 || os[0].State != "cancelled" {
		t.Fatal(os)
	}
	revert := pollOrder(t, c)
	if !revert.Revert {
		t.Fatal(revert)
	}
	// Reapproval after cancellation can make a fresh order once the switch is off.
	if e = s.st.SetSetting(ctx, "decide.killswitch", "off"); e != nil {
		t.Fatal(e)
	}
	if e = s.st.DecideProposal(ctx, p.ID, "approved", "admin", s.now()); e != nil {
		t.Fatal(e)
	}
	plan(t, s)
	next := pollOrder(t, c)
	if next.Revert || next.ID == os[0].ID {
		t.Fatal(next)
	}
}

func TestResolutionKeepsTTLAndEmitsOnce(t *testing.T) {
	ts, _, s, now := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "ttl")
	helloActor(t, c, logCaps(t))
	dev := orderDevice(t, s)
	orderProposal(t, s, dev, "resolved", "isolate", 3600)
	plan(t, s)
	o := pollOrder(t, c)
	finish(t, s, c, o, proto.OrderDone)
	for range 2 {
		if e := s.resolveDeviceProposals(ctx, dev); e != nil {
			t.Fatal(e)
		}
		plan(t, s)
	}
	saved, _ := s.st.GetOrder(ctx, o.ID)
	if !saved.RevertDueAt.Equal(now.Add(time.Hour)) {
		t.Fatal(saved.RevertDueAt)
	}
	events, _ := s.st.ListEvents(ctx, 100)
	count := 0
	for _, ev := range events {
		if ev.Summary == "finding fixed on actor-target; revert available" {
			count++
			if !strings.Contains(ev.Data, `"severity":"info"`) {
				t.Fatal(ev)
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
	var envs []orders.Envelope
	if e := c.Do(ctx, "GET", "/v1/orders?wait=0", nil, &envs); e != nil || len(envs) != 0 {
		t.Fatal(envs, e)
	}
	*now = now.Add(time.Hour)
	plan(t, s)
	revert := pollOrder(t, c)
	if !revert.Revert {
		t.Fatal(revert)
	}
}

func TestRevertRateLimitRefundAndDisabledAlert(t *testing.T) {
	ts, _, s, now := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "blocked")
	helloActor(t, c, logCaps(t))
	dev := orderDevice(t, s)
	orderProposal(t, s, dev, "reliability", "isolate", 60)
	plan(t, s)
	o := pollOrder(t, c)
	finish(t, s, c, o, proto.OrderDone)
	*now = now.Add(time.Minute)
	plan(t, s)
	revert := pollOrder(t, c)
	r := proto.OrderResult{Version: proto.Version, OrderID: revert.ID, Status: proto.OrderRejected, At: *now, Message: "hourly rate limit exceeded"}
	if e := c.Do(ctx, "POST", "/v1/orders/result", r, nil); e != nil {
		t.Fatal(e)
	}
	saved, _ := s.st.GetOrder(ctx, o.ID)
	if saved.RevertAttempts != 0 || !saved.RevertDueAt.Equal(now.Add(10*time.Minute)) {
		t.Fatal(saved)
	}
	if e := c.Do(ctx, "POST", "/v1/orders/result", r, nil); e != nil {
		t.Fatal(e)
	}
	saved, _ = s.st.GetOrder(ctx, o.ID)
	if saved.RevertAttempts != 0 {
		t.Fatal(saved.RevertAttempts)
	}
	actors, _ := s.st.ListActors(ctx)
	if e := s.st.SetPeerDisabled(ctx, actors[0].Peer.ID, true); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(10 * time.Minute)
	plan(t, s)
	plan(t, s)
	events, _ := s.st.ListEvents(ctx, 100)
	count := 0
	for _, ev := range events {
		if ev.Summary == "revert blocked: actor blocked disabled" {
			count++
			if !strings.Contains(ev.Data, `"severity":"critical"`) {
				t.Fatal(ev)
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
	if e := s.st.SetPeerDisabled(ctx, actors[0].Peer.ID, false); e != nil {
		t.Fatal(e)
	}
	plan(t, s)
	_ = pollOrder(t, c)
}

func TestOrderPollAdmissionAndRelease(t *testing.T) {
	ts, _, s, _ := setupOrders(t)
	c, creds := enrollOrderActor(t, s, ts, "poller")
	_ = c
	ctx := context.Background()
	actors, _ := s.st.ListActors(ctx)
	id := actors[0].Peer.ID
	// Start two real waiting requests, then exercise the HTTP rejection and cleanup.
	pollCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(pollCtx, "GET", ts.URL+"/v1/orders?wait=30", nil)
			req.Header.Set("Authorization", "Bearer "+creds.Token)
			resp, e := ts.Client().Do(req)
			if e == nil {
				resp.Body.Close()
			}
		}()
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.orders.mu.Lock()
		n := s.orders.polls[id]
		s.orders.mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("polls did not enter")
		}
		time.Sleep(time.Millisecond)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/v1/orders?wait=0", nil)
	req.Header.Set("Authorization", "Bearer "+creds.Token)
	resp, e := ts.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatal(resp.StatusCode)
	}
	cancel()
	wg.Wait()
	deadline = time.Now().Add(3 * time.Second)
	for {
		s.orders.mu.Lock()
		n := s.orders.pollTotal
		s.orders.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slots leaked")
		}
		time.Sleep(time.Millisecond)
	}
	// Global capacity is shared across actors; the handler still returns 429.
	for i := int64(1000); i < 1128; i++ {
		if !s.acquireOrderPoll(i) || !s.acquireOrderPoll(i) {
			t.Fatal(i)
		}
	}
	req, _ = http.NewRequest("GET", ts.URL+"/v1/orders?wait=0", nil)
	req.Header.Set("Authorization", "Bearer "+creds.Token)
	resp, e = ts.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatal(resp.StatusCode)
	}
	for i := int64(1000); i < 1128; i++ {
		s.releaseOrderPoll(i)
		s.releaseOrderPoll(i)
	}
	if !s.acquireOrderPoll(id) {
		t.Fatal("capacity not released")
	}
	s.releaseOrderPoll(id)
}

func TestQueuedReversibleExpiryHasNoPrecaution(t *testing.T) {
	ts, _, s, now := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "queued")
	helloActor(t, c, logCaps(t))
	dev := orderDevice(t, s)
	p := orderProposal(t, s, dev, "queued-expiry", "isolate", 60)
	plan(t, s)
	*now = now.Add(11 * time.Minute)
	plan(t, s)
	os, _ := s.st.ListOrders(ctx, store.OrderFilter{ProposalID: p.ID})
	if len(os) != 1 || os[0].State != "expired" || !os[0].RevertDueAt.IsZero() {
		t.Fatal(os)
	}
	r := proto.OrderResult{Version: proto.Version, OrderID: os[0].ID, Status: proto.OrderDone, At: *now}
	if e := c.Do(ctx, "POST", "/v1/orders/result", r, nil); e == nil || !strings.Contains(e.Error(), "409") {
		t.Fatal("never sent", e)
	}
}

func TestPlannerUsesCapabilityKindOrder(t *testing.T) {
	ts, _, s, _ := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "kind-order")
	helloActor(t, c, []proto.Capability{{Action: "snapshot", TargetIDKinds: []string{"ip", "agent", "mac"}}})
	dev := orderDevice(t, s)
	if e := s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
		return tx.PutIdentifier(dev, proto.Identifier{Kind: "agent", Value: "pinned-agent", Strength: proto.Strong}, "test", s.now())
	}); e != nil {
		t.Fatal(e)
	}
	orderProposal(t, s, dev, "kind", "snapshot", 0)
	plan(t, s)
	o := pollOrder(t, c)
	if len(o.Targets) != 1 || o.Targets[0].Kind != "agent" || o.Targets[0].Value != "pinned-agent" {
		t.Fatal(o.Targets)
	}
}

func TestPlannerDoesNotExecuteExpiredApprovalBeyondExpiryBatch(t *testing.T) {
	ts, _, s, now := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "expiry-batch")
	helloActor(t, c, logCaps(t))
	dev := orderDevice(t, s)
	for i := range 201 {
		orderProposal(t, s, dev, fmt.Sprint("old-", i), "snapshot", 0)
	}
	*now = now.Add(7 * 24 * time.Hour)
	plan(t, s)
	all, e := s.st.ListOrders(ctx, store.OrderFilter{})
	if e != nil || len(all) != 0 {
		t.Fatal("expired approval executed", len(all), e)
	}
	stats, e := s.st.ProposalStats(ctx)
	if e != nil || stats["expired"] != 201 {
		t.Fatal(stats, e)
	}
}
