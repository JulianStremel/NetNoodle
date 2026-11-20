package server

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func TestUncertainResultsRecoverImmediately(t *testing.T) {
	for _, mode := range []string{"sent", "late", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ts, _, s, now := setupOrders(t)
			ctx := context.Background()
			owner, _ := enrollOrderActor(t, s, ts, "owner")
			other, _ := enrollOrderActor(t, s, ts, "other")
			helloActor(t, owner, logCaps(t))
			p := orderProposal(t, s, orderDevice(t, s), mode, "isolate", 3600)
			plan(t, s)
			oos, err := s.st.ListOrders(ctx, store.OrderFilter{ProposalID: p.ID})
			if err != nil || len(oos) != 1 {
				t.Fatal(oos, err)
			}
			r := proto.OrderResult{Version: proto.Version, OrderID: oos[0].ID, Status: proto.OrderUncertain, Message: "verification failed", At: *now}
			if err = owner.Do(ctx, "POST", "/v1/orders/result", r, nil); err == nil || !strings.Contains(err.Error(), "409") {
				t.Fatal("queued result", err)
			}
			o := pollOrder(t, owner)
			if err = other.Do(ctx, "POST", "/v1/orders/result", r, nil); err == nil || !strings.Contains(err.Error(), "404") {
				t.Fatal("wrong owner", err)
			}
			if mode != "sent" {
				*now = now.Add(11 * time.Minute)
			}
			if mode == "expired" {
				plan(t, s)
			}
			// Even a changed capability cannot reroute recovery to another actor.
			helloActor(t, owner, nil)
			helloActor(t, other, logCaps(t))
			if err = s.st.SetSetting(ctx, "decide.killswitch", "on"); err != nil {
				t.Fatal(err)
			}
			if err = owner.Do(ctx, "POST", "/v1/orders/result", r, nil); err != nil {
				t.Fatal(err)
			}
			got, err := s.st.GetOrder(ctx, o.ID)
			if err != nil || got.State != "uncertain" {
				t.Fatal(got, err)
			}
			proposal, err := s.st.GetProposal(ctx, p.ID)
			if err != nil || proposal.State != "failed" || proposal.Reason != "possibly applied: verification failed; precautionary revert sent" {
				t.Fatal(proposal, err)
			}
			// No planner tick is needed after the result.
			oos, err = s.st.ListOrders(ctx, store.OrderFilter{ProposalID: p.ID})
			if err != nil || len(oos) != 2 {
				t.Fatal(oos, err)
			}
			revert := pollOrder(t, owner)
			if !revert.Revert || revert.RevertOf != o.ID || revert.Actor != "owner" || !reflect.DeepEqual(revert.Targets, o.Targets) {
				t.Fatal(revert)
			}
			for range 2 {
				if err = owner.Do(ctx, "POST", "/v1/orders/result", r, nil); err != nil {
					t.Fatal("idempotent retry", err)
				}
			}
			changed := r
			changed.Message = "changed"
			if err = owner.Do(ctx, "POST", "/v1/orders/result", changed, nil); err == nil || !strings.Contains(err.Error(), "409") {
				t.Fatal("conflicting retry", err)
			}
			oos, _ = s.st.ListOrders(ctx, store.OrderFilter{ProposalID: p.ID})
			if len(oos) != 2 {
				t.Fatal("duplicate recovery", oos)
			}
			events, err := s.st.ListEvents(ctx, 100)
			if err != nil {
				t.Fatal(err)
			}
			uncertainEvents := 0
			for _, ev := range events {
				if ev.Type == "order.uncertain" {
					uncertainEvents++
				}
			}
			if uncertainEvents != 1 {
				t.Fatal("result notification must be emitted exactly once, including after expiry", uncertainEvents)
			}
			finish(t, s, owner, revert, proto.OrderUncertain)
			plan(t, s)
			oos, _ = s.st.ListOrders(ctx, store.OrderFilter{ProposalID: p.ID})
			if len(oos) != 2 {
				t.Fatal("uncertain revert bypassed retry backoff", oos)
			}
			*now = now.Add(10 * time.Minute)
			plan(t, s)
			retry := pollOrder(t, owner)
			if !retry.Revert || retry.RevertOf != o.ID {
				t.Fatal(retry)
			}
		})
	}
}

func TestUncertainResultOutsideWindow(t *testing.T) {
	ts, _, s, now := setupOrders(t)
	c, _ := enrollOrderActor(t, s, ts, "owner")
	helloActor(t, c, logCaps(t))
	orderProposal(t, s, orderDevice(t, s), "old", "isolate", 0)
	plan(t, s)
	o := pollOrder(t, c)
	*now = o.NotAfter.Add(24*time.Hour + time.Second)
	err := c.Do(context.Background(), "POST", "/v1/orders/result", proto.OrderResult{Version: proto.Version, OrderID: o.ID, Status: proto.OrderUncertain}, nil)
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatal(err)
	}
}

func TestPlannerScopedCapabilities(t *testing.T) {
	for _, mode := range []string{"scoped-wins", "mismatch", "tie", "kinds", "subset"} {
		t.Run(mode, func(t *testing.T) {
			ts, h, s, _ := setupOrders(t)
			ctx := context.Background()
			first, _ := enrollOrderActor(t, s, ts, "first")
			second, _ := enrollOrderActor(t, s, ts, "second")
			dev := orderDevice(t, s)
			if err := s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
				for _, id := range []proto.Identifier{{Kind: "agent", Value: "target", Strength: proto.Strong}, {Kind: "mac", Value: "aa:bb:cc:dd:ee:ff", Strength: proto.Strong}} {
					if err := tx.PutIdentifier(dev, id, "scan", s.now()); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			base := proto.Capability{Action: "isolate", TargetIDKinds: []string{"mac", "agent"}, Reversible: true, RevertAction: "unisolate"}
			c1, c2 := base, base
			c2.TargetScope = []string{"agent=targ[ea]t", "mac=00:11:*"}
			wantActor, wantKind := "second", "mac"
			switch mode {
			case "mismatch":
				c2.TargetScope = []string{"agent=elsewhere"}
				wantActor = "first"
			case "tie":
				c1.TargetScope = c2.TargetScope
				wantActor = "first"
			case "kinds":
				c2.TargetScope = []string{"agent=target"}
				wantKind = "agent"
			case "subset":
				c2.TargetScope = []string{"mac=00:11:*"}
			}
			helloActor(t, first, []proto.Capability{c1})
			helloActor(t, second, []proto.Capability{c2})
			var actors []store.ActorCaps
			if code := doJSON(t, h, "GET", ts.URL+"/api/actors", "", "", &actors); code != 200 || !reflect.DeepEqual(actors[1].Capabilities[0].TargetScope, c2.TargetScope) {
				t.Fatal(actors, code)
			}
			p := orderProposal(t, s, dev, mode, "isolate", 60)
			plan(t, s)
			os, err := s.st.ListOrders(ctx, store.OrderFilter{ProposalID: p.ID})
			if err != nil || len(os) != 1 || os[0].Actor != wantActor || os[0].Targets[0].Kind != wantKind {
				t.Fatal(os, err)
			}
			if mode == "subset" && (len(os[0].Targets) != 1 || os[0].Targets[0].Value != "00:11:22:33:44:55") {
				t.Fatal(os)
			}
		})
	}
}

func TestScopePatternsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		pattern, kind, value string
		want                 bool
	}{
		{"agent=host-?", "agent", "host-a", true},
		{"agent=host-?", "agent", "host-ab", false},
		{"agent=*", "mac", "host-a", false},
		{"agent=[", "agent", "[", false},
		{"missing-separator", "agent", "x", false},
		// "/*" with a literal prefix is a subtree, as on the actor side
		// (proto.MatchesScope; security review 2026-11-20).
		{"proxmox.guest=pve/*", "proxmox.guest", "pve/cluster/100", true},
		{"proxmox.guest=p*/*", "proxmox.guest", "pve/cluster/100", false},
		{"proxmox.guest=pve/*/*", "proxmox.guest", "pve/cluster/100", true},
	} {
		if got := matchesTargetScope([]string{tc.pattern}, proto.Identifier{Kind: tc.kind, Value: tc.value}); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}

type portReviewDecider struct {
	params map[string]any
	auto   bool
}

func (d portReviewDecider) Name() string { return "ports" }
func (d portReviewDecider) Decide(context.Context, decide.Situation) (decide.Proposal, bool, error) {
	tier := decide.TierApprove
	if d.auto {
		tier = decide.TierAuto
	}
	return decide.Proposal{Action: "block-port", Tier: tier, TTL: 60, Reason: "vulnerable listener", Params: d.params}, true, nil
}

func TestBlockPortListenerFiltering(t *testing.T) {
	for _, supplied := range []bool{false, true} {
		t.Run(fmt.Sprint("supplied=", supplied), func(t *testing.T) {
			_, _, _, s := newTestServerS(t)
			ctx := context.Background()
			dev := orderDevice(t, s)
			values := []string{"0/tcp", "65536/udp", "-1/tcp", "80/sctp", "abc/tcp", "80/tcp", "80/tcp", "80/udp", "65535/udp", "22/tcp", "7444/tcp", "22/udp", "7444/udp"}
			for n := 100; n < 140; n++ {
				values = append(values, fmt.Sprintf("%d/tcp", n))
			}
			params := map[string]any(nil)
			if supplied {
				params = map[string]any{"ports": values}
			}
			f := store.FindingRow{Finding: store.Finding{DeviceID: dev, VulnID: "ports"}}
			situation := decide.Situation{Device: decide.Device{Listeners: values}}
			if err := s.evaluateSituation(ctx, []decide.Decider{portReviewDecider{params: params}}, nil, f, situation, newProposalBatch()); err != nil {
				t.Fatal(err)
			}
			ps, err := s.st.ListProposals(ctx, store.ProposalFilter{})
			if err != nil || len(ps) != 1 {
				t.Fatal(ps, err)
			}
			ports := ps[0].Params["ports"].([]any)
			if len(ports) != 32 || ports[0] != "80/tcp" || ports[1] != "80/udp" || ports[2] != "65535/udp" || ports[31] != "128/tcp" {
				t.Fatal(ports)
			}
			for _, value := range []string{"22/tcp", "7444/tcp", "22/udp", "7444/udp"} {
				if !strings.Contains(ps[0].Reason, "ports "+value+" kept open") {
					t.Fatal(ps[0].Reason)
				}
			}
		})
	}
	_, _, _, s := newTestServerS(t)
	ctx := context.Background()
	f := store.FindingRow{Finding: store.Finding{DeviceID: orderDevice(t, s), VulnID: "protected"}}
	situation := decide.Situation{Device: decide.Device{Listeners: []string{"22/tcp", "7444/tcp", "0/tcp", "65536/tcp", "80/icmp"}}}
	if err := s.evaluateSituation(ctx, []decide.Decider{portReviewDecider{}}, nil, f, situation, newProposalBatch()); err != nil {
		t.Fatal(err)
	}
	ps, err := s.st.ListProposals(ctx, store.ProposalFilter{})
	if err != nil || len(ps) != 1 || ps[0].State != "notify" || ps[0].Action != "" || !strings.Contains(ps[0].Reason, "no exposed port to block") {
		t.Fatal(ps, err)
	}
	if err := s.st.SetSetting(ctx, "decide.killswitch", "on"); err != nil {
		t.Fatal(err)
	}
	f.VulnID = "kill-switch-ports"
	situation.Device.Listeners = []string{"80/tcp", "22/tcp", "7444/tcp"}
	if err := s.evaluateSituation(ctx, []decide.Decider{portReviewDecider{auto: true}}, nil, f, situation, newProposalBatch()); err != nil {
		t.Fatal(err)
	}
	ps, err = s.st.ListProposals(ctx, store.ProposalFilter{State: "pending"})
	if err != nil || len(ps) != 1 || ps[0].Reason != "kill switch; ports 22/tcp kept open; ports 7444/tcp kept open" {
		t.Fatal(ps, err)
	}
}

func TestAgentOnlyMACApprovalOverride(t *testing.T) {
	ts, h, s, _ := setupOrders(t)
	ctx := context.Background()
	actor, _ := enrollOrderActor(t, s, ts, "mac-actor")
	helloActor(t, actor, []proto.Capability{{Action: "isolate", TargetIDKinds: []string{"mac"}, Reversible: true, RevertAction: "unisolate"}})
	var dev int64
	err := s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
		var err error
		dev, err = tx.CreateDevice(inventory.Device{Name: "agent-host", Kind: proto.KindHost, Seen: s.now()})
		if err != nil {
			return err
		}
		for _, id := range []proto.Identifier{{Kind: "agent", Value: "host-agent", Strength: proto.Strong}, {Kind: "mac", Value: "00:11:22:33:44:55", Strength: proto.Strong}} {
			if err := tx.PutIdentifier(dev, id, "host-agent", s.now()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p := orderProposal(t, s, dev, "agent-only", "isolate", 60)
	plan(t, s)
	p, err = s.st.GetProposal(ctx, p.ID)
	wantReason := "target MAC only reported by the device's own agent — confirm with UniFi/scan data or approve again with override"
	if err != nil || p.State != "pending" || p.Reason != wantReason || p.OverrideAgentOnly {
		t.Fatal(p, err)
	}
	endpoint := fmt.Sprintf("%s/api/proposals/%d/approve", ts.URL, p.ID)
	if code := doJSON(t, h, "POST", endpoint, "", `{"override_agent_only":"yes"}`, nil); code != 400 {
		t.Fatal(code)
	}
	if code := doJSON(t, h, "POST", endpoint, "", `{"override_agent_only":true}`, &p); code != 200 || !p.OverrideAgentOnly {
		t.Fatal(code, p)
	}
	// Invalidation consumes the approval's override; ordinary reapproval must fail.
	if err = s.st.SetProposalOrderState(ctx, p.ID, "pending", "approve again", s.now()); err != nil {
		t.Fatal(err)
	}
	if code := doJSON(t, h, "POST", endpoint, "", `{}`, &p); code != 200 || p.OverrideAgentOnly {
		t.Fatal(code, p)
	}
	plan(t, s)
	p, _ = s.st.GetProposal(ctx, p.ID)
	if p.State != "pending" {
		t.Fatal(p)
	}
	if code := doJSON(t, h, "POST", endpoint, "", `{"override_agent_only":true}`, &p); code != 200 {
		t.Fatal(code)
	}
	plan(t, s)
	o := pollOrder(t, actor)
	if len(o.Targets) != 1 || o.Targets[0].Kind != "mac" {
		t.Fatal(o)
	}
	// A second proposal for the device never inherits the first override.
	q := orderProposal(t, s, dev, "second", "isolate", 60)
	plan(t, s)
	q, _ = s.st.GetProposal(ctx, q.ID)
	if q.State != "pending" || q.OverrideAgentOnly {
		t.Fatal(q)
	}
	// Independent confirmation followed by another agent report remains usable.
	if err = s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
		id := proto.Identifier{Kind: "mac", Value: "00:11:22:33:44:55", Strength: proto.Strong}
		if err := tx.PutIdentifier(dev, id, "unifi", s.now()); err != nil {
			return err
		}
		return tx.PutIdentifier(dev, id, "host-agent", s.now())
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.st.DecideProposal(ctx, q.ID, "approved", "admin", s.now()); err != nil {
		t.Fatal(err)
	}
	plan(t, s)
	q, _ = s.st.GetProposal(ctx, q.ID)
	if q.State != "ordered" || q.OverrideAgentOnly || !q.TargetReportedElsewhere["mac=00:11:22:33:44:55"] {
		t.Fatal(q)
	}
}

func TestApprovalViewSnapshotAndClaims(t *testing.T) {
	ts, h, s, now := setupOrders(t)
	ctx := context.Background()
	dev := orderDevice(t, s)
	p, _, err := s.st.UpsertProposal(ctx, store.Proposal{DeviceID: dev, VulnID: "review", Action: "block-port", State: "pending", Tier: "approve", Params: map[string]any{"ports": []string{"80/tcp"}}, CreatedAt: *now})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []store.Event{
		{At: now.Add(-24 * time.Hour), Type: "device.claimed", Actor: "<agent>", Data: fmt.Sprintf(`{"device_id":%d}`, dev)},
		{At: now.Add(-31 * 24 * time.Hour), Type: "device.claimed", Actor: "old", Data: fmt.Sprintf(`{"device_id":%d}`, dev)},
		{At: now.Add(-time.Hour), Type: "device.claimed", Actor: "other-device", Data: fmt.Sprintf(`{"device_id":%d}`, dev+1)},
	} {
		if err = s.st.AddEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	var ps []store.Proposal
	if code := doJSON(t, h, "GET", ts.URL+"/api/proposals?state=pending", "", "", &ps); code != 200 || len(ps) != 1 || len(ps[0].TargetSnapshot) != 1 || len(ps[0].RecentClaims) != 1 || ps[0].RecentClaims[0].Agent != "<agent>" || !ps[0].TargetReportedElsewhere["mac=00:11:22:33:44:55"] || ps[0].Params["ports"].([]any)[0] != "80/tcp" {
		t.Fatal(code, ps)
	}
	if err = s.st.DecideProposal(ctx, p.ID, "approved", "admin", *now); err != nil {
		t.Fatal(err)
	}
	if err = s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
		return tx.PutIdentifier(dev, proto.Identifier{Kind: "mac", Value: "aa:bb:cc:dd:ee:ff", Strength: proto.Strong}, "scan", *now)
	}); err != nil {
		t.Fatal(err)
	}
	if code := doJSON(t, h, "GET", ts.URL+"/api/proposals?state=approved", "", "", &ps); code != 200 || len(ps) != 1 || len(ps[0].TargetSnapshot) != 1 || len(ps[0].RecentClaims) != 1 {
		t.Fatal(code, ps)
	}
}
