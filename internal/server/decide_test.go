package server

import (
	"context"
	"fmt"
	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
	"strings"
	"testing"
	"time"
)

type captureDecider struct {
	calls int
	first decide.Situation
}

func (d *captureDecider) Name() string { return "capture" }
func (d *captureDecider) Decide(_ context.Context, s decide.Situation) (decide.Proposal, bool, error) {
	if d.calls == 0 {
		d.first = s
	}
	d.calls++
	return decide.Proposal{Tier: decide.TierNone}, true, nil
}
func TestMatchEvaluationBoundAndContext(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	ctx := context.Background()
	now := time.Now()
	var id int64
	if e := s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
		var e error
		id, e = tx.CreateDevice(inventory.Device{Name: "host", Kind: proto.KindHost, Seen: now})
		if e != nil {
			return e
		}
		if e = tx.PutIdentifier(id, proto.Identifier{Kind: "ip", Value: "10.1.2.3", Strength: proto.Weak}, "test", now); e != nil {
			return e
		}
		if e = tx.PutComponents(id, "test", []proto.Component{{PURL: "pkg:generic/a@1", Name: "a", Version: "1"}}, true, now); e != nil {
			return e
		}
		return tx.PutServices(id, "test", []proto.Service{{Port: 80, Proto: "tcp", Address: "0.0.0.0", Component: "pkg:generic/a@1"}, {Port: 81, Proto: "tcp", Address: "127.0.0.1", Component: "pkg:generic/a@1"}}, true, now)
	}); e != nil {
		t.Fatal(e)
	}
	if e := s.st.SetTags(ctx, id, []string{"auto", "lan"}); e != nil {
		t.Fatal(e)
	}
	vs := []intel.Vuln{}
	for i := range maxEvaluationsPerDevice + 5 {
		vs = append(vs, intel.Vuln{ID: fmt.Sprintf("CVE-%d", i), Score: 8, KEV: true})
	}
	fm := &fakeMatcher{vulns: map[string][]intel.Vuln{"a": vs}}
	d := &captureDecider{}
	s.SetIntel([]intel.Matcher{fm}, nil)
	s.SetDecide([]decide.Decider{d}, nil)
	if e := s.MatchDevice(ctx, id); e != nil {
		t.Fatal(e)
	}
	if d.calls != maxEvaluationsPerDevice {
		t.Fatal(d.calls)
	}
	v := d.first
	if v.Device.ID != id || !v.Device.Exposed || len(v.Device.Ports) != 1 || v.Device.Ports[0] != 80 || len(v.Device.Tags) != 2 || len(v.Networks) != 1 || v.Networks[0] != "10.1.2.0/24" || v.Confidence != "high" {
		t.Fatalf("situation %+v", v)
	}
	d.calls = 0
	if e := s.MatchDevice(ctx, id); e != nil {
		t.Fatal(e)
	}
	if d.calls != 0 {
		t.Fatal("unchanged findings evaluated again")
	}
	if e := s.reevaluate(ctx); e != nil {
		t.Fatal(e)
	}
	if d.calls != maxEvaluationsPerDevice {
		t.Fatal("reevaluation bound", d.calls)
	}
}

type captureNotifier struct{ ch chan notify.Event }

func (n captureNotifier) Name() string                                   { return "capture" }
func (n captureNotifier) Notify(_ context.Context, e notify.Event) error { n.ch <- e; return nil }
func TestProposalNotificationBatch(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	b := newProposalBatch()
	n := captureNotifier{make(chan notify.Event, 2)}
	s.SetNotifiers([]notify.Notifier{n})
	for range 21 {
		b.add(store.Proposal{State: "pending"})
		b.add(store.Proposal{State: "notify"})
	}
	if len(b.samples["pending"]) != 20 {
		t.Fatal("unbounded details")
	}
	s.emitProposalBatch(context.Background(), b)
	for range 2 {
		select {
		case e := <-n.ch:
			if e.Link != "#/actions" || !strings.Contains(e.Title, "21") {
				t.Fatal(e)
			}
			if e.Type == "proposal.pending" && e.Severity != "warning" || e.Type == "proposal.notify" && e.Severity != "info" {
				t.Fatal(e)
			}
		case <-time.After(time.Second):
			t.Fatal("missing notification")
		}
	}
	evs, e := s.st.ListEvents(context.Background(), 100)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, ev := range evs {
		if strings.HasPrefix(ev.Type, "proposal.") {
			count++
		}
	}
	if count != 2 {
		t.Fatal(count)
	}
}
