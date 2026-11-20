package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	_ "github.com/JulianStremel/netnoodle/internal/actor/logactor"
	"github.com/JulianStremel/netnoodle/internal/client"
	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func setupOrders(t *testing.T) (*httptest.Server, *http.Client, *Server, *time.Time) {
	t.Helper()
	ts, h, pw, s := newTestServerS(t)
	key, e := LoadOrCreateOrderKey(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s.SetOrderKey(key)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	if post(t, h, ts.URL+"/api/login", "application/json", fmt.Sprintf(`{"user":"admin","password":%q}`, pw)).StatusCode != 200 {
		t.Fatal("login")
	}
	return ts, h, s, &now
}
func enrollOrderActor(t *testing.T, s *Server, ts *httptest.Server, name string) (*client.Client, client.Credentials) {
	t.Helper()
	ctx := context.Background()
	join := RandomToken(32)
	if _, e := s.st.CreateJoinToken(ctx, HashToken(join), store.RoleActor, name, 1, s.now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(ts.Certificate().Raw)
	creds, e := client.Enroll(ctx, ts.URL, hex.EncodeToString(hash[:]), join, name)
	if e != nil {
		t.Fatal(e)
	}
	if creds.OrderKey == "" || creds.Name != name {
		t.Fatal(creds)
	}
	cl, e := client.New(creds)
	if e != nil {
		t.Fatal(e)
	}
	return cl, creds
}
func orderDevice(t *testing.T, s *Server) int64 {
	t.Helper()
	var id int64
	e := s.st.InventoryTx(context.Background(), func(tx inventory.Tx) error {
		var e error
		id, e = tx.CreateDevice(inventory.Device{Name: "actor-target", Kind: proto.KindHost, Seen: s.now()})
		if e != nil {
			return e
		}
		for _, v := range []proto.Identifier{{Kind: "mac", Value: "00:11:22:33:44:55", Strength: proto.Strong}, {Kind: "ip", Value: "192.0.2.1", Strength: proto.Weak}} {
			if e = tx.PutIdentifier(id, v, "test", s.now()); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func orderProposal(t *testing.T, s *Server, device int64, vuln, action string, ttl int64) store.Proposal {
	t.Helper()
	ctx := context.Background()
	p, _, e := s.st.UpsertProposal(ctx, store.Proposal{DeviceID: device, VulnID: vuln, Action: action, State: "pending", Tier: "approve", TTL: ttl, CreatedAt: s.now()})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.st.DecideProposal(ctx, p.ID, "approved", "admin", s.now()); e != nil {
		t.Fatal(e)
	}
	return p
}
func logCaps(t *testing.T) []proto.Capability {
	t.Helper()
	b, e := actor.Registry.Build("log", "log", nil)
	if e != nil {
		t.Fatal(e)
	}
	return b.Capabilities()
}
func helloActor(t *testing.T, c *client.Client, caps []proto.Capability) {
	t.Helper()
	if e := c.Do(context.Background(), "POST", "/v1/actor/hello", proto.ActorHello{Version: proto.Version, Actor: "ignored-body-name", Capabilities: caps}, nil); e != nil {
		t.Fatal(e)
	}
}
func plan(t *testing.T, s *Server) {
	t.Helper()
	if e := s.planOrders(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func pollOrder(t *testing.T, c *client.Client) proto.Order {
	t.Helper()
	var envs []orders.Envelope
	if e := c.Do(context.Background(), "GET", "/v1/orders?wait=0", nil, &envs); e != nil || len(envs) != 1 {
		t.Fatal("poll", len(envs), e)
	}
	var o proto.Order
	if e := json.Unmarshal(envs[0].Payload, &o); e != nil {
		t.Fatal(e)
	}
	return o
}
func finish(t *testing.T, s *Server, c *client.Client, o proto.Order, status proto.OrderStatus) {
	t.Helper()
	if e := c.Do(context.Background(), "POST", "/v1/orders/result", proto.OrderResult{Version: proto.Version, OrderID: o.ID, Status: status, At: s.now(), Message: string(status)}, nil); e != nil {
		t.Fatal(e)
	}
}

func TestOrdersEndToEnd(t *testing.T) {
	ts, h, s, now := setupOrders(t)
	ctx := context.Background()
	cl, creds := enrollOrderActor(t, s, ts, "actor-a")
	other, _ := enrollOrderActor(t, s, ts, "actor-b")
	helloActor(t, cl, logCaps(t))
	dev := orderDevice(t, s)
	p := orderProposal(t, s, dev, "v1", "isolate", 60)
	// Register a waiting poller before planning to exercise the wake channel.
	envCh := make(chan []orders.Envelope, 1)
	errCh := make(chan error, 1)
	go func() {
		var envs []orders.Envelope
		e := cl.Do(ctx, "GET", "/v1/orders?wait=2", nil, &envs)
		envCh <- envs
		errCh <- e
	}()
	plan(t, s)
	envs := <-envCh
	if e := <-errCh; e != nil || len(envs) != 1 {
		t.Fatal(len(envs), e)
	}
	// Parse after signature verification using the pinned enrollment key.
	r, e := actor.NewRunner(actor.Config{NonceFile: filepath.Join(t.TempDir(), "nonces"), Backends: []registry.Spec{{Type: "log"}}, Allow: []actor.AllowRule{{Action: "isolate", Targets: []string{"mac=*", "ip=*"}}}}, creds)
	if e != nil {
		t.Fatal(e)
	}
	o, e := orders.Verify(r.Key, envs[0])
	if e != nil || o.Actor != "actor-a" || o.Targets[0].Strength != proto.Strong {
		t.Fatal(o, e)
	}
	if e = other.Do(ctx, "POST", "/v1/orders/result", proto.OrderResult{Version: proto.Version, OrderID: o.ID, Status: proto.OrderDone}, nil); e == nil || !strings.Contains(e.Error(), "404") {
		t.Fatal("wrong actor", e)
	}
	if e = cl.Do(ctx, "POST", "/v1/orders/result", proto.OrderResult{Version: proto.Version, OrderID: "unknown", Status: proto.OrderDone}, nil); e == nil || !strings.Contains(e.Error(), "404") {
		t.Fatal("unknown", e)
	}
	finish(t, s, cl, o, proto.OrderDone)
	saved, e := s.st.GetOrder(ctx, o.ID)
	if e != nil || !saved.RevertDueAt.Equal(now.Add(time.Minute)) {
		t.Fatal(saved, e)
	}
	proposal, _ := s.st.GetProposal(ctx, p.ID)
	if proposal.State != "done" {
		t.Fatal(proposal)
	}
	// Completed scopes survive another decision evaluation unchanged.
	updated, _, e := s.st.UpsertProposal(ctx, store.Proposal{DeviceID: dev, VulnID: "v1", Action: "isolate", State: "auto", Tier: "auto", TTL: 2, CreatedAt: *now})
	if e != nil || updated.State != "done" || updated.TTL != 60 {
		t.Fatal(updated, e)
	}
	if e = s.st.SetSetting(ctx, "decide.killswitch", "on"); e != nil {
		t.Fatal(e)
	}
	blocked := orderProposal(t, s, dev, "blocked", "snapshot", 0)
	*now = now.Add(time.Minute)
	plan(t, s)
	revert := pollOrder(t, cl)
	if !revert.Revert || revert.RevertOf != o.ID || revert.Action != "unisolate" || revert.TTL != 0 {
		t.Fatal(revert)
	}
	finish(t, s, cl, revert, proto.OrderDone)
	proposal, _ = s.st.GetProposal(ctx, p.ID)
	if proposal.State != "reverted" {
		t.Fatal(proposal)
	}
	saved, _ = s.st.GetOrder(ctx, o.ID)
	if !saved.Reverted {
		t.Fatal("not marked reverted")
	}
	proposal, _ = s.st.GetProposal(ctx, blocked.ID)
	if proposal.State != "approved" {
		t.Fatal("kill switch", proposal)
	}
	res, e := h.Get(ts.URL + "/api/info")
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	var info map[string]string
	_ = json.NewDecoder(res.Body).Decode(&info)
	if info["order_key"] != creds.OrderKey || len(info["order_key_fingerprint"]) != 64 {
		t.Fatal(info)
	}
}

func TestNoActorAndHelloRetry(t *testing.T) {
	ts, _, s, _ := setupOrders(t)
	dev := orderDevice(t, s)
	p := orderProposal(t, s, dev, "none", "isolate", 10)
	plan(t, s)
	got, _ := s.st.GetProposal(context.Background(), p.ID)
	if got.State != "no-actor" {
		t.Fatal(got)
	}
	c, _ := enrollOrderActor(t, s, ts, "late")
	helloActor(t, c, logCaps(t))
	plan(t, s)
	o := pollOrder(t, c)
	if o.Action != "isolate" {
		t.Fatal(o)
	}
}

func TestOrderRevertRetryAndResolution(t *testing.T) {
	ts, _, s, now := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "reverter")
	helloActor(t, c, logCaps(t))
	dev := orderDevice(t, s)
	p := orderProposal(t, s, dev, "fixed", "isolate", 3600)
	plan(t, s)
	o := pollOrder(t, c)
	finish(t, s, c, o, proto.OrderDone)
	if e := s.st.ResolveProposals(ctx, dev, nil); e != nil {
		t.Fatal(e)
	}
	plan(t, s)
	revert := pollOrder(t, c)
	for attempt := 1; attempt <= 6; attempt++ {
		finish(t, s, c, revert, proto.OrderFailed)
		plan(t, s)
		var empty []orders.Envelope
		if e := c.Do(ctx, "GET", "/v1/orders?wait=0", nil, &empty); e != nil || len(empty) != 0 {
			t.Fatal("early retry", e)
		}
		*now = now.Add(10 * time.Minute)
		plan(t, s)
		if attempt < 6 {
			revert = pollOrder(t, c)
		}
	}
	all, e := s.st.ListOrders(ctx, store.OrderFilter{ProposalID: p.ID})
	if e != nil || len(all) != 7 {
		t.Fatal(len(all), e)
	}
	events, _ := s.st.ListEvents(ctx, 100)
	critical := 0
	for _, ev := range events {
		if strings.Contains(ev.Data, `"severity":"critical"`) {
			critical++
		}
	}
	if critical != 6 {
		t.Fatal("critical events", critical)
	}
}

func TestOrdersExpireAndManualRevert(t *testing.T) {
	ts, h, s, now := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "manual")
	helloActor(t, c, logCaps(t))
	dev := orderDevice(t, s)
	p := orderProposal(t, s, dev, "expire", "snapshot", 0)
	plan(t, s)
	*now = now.Add(10 * time.Minute)
	plan(t, s)
	got, _ := s.st.GetProposal(ctx, p.ID)
	if got.State != "failed" || got.Reason != "order expired" {
		t.Fatal(got)
	}
	orderProposal(t, s, dev, "manual", "isolate", 0)
	plan(t, s)
	o := pollOrder(t, c)
	finish(t, s, c, o, proto.OrderDone)
	if code := post(t, h, ts.URL+"/api/orders/"+o.ID+"/revert", "application/json", "{}").StatusCode; code != 202 {
		t.Fatal(code)
	}
	plan(t, s)
	r := pollOrder(t, c)
	if !r.Revert {
		t.Fatal(r)
	}
	finish(t, s, c, r, proto.OrderDone)
}

type reportingActorClient struct {
	*client.Client
	results chan proto.OrderResult
}

func (c reportingActorClient) Do(ctx context.Context, method, path string, in, out any) error {
	err := c.Client.Do(ctx, method, path, in, out)
	if err == nil && path == "/v1/orders/result" {
		c.results <- in.(proto.OrderResult)
	}
	return err
}

func TestActorRunAgainstServer(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(fmt.Sprint("allow=", allow), func(t *testing.T) {
			ts, _, s, _ := setupOrders(t)
			c, creds := enrollOrderActor(t, s, ts, "runner")
			dev := orderDevice(t, s)
			p := orderProposal(t, s, dev, "runtime", "isolate", 60)
			cfg := actor.Config{NonceFile: filepath.Join(t.TempDir(), "nonces"), Backends: []registry.Spec{
				{Type: "log", Name: "mac", Settings: json.RawMessage(`{"target_id_kinds":["mac"]}`)},
				{Type: "log", Name: "ip", Settings: json.RawMessage(`{"target_id_kinds":["ip"]}`)},
			}}
			if allow {
				cfg.Allow = []actor.AllowRule{{Action: "isolate", Targets: []string{"mac=*", "ip=*"}}}
			}
			r, err := actor.NewRunner(cfg, creds)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			workerDone := make(chan struct{})
			go func() { defer close(workerDone); s.RunPlanner(ctx) }()
			reports := reportingActorClient{c, make(chan proto.OrderResult, 1)}
			runDone := make(chan error, 1)
			go func() { runDone <- r.Run(ctx, reports) }()
			defer func() { cancel(); <-runDone; <-workerDone }()
			select {
			case result := <-reports.results:
				want := proto.OrderRejected
				state := "failed"
				if allow {
					want = proto.OrderDone
					state = "done"
					if !strings.HasPrefix(result.Message, "dry run: would isolate") {
						t.Fatal(result)
					}
				}
				if result.Status != want {
					t.Fatal(result)
				}
				got, err := s.st.GetProposal(context.Background(), p.ID)
				if err != nil || got.State != state {
					t.Fatal(got, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("actor did not complete an order")
			}
		})
	}
}

func TestPlannerActorPreference(t *testing.T) {
	for _, mode := range []string{"strong", "tie", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			ts, _, s, _ := setupOrders(t)
			first, _ := enrollOrderActor(t, s, ts, "first")
			second, _ := enrollOrderActor(t, s, ts, "second")
			kinds := []string{"mac"}
			if mode == "strong" {
				kinds = []string{"ip"}
			}
			helloActor(t, first, []proto.Capability{{Action: "isolate", TargetIDKinds: kinds, Reversible: true, RevertAction: "unisolate"}})
			helloActor(t, second, []proto.Capability{{Action: "isolate", TargetIDKinds: []string{"mac"}, Reversible: true, RevertAction: "unisolate"}})
			actors, _ := s.st.ListActors(context.Background())
			if mode == "disabled" {
				if err := s.st.SetPeerDisabled(context.Background(), actors[0].Peer.ID, true); err != nil {
					t.Fatal(err)
				}
			}
			dev := orderDevice(t, s)
			orderProposal(t, s, dev, "selection", "isolate", 60)
			plan(t, s)
			chosen := second
			name := "second"
			if mode == "tie" {
				chosen = first
				name = "first"
			}
			o := pollOrder(t, chosen)
			if o.Actor != name {
				t.Fatal(o)
			}
		})
	}
}

func TestActorHelloValidationAndOrderTransitions(t *testing.T) {
	ts, _, s, now := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "validation")
	for _, caps := range [][]proto.Capability{
		{{Action: "unknown", TargetIDKinds: []string{"mac"}}},
		{{Action: "snapshot", TargetIDKinds: make([]string, 17)}},
		make([]proto.Capability, 65),
	} {
		if err := c.Do(ctx, "POST", "/v1/actor/hello", proto.ActorHello{Version: proto.Version, Capabilities: caps}, nil); err == nil || !strings.Contains(err.Error(), "400") {
			t.Fatal("invalid hello accepted", err)
		}
	}
	helloActor(t, c, logCaps(t))
	helloActor(t, c, nil)
	actors, err := s.st.ListActors(ctx)
	if err != nil || len(actors) != 1 || actors[0].Capabilities == nil || len(actors[0].Capabilities) != 0 {
		t.Fatal(actors, err)
	}
	helloActor(t, c, []proto.Capability{{Action: "snapshot", TargetIDKinds: []string{"mac"}}})
	actors, err = s.st.ListActors(ctx)
	if err != nil || len(actors) != 1 || len(actors[0].Capabilities) != 1 {
		t.Fatal(actors, err)
	}
	dev := orderDevice(t, s)
	p := orderProposal(t, s, dev, "states", "snapshot", 0)
	plan(t, s)
	os, err := s.st.ListOrders(ctx, store.OrderFilter{ProposalID: p.ID})
	if err != nil || len(os) != 1 {
		t.Fatal(os, err)
	}
	result := proto.OrderResult{Version: proto.Version, OrderID: os[0].ID, Status: proto.OrderDone}
	if err = c.Do(ctx, "POST", "/v1/orders/result", result, nil); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatal("queued result", err)
	}
	o := pollOrder(t, c)
	finish(t, s, c, o, proto.OrderDone)
	if err = c.Do(ctx, "POST", "/v1/orders/result", result, nil); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatal("duplicate result", err)
	}
	orderProposal(t, s, dev, "late", "snapshot", 0)
	plan(t, s)
	late := pollOrder(t, c)
	*now = now.Add(10 * time.Minute)
	if err = c.Do(ctx, "POST", "/v1/orders/result", proto.OrderResult{Version: proto.Version, OrderID: late.ID, Status: proto.OrderDone}, nil); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatal("expired result", err)
	}
}

func TestOrdersSurviveInventoryMerge(t *testing.T) {
	ts, _, s, _ := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "merge")
	helloActor(t, c, logCaps(t))
	drop := orderDevice(t, s)
	p := orderProposal(t, s, drop, "merge-vuln", "isolate", 60)
	plan(t, s)
	o := pollOrder(t, c)
	finish(t, s, c, o, proto.OrderDone)
	var keep int64
	if err := s.st.InventoryTx(ctx, func(tx inventory.Tx) error {
		var err error
		keep, err = tx.CreateDevice(inventory.Device{Name: "destination", Kind: proto.KindHost, Seen: s.now()})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.st.UpsertProposal(ctx, store.Proposal{DeviceID: keep, VulnID: "merge-vuln", Action: "isolate", State: "notify", Tier: "notify", CreatedAt: s.now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.st.InventoryTx(ctx, func(tx inventory.Tx) error { return tx.Merge(keep, drop) }); err != nil {
		t.Fatal(err)
	}
	got, err := s.st.GetProposal(ctx, p.ID)
	if err != nil || got.DeviceID != keep || got.State != "done" {
		t.Fatal(got, err)
	}
	if _, err = s.st.GetOrder(ctx, o.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.st.ResolveProposals(ctx, keep, nil); err != nil {
		t.Fatal(err)
	}
	plan(t, s)
	r := pollOrder(t, c)
	if r.RevertOf != o.ID {
		t.Fatal(r)
	}
}

func TestResolutionBeforeOrderResult(t *testing.T) {
	ts, _, s, now := setupOrders(t)
	ctx := context.Background()
	c, _ := enrollOrderActor(t, s, ts, "early")
	helloActor(t, c, logCaps(t))
	dev := orderDevice(t, s)
	p := orderProposal(t, s, dev, "early", "isolate", 0)
	plan(t, s)
	o := pollOrder(t, c)
	if err := s.st.ResolveProposals(ctx, dev, nil); err != nil {
		t.Fatal(err)
	}
	finish(t, s, c, o, proto.OrderDone)
	got, err := s.st.GetProposal(ctx, p.ID)
	if err != nil || got.State != "done" {
		t.Fatal(got, err)
	}
	saved, err := s.st.GetOrder(ctx, o.ID)
	if err != nil || !saved.RevertDueAt.Equal(*now) {
		t.Fatal(saved, err)
	}
	plan(t, s)
	r := pollOrder(t, c)
	if !r.Revert || r.RevertOf != o.ID {
		t.Fatal(r)
	}
}
