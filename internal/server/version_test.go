package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
	"github.com/JulianStremel/netnoodle/internal/version"
)

func TestActorVersionWindowAndRecovery(t *testing.T) {
	previous := version.Version
	version.Version = "v0.5.0"
	defer func() { version.Version = previous }()
	ts, h, s, now := setupOrders(t)
	ctx := context.Background()
	cl, creds := enrollOrderActor(t, s, ts, "version-actor")
	oldHello := struct {
		proto.ActorHello
		ActorVersion string `json:"actor_version"`
	}{proto.ActorHello{Version: proto.Version, Capabilities: logCaps(t)}, "v0.3.9"}
	b, err := json.Marshal(oldHello)
	if err != nil {
		t.Fatal(err)
	}
	if code := doJSON(t, h, "POST", ts.URL+"/v1/actor/hello", creds.Token, string(b), nil); code != 200 {
		t.Fatal(code)
	}
	p, err := s.st.PeerByToken(ctx, HashToken(creds.Token))
	if err != nil || p.Version != "v0.3.9" {
		t.Fatal(p, err)
	}
	dev := orderDevice(t, s)
	proposal := orderProposal(t, s, dev, "old", "isolate", 60)
	plan(t, s)
	got, err := s.st.GetProposal(ctx, proposal.ID)
	if err != nil || got.State != "no-actor" || got.Reason != "actor version too old" {
		t.Fatal(got, err)
	}
	var peers []struct {
		store.Peer
		Outdated bool `json:"outdated"`
	}
	if code := doJSON(t, h, "GET", ts.URL+"/api/peers", "", "", &peers); code != 200 || len(peers) != 1 || peers[0].Version != "v0.3.9" || !peers[0].Outdated {
		t.Fatal(code, peers)
	}
	var info map[string]string
	if code := doJSON(t, h, "GET", ts.URL+"/api/info", "", "", &info); code != 200 || info["version"] != version.Version || info["protocol"] != version.Protocol {
		t.Fatal(code, info)
	}
	// Current hello makes the actor eligible and the queued order is delivered.
	helloActor(t, cl, logCaps(t))
	plan(t, s)
	o := pollOrder(t, cl)
	finish(t, s, cl, o, proto.OrderDone)
	// A previously queued forward order must also be withheld after downgrade.
	queued := orderProposal(t, s, dev, "queued", "snapshot", 0)
	plan(t, s)
	if err := s.st.SetPeerVersion(ctx, p.ID, "v0.3.0"); err != nil {
		t.Fatal(err)
	}
	var envs []orders.Envelope
	if code := doJSON(t, h, "GET", ts.URL+"/v1/orders?wait=0", creds.Token, "", &envs); code != 200 || len(envs) != 0 {
		t.Fatal(code, envs)
	}
	*now = now.Add(time.Minute)
	plan(t, s)
	if code := doJSON(t, h, "GET", ts.URL+"/v1/orders?wait=0", creds.Token, "", &envs); code != 200 || len(envs) != 1 {
		t.Fatal(code, envs)
	}
	if _, err := orders.Verify(s.orders.key.Public().(ed25519.PublicKey), envs[0]); err != nil {
		t.Fatal(err)
	}
	var recovery proto.Order
	if err := json.Unmarshal(envs[0].Payload, &recovery); err != nil || !recovery.Revert || recovery.RevertOf != o.ID {
		t.Fatal(recovery, err)
	}
	q, err := s.st.GetProposal(ctx, queued.ID)
	if err != nil || q.State != "ordered" {
		t.Fatal(q, err)
	}
}
