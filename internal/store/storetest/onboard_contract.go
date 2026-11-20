package storetest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

func testOnboarding(t *testing.T, open func(*testing.T) store.Store) {
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	hash := func(v string) []byte { h := sha256.Sum256([]byte(v)); return h[:] }
	newSession := func(t *testing.T, st store.Store, id, kind string) store.OnboardSession {
		t.Helper()
		o := store.OnboardSession{ID: id, SecretHash: hash("secret-" + id), Name: id, Kind: kind, Platform: "linux", Expires: now.Add(30 * time.Minute)}
		role := store.RoleAgent
		if kind == "scan" {
			role = store.RoleSource
		}
		if kind == "actor-host" {
			role = store.RoleActor
		}
		if err := st.CreateOnboard(ctx, o, hash("join-"+id), role, now); err != nil {
			t.Fatal(err)
		}
		return o
	}
	get := func(t *testing.T, st store.Store, id, state string) store.OnboardSession {
		t.Helper()
		o, err := st.GetOnboard(ctx, id)
		if err != nil || o.State != state {
			t.Fatalf("session %s: %+v, %v; want %s", id, o, err, state)
		}
		return o
	}
	t.Run("state machine and history", func(t *testing.T) {
		st := open(t)
		o := newSession(t, st, "agent-one", "agent")
		get(t, st, o.ID, "created")
		if err := st.AddOnboardStep(ctx, o.ID, store.OnboardStep{Name: "done", OK: true, At: now}); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("done before connected: %v", err)
		}
		p, err := st.Enroll(ctx, hash("join-"+o.ID), "wrong-name", hash("peer-one"), now, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name != o.Name || p.Role != store.RoleAgent {
			t.Fatalf("not name and role bound: %+v", p)
		}
		if got := get(t, st, o.ID, "enrolled"); got.PeerID != p.ID {
			t.Fatalf("peer id: %+v", got)
		}
		if _, err = st.Enroll(ctx, hash("join-"+o.ID), o.Name, hash("peer-two"), now, nil); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("token reused: %v", err)
		}
		if err = st.ConnectOnboard(ctx, p.ID, now); err != nil {
			t.Fatal(err)
		}
		get(t, st, o.ID, "connected")
		if err = st.AddOnboardStep(ctx, o.ID, store.OnboardStep{Name: "done", OK: true, At: now}); err != nil {
			t.Fatal(err)
		}
		if err = st.ConnectOnboard(ctx, p.ID, now); err != nil {
			t.Fatal(err)
		}
		get(t, st, o.ID, "done")
		if err = st.AbortOnboard(ctx, o.ID, "late", now); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("abort done: %v", err)
		}
		if err = st.ExpireOnboard(ctx, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		get(t, st, o.ID, "done")
		if err = st.ExpireOnboard(ctx, now.Add(7*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err = st.GetOnboard(ctx, o.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("history retained too long: %v", err)
		}
		if _, err = st.PeerByToken(ctx, hash("peer-one")); err != nil {
			t.Fatalf("done peer removed: %v", err)
		}
	})
	t.Run("abort and expiry revoke only their peers", func(t *testing.T) {
		for _, enrolled := range []bool{false, true} {
			for _, abort := range []bool{false, true} {
				st := open(t)
				o := newSession(t, st, "scan-one", "scan")
				other := newSession(t, st, "agent-two", "agent")
				if enrolled {
					if _, err := st.Enroll(ctx, hash("join-"+o.ID), o.Name, hash("peer-one"), now, nil); err != nil {
						t.Fatal(err)
					}
				}
				state := "expired"
				if abort {
					state = "aborted"
					if err := st.AbortOnboard(ctx, o.ID, "test failure", now); err != nil {
						t.Fatal(err)
					}
				} else {
					// Keep the unrelated installation alive beyond this expiry tick.
					otherPeer, err := st.Enroll(ctx, hash("join-"+other.ID), other.Name, hash("other-peer"), now, nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := st.ConnectOnboard(ctx, otherPeer.ID, now); err != nil {
						t.Fatal(err)
					}
					// Both expire together; a separate ordinary peer must still remain.
					if _, err := st.CreateJoinToken(ctx, hash("ordinary-join"), store.RoleAgent, "ordinary", 1, now.Add(time.Hour)); err != nil {
						t.Fatal(err)
					}
					if _, err := st.Enroll(ctx, hash("ordinary-join"), "ordinary", hash("ordinary-peer"), now, nil); err != nil {
						t.Fatal(err)
					}
					if err := st.ExpireOnboard(ctx, o.Expires); err != nil {
						t.Fatal(err)
					}
					if _, err := st.PeerByToken(ctx, hash("ordinary-peer")); err != nil {
						t.Fatalf("unrelated peer removed: %v", err)
					}
				}
				get(t, st, o.ID, state)
				if _, err := st.PeerByToken(ctx, hash("peer-one")); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("peer still usable: %v", err)
				}
				if _, err := st.Enroll(ctx, hash("join-"+o.ID), o.Name, hash("new-peer"), now, nil); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("token still usable: %v", err)
				}
				if err := st.AbortOnboard(ctx, o.ID, "again", now); err != nil {
					t.Fatal(err)
				}
				if abort {
					get(t, st, other.ID, "created")
				}
			}
		}
	})
	t.Run("limits are atomic", func(t *testing.T) {
		st := open(t)
		for i := 0; i < 20; i++ {
			newSession(t, st, fmt.Sprintf("peer-%02d", i), "agent")
		}
		o := store.OnboardSession{ID: "overflow", SecretHash: hash("secret"), Name: "overflow", Kind: "agent", Platform: "linux", Expires: now.Add(30 * time.Minute)}
		if err := st.CreateOnboard(ctx, o, hash("overflow"), store.RoleAgent, now); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("21st session: %v", err)
		}
		tokens, err := st.ListJoinTokens(ctx, now)
		if err != nil || len(tokens) != 20 {
			t.Fatalf("partial token created: %d, %v", len(tokens), err)
		}
		for i := 0; i < 64; i++ {
			if err = st.AddOnboardStep(ctx, "peer-00", store.OnboardStep{Name: "test", OK: true, At: now}); err != nil {
				t.Fatal(err)
			}
		}
		if err = st.AddOnboardStep(ctx, "peer-00", store.OnboardStep{Name: "overflow", At: now}); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("65th step: %v", err)
		}
		if err = st.AddOnboardStep(ctx, "peer-01", store.OnboardStep{Name: "late", At: o.Expires}); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("expired step: %v", err)
		}
		if err = st.AbortOnboard(ctx, "peer-00", "test", now); err != nil {
			t.Fatal(err)
		}
		if err = st.CreateOnboard(ctx, o, hash("overflow"), store.RoleAgent, now); err != nil {
			t.Fatalf("slot not freed: %v", err)
		}
	})
	t.Run("tokens expire exactly after thirty minutes", func(t *testing.T) {
		st := open(t)
		o := newSession(t, st, "expires-unconsumed", "actor-host")
		tokens, err := st.ListJoinTokens(ctx, now)
		if err != nil || len(tokens) != 1 || tokens[0].Expires != now.Add(30*time.Minute) || tokens[0].UsesLeft != 1 || tokens[0].Name != o.Name || tokens[0].Role != store.RoleActor {
			t.Fatalf("bound token: %+v %v", tokens, err)
		}
		if _, err := st.Enroll(ctx, hash("join-"+o.ID), o.Name, hash("late-peer"), o.Expires, nil); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("token usable at expiry: %v", err)
		}
		get(t, st, o.ID, "created")
		if err := st.ConnectOnboard(ctx, 0, now); err != nil {
			t.Fatal(err)
		}
		get(t, st, o.ID, "created")
	})
	t.Run("pull pairing is scoped and expires", func(t *testing.T) {
		st := open(t)
		o := newSession(t, st, "pull-one", "agent-pull")
		if err := st.PairOnboard(ctx, o.ID, "host:7444", "code", now); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("pair before enroll: %v", err)
		}
		p, err := st.Enroll(ctx, hash("join-"+o.ID), o.Name, hash("push-token"), now, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = st.PairOnboard(ctx, o.ID, "host:7444", "code", now); err != nil {
			t.Fatal(err)
		}
		if _, err = st.PeerByToken(ctx, hash("push-token")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("pull bearer still usable: %v", err)
		}
		pp, err := st.GetPullPeer(ctx, p.ID)
		if err != nil || pp.PairExpires != o.Expires {
			t.Fatalf("pair expiry: %+v %v", pp, err)
		}
		if err = st.AbortOnboard(ctx, o.ID, "test", now); err != nil {
			t.Fatal(err)
		}
		if _, err = st.GetPullPeer(ctx, p.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("pull peer remains: %v", err)
		}
	})
}
