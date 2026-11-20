package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

func TestOnboardRollbackAtomic(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "abort", true: "expiry"}[expire], func(t *testing.T) {
			ctx := context.Background()
			db, err := Open(ctx, ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			now := time.Now().UTC()
			hash := make([]byte, 32)
			o := store.OnboardSession{ID: "atomic-session", Name: "atomic-peer", Kind: "agent", Platform: "linux", SecretHash: hash, Expires: now.Add(30 * time.Minute)}
			if err = db.CreateOnboard(ctx, o, hash, store.RoleAgent, now); err != nil {
				t.Fatal(err)
			}
			peerHash := append([]byte{1}, hash[1:]...)
			if _, err = db.Enroll(ctx, hash, o.Name, peerHash, now, nil); err != nil {
				t.Fatal(err)
			}
			// Fail after deleting the peer, at token revocation. Neither the
			// deletion nor the state change may escape the transaction.
			if _, err = db.db.Exec(`CREATE TRIGGER fail_revoke BEFORE UPDATE OF uses_left ON join_tokens BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
				t.Fatal(err)
			}
			rollback := func() error {
				if expire {
					return db.ExpireOnboard(ctx, o.Expires)
				}
				return db.AbortOnboard(ctx, o.ID, "failure", now)
			}
			if err = rollback(); err == nil {
				t.Fatal("injected failure was ignored")
			}
			if _, err = db.PeerByToken(ctx, peerHash); err != nil {
				t.Fatalf("partial peer deletion: %v", err)
			}
			saved, err := db.GetOnboard(ctx, o.ID)
			if err != nil || saved.State != "enrolled" || saved.PeerID == 0 {
				t.Fatalf("partial state change: %+v %v", saved, err)
			}
			if _, err = db.db.Exec(`DROP TRIGGER fail_revoke`); err != nil {
				t.Fatal(err)
			}
			if err = rollback(); err != nil {
				t.Fatal(err)
			}
			if _, err = db.PeerByToken(ctx, peerHash); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("peer survived rollback: %v", err)
			}
		})
	}
}

func TestOnboardDoesNotOwnReusedIDs(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	hash := make([]byte, 32)
	o := store.OnboardSession{ID: "old-session", Name: "old-peer", Kind: "agent", Platform: "linux", SecretHash: hash, Expires: now.Add(30 * time.Minute)}
	if err = db.CreateOnboard(ctx, o, hash, store.RoleAgent, now); err != nil {
		t.Fatal(err)
	}
	p, err := db.Enroll(ctx, hash, o.Name, hash, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	old, err := db.GetOnboard(ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.db.Exec(`DELETE FROM peers WHERE id=?`, p.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteJoinToken(ctx, old.JoinID); err != nil {
		t.Fatal(err)
	}
	newJoin, err := db.CreateJoinToken(ctx, hash, store.RoleAgent, "unrelated", 2, o.Expires)
	if err != nil || newJoin != old.JoinID {
		t.Fatalf("test did not reuse token ID: %d %v", newJoin, err)
	}
	newPeer, err := db.Enroll(ctx, hash, "unrelated", hash, now, nil)
	if err != nil || newPeer.ID != p.ID {
		t.Fatalf("test did not reuse peer ID: %+v %v", newPeer, err)
	}
	if err = db.AbortOnboard(ctx, o.ID, "old installer failed", now); err != nil {
		t.Fatal(err)
	}
	if got, err := db.PeerByToken(ctx, hash); err != nil || got.Name != "unrelated" {
		t.Fatalf("old session deleted an unrelated peer: %+v %v", got, err)
	}
	var uses int
	if err = db.db.QueryRow(`SELECT uses_left FROM join_tokens WHERE id=?`, newJoin).Scan(&uses); err != nil || uses != 1 {
		t.Fatalf("new token: %d %v", uses, err)
	}
}
