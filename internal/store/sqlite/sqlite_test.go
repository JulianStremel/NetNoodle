package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"netnoodle/internal/store"
)

func open(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestUsersAndSessions(t *testing.T) {
	ctx := context.Background()
	db := open(t)

	if n, err := db.CountUsers(ctx); err != nil || n != 0 {
		t.Fatalf("CountUsers = %d, %v", n, err)
	}
	id, err := db.CreateUser(ctx, "admin", []byte("h"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(ctx, "admin", []byte("h")); err == nil {
		t.Fatal("duplicate user accepted")
	}
	u, err := db.UserByName(ctx, "admin")
	if err != nil || u.ID != id {
		t.Fatalf("UserByName = %+v, %v", u, err)
	}
	if _, err := db.UserByName(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user err = %v", err)
	}

	now := time.Now()
	tok := []byte("tokenhash")
	if err := db.CreateSession(ctx, []byte("other"), id, []byte("stale"), now.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("session with a stale password hash: err = %v", err)
	}
	if err := db.CreateSession(ctx, tok, id, u.PassHash, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if u, err := db.SessionUser(ctx, tok, now); err != nil || u.Name != "admin" {
		t.Fatalf("SessionUser = %+v, %v", u, err)
	}
	if _, err := db.SessionUser(ctx, tok, now.Add(2*time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session err = %v", err)
	}
	if err := db.DeleteSession(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SessionUser(ctx, tok, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted session err = %v", err)
	}
}

func TestMigrateTwice(t *testing.T) {
	db := open(t)
	if err := db.migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
}
