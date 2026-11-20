package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// raceCalls releases all contenders together and checks every outcome.
func raceCalls(t *testing.T, n int, call func(int) error, loser error) {
	t.Helper()
	start := make(chan struct{})
	results := make(chan error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { <-start; results <- call(i) })
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, loser) {
			t.Fatalf("unexpected competing operation error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("got %d successful contenders, want exactly one", wins)
	}
}

func testPasswordChangeDeletesSessions(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	id, err := st.CreateUser(ctx, "alice", []byte("old"))
	must(t, err)
	for _, token := range []string{"one", "two"} {
		must(t, st.CreateSession(ctx, []byte(token), id, []byte("old"), now.Add(time.Hour)))
	}
	must(t, st.SetPassword(ctx, id, []byte("new")))
	for _, token := range []string{"one", "two"} {
		if _, err := st.SessionUser(ctx, []byte(token), now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("session survived password change: %v", err)
		}
	}
	if err := st.CreateSession(ctx, []byte("stale"), id, []byte("old"), now.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale password accepted: %v", err)
	}
	must(t, st.CreateSession(ctx, []byte("fresh"), id, []byte("new"), now.Add(time.Hour)))
	// Either ordering of a racing login and password change must end without
	// a session authenticated by the old hash.
	start := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		<-start
		result <- st.CreateSession(ctx, []byte("racing"), id, []byte("new"), now.Add(time.Hour))
	}()
	close(start)
	must(t, st.SetPassword(ctx, id, []byte("newest")))
	if err := <-result; err != nil && !errors.Is(err, store.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := st.SessionUser(ctx, []byte("racing"), now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("racing stale session survived: %v", err)
	}
}

func testEnrollmentAtomicity(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	_, err := st.CreateJoinToken(ctx, []byte("join"), store.RoleAgent, "", 2, now.Add(time.Hour))
	must(t, err)
	denied := errors.New("policy denied")
	_, err = st.Enroll(ctx, []byte("join"), "denied", []byte("denied"), now, func(name string) error {
		if name != "denied" {
			t.Errorf("allow received %q", name)
		}
		return denied
	})
	if !errors.Is(err, denied) {
		t.Fatalf("allow error: %v", err)
	}
	joins, err := st.ListJoinTokens(ctx, now)
	must(t, err)
	if len(joins) != 1 || joins[0].UsesLeft != 2 {
		t.Fatalf("denial consumed token: %+v", joins)
	}
	p, err := st.Enroll(ctx, []byte("join"), "alice", []byte("alice"), now, nil)
	must(t, err)
	if p.Role != store.RoleAgent || p.Name != "alice" {
		t.Fatal(p)
	}
	_, err = st.Enroll(ctx, []byte("join"), "alice", []byte("duplicate"), now, nil)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	joins, err = st.ListJoinTokens(ctx, now)
	must(t, err)
	if len(joins) != 1 || joins[0].UsesLeft != 1 {
		t.Fatalf("uses after successful/failed enrollment: %+v", joins)
	}
	_, err = st.Enroll(ctx, []byte("join"), "bob", []byte("bob"), now, nil)
	must(t, err)
	_, err = st.Enroll(ctx, []byte("join"), "extra", []byte("extra"), now, nil)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("exhausted token: %v", err)
	}
}

func testEnrollmentExactlyOneWins(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	_, err := st.CreateJoinToken(ctx, []byte("join"), store.RoleAgent, "fixed", 1, now.Add(time.Hour))
	must(t, err)
	raceCalls(t, 12, func(i int) error {
		_, err := st.Enroll(ctx, []byte("join"), fmt.Sprint(i), []byte(fmt.Sprint(i)), now, nil)
		return err
	}, store.ErrNotFound)
	peers, err := st.ListPeers(ctx)
	must(t, err)
	if len(peers) != 1 || peers[0].Name != "fixed" {
		t.Fatal(peers)
	}
}

func testPeerNameExactlyOneWins(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	_, err := st.CreateJoinToken(ctx, []byte("join"), store.RoleAgent, "", 12, now.Add(time.Hour))
	must(t, err)
	raceCalls(t, 12, func(i int) error {
		_, err := st.Enroll(ctx, []byte("join"), "same-name", []byte(fmt.Sprint(i)), now, nil)
		return err
	}, store.ErrConflict)
	joins, err := st.ListJoinTokens(ctx, now)
	must(t, err)
	if len(joins) != 1 || joins[0].UsesLeft != 11 {
		t.Fatalf("failed duplicate enrollments consumed uses: %+v", joins)
	}
}

func testEnrollmentAllowInsideTransaction(t *testing.T, open func(*testing.T) store.Store) {
	st, now := open(t), time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := st.CreateJoinToken(ctx, []byte("join"), store.RoleAgent, "", 1, now.Add(time.Hour))
	must(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, err := st.Enroll(ctx, []byte("join"), "first", []byte("first"), now, func(string) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		first <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("allow callback never entered")
	}
	secondEntered := make(chan struct{}, 1)
	second := make(chan error, 1)
	go func() {
		_, err := st.Enroll(ctx, []byte("join"), "second", []byte("second"), now, func(string) error { secondEntered <- struct{}{}; return nil })
		second <- err
	}()
	// A competing enrollment cannot observe this one-use token as available
	// while its policy callback is running. This also catches implementations
	// that invoke the callback before acquiring the enrollment transaction.
	select {
	case <-secondEntered:
		t.Error("another enrollment entered allow while the token was reserved")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	must(t, <-first)
	if err := <-second; !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("competing enrollment: %v", err)
	}
}

func testPullPairingCodeExactlyOnce(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	p, err := st.CreatePullPeer(ctx, store.PullPeer{Peer: store.Peer{Name: "pull"}, Transport: "https", Address: "https://agent", PairCode: "old", PairExpires: now.Add(time.Hour), Interval: time.Minute, NextPull: now}, []byte("pull"), now)
	must(t, err)
	must(t, st.SetPairCode(ctx, p.ID, "current", now.Add(time.Hour), now))
	if err := st.SetPin(ctx, p.ID, "old", "bad"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale code: %v", err)
	}
	raceCalls(t, 12, func(i int) error { return st.SetPin(ctx, p.ID, "current", fmt.Sprint("pin-", i)) }, store.ErrConflict)
	p, err = st.GetPullPeer(ctx, p.ID)
	must(t, err)
	if p.Pin == "" || p.PairCode != "" || !p.PairExpires.IsZero() {
		t.Fatalf("code was not consumed: %+v", p)
	}
	if err := st.SetPin(ctx, p.ID, "", "replace"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("empty code: %v", err)
	}
	must(t, st.SetPairCode(ctx, p.ID, "again", now.Add(time.Hour), now))
	p, err = st.GetPullPeer(ctx, p.ID)
	must(t, err)
	if p.Pin != "" || p.PairCode != "again" {
		t.Fatal(p)
	}
	due, err := st.DuePullPeers(ctx, now)
	must(t, err)
	if len(due) != 1 {
		t.Fatal(due)
	}
	must(t, st.SetPeerDisabled(ctx, p.ID, true))
	due, err = st.DuePullPeers(ctx, now)
	must(t, err)
	if len(due) != 0 {
		t.Fatal(due)
	}
}

func testSettingsAndEventRetention(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	if _, err := st.GetSetting(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	for _, value := range []string{"first", "replacement"} {
		must(t, st.SetSetting(ctx, "custom", value))
		got, err := st.GetSetting(ctx, "custom")
		must(t, err)
		if got != value {
			t.Fatal(got)
		}
	}
	for _, delta := range []time.Duration{-time.Second, 0, time.Second} {
		must(t, st.AddEvent(ctx, store.Event{At: now.Add(delta), Type: "test", Summary: delta.String()}))
	}
	must(t, st.PurgeEvents(ctx, now))
	events, err := st.ListEvents(ctx, 10)
	must(t, err)
	if len(events) != 2 || !events[0].At.Equal(now.Add(time.Second)) || !events[1].At.Equal(now) {
		t.Fatal(events)
	}
	events, err = st.ListEvents(ctx, 1)
	must(t, err)
	if len(events) != 1 || events[0].Summary != "1s" {
		t.Fatal(events)
	}
}
