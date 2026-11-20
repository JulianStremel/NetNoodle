package storetest

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

func testIntegrations(t *testing.T, open func(*testing.T) store.Store) {
	st := open(t)
	ctx := t.Context()
	now := time.Now().UTC()
	rows, err := st.ListIntegrations(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
	i := store.Integration{Type: "unifi", Name: "controller", Settings: json.RawMessage(`{"url":"https://controller"}`), Secrets: json.RawMessage(`{"api_key":"contract-secret"}`), Enabled: true, CreatedAt: now, UpdatedAt: now}
	i, err = st.CreateIntegration(ctx, i)
	if err != nil || i.ID == 0 {
		t.Fatal(i, err)
	}
	duplicate := i
	duplicate.Name = "CONTROLLER"
	if _, err = st.CreateIntegration(ctx, duplicate); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("name uniqueness: %v", err)
	}
	saved, err := st.GetIntegration(ctx, i.ID)
	if err != nil || saved.Kind != "source" || string(saved.Settings) != string(i.Settings) || string(saved.Secrets) != string(i.Secrets) || !saved.CreatedAt.Equal(now) || !saved.Enabled {
		t.Fatal(saved, err)
	}
	if err = st.SetIntegrationResult(ctx, i.ID, now, now.Add(time.Second), ""); err != nil {
		t.Fatal(err)
	}
	if err = st.SetIntegrationResult(ctx, i.ID, now, now.Add(2*time.Second), "poll failed"); err != nil {
		t.Fatal(err)
	}
	saved, _ = st.GetIntegration(ctx, i.ID)
	if !saved.LastOKAt.Equal(now.Add(time.Second)) || saved.LastError != "poll failed" {
		t.Fatal(saved)
	}
	saved.Name = "renamed"
	saved.Enabled = false
	saved.UpdatedAt = now.Add(3 * time.Second)
	if err = st.UpdateIntegration(ctx, saved); err != nil {
		t.Fatal(err)
	}
	if err = st.SetIntegrationResult(ctx, i.ID, now, now.Add(4*time.Second), "stale error"); err != nil {
		t.Fatal(err)
	}
	saved, _ = st.GetIntegration(ctx, i.ID)
	if saved.Enabled || saved.Name != "renamed" || saved.LastError != "" || string(saved.Secrets) != string(i.Secrets) {
		t.Fatal(saved)
	}
	rows, err = st.ListIntegrations(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	// Integrations cannot take the identity of an enrolled peer, or vice versa.
	if _, err = st.CreateJoinToken(ctx, []byte("integration-join"), store.RoleSource, "renamed", 1, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = st.Enroll(ctx, []byte("integration-join"), "renamed", []byte("peer-secret"), now, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("source name collision: %v", err)
	}
	if err = st.DeleteIntegration(ctx, i.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = st.GetIntegration(ctx, i.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err = st.DeleteIntegration(ctx, i.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err = st.UpdateIntegration(ctx, saved); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err = st.Enroll(ctx, []byte("integration-join"), "renamed", []byte("peer-secret"), now, nil); err != nil {
		t.Fatal(err)
	}
	i.Name = "RENAMED"
	if _, err = st.CreateIntegration(ctx, i); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("peer name collision: %v", err)
	}
}
