package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Security review 2026-11-20 (host updater): the untrusted server cannot
// choose the channel, the installed version, the rollback target or the
// size of the queue.

func TestRequestCannotChangeHostChannel(t *testing.T) {
	u, _, req := fixture(t)
	req.Channel = "latest"
	if e := WriteJSON(u.Config.SharedDir, req, "requests", req.ID+".json"); e != nil {
		t.Fatal(e)
	}
	_ = u.RunOnce(context.Background())
	if s := readStatus(t, u, req.ID); s.State != "failed" || !strings.Contains(s.Error, "host channel") {
		t.Fatal(s)
	}
}

func TestDowngradeUsesHostView(t *testing.T) {
	u, r, req := fixture(t)
	r.label = "v1.2.0" // target is older than the running v1.2.3
	u.Health = func(context.Context) (Health, error) { return Health{Version: "v0.0.1", Schema: 1}, nil }
	_ = u.RunOnce(context.Background())
	if s := readStatus(t, u, req.ID); s.State != "failed" || !strings.Contains(s.Error, "downgrade") || s.FromVersion != oldVersion {
		t.Fatal(s)
	}
}

func TestRollbackOnlyOfLastUpdate(t *testing.T) {
	u, _, req := fixture(t)
	if e := u.RunOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(u.Config.StateDir, "current.json")); e != nil {
		t.Fatal(e)
	}
	rb := Request{ID: "rollback-request-456", Kind: "rollback", To: req.ID, Channel: "stable", RequestedBy: "admin", RequestedAt: time.Now().UTC()}
	if e := WriteJSON(u.Config.SharedDir, rb, "requests", rb.ID+".json"); e != nil {
		t.Fatal(e)
	}
	_ = u.RunOnce(context.Background())
	if s := readStatus(t, u, rb.ID); s.State != "rejected" || !strings.Contains(s.Error, "last update") {
		t.Fatal(s)
	}
}

type alwaysFail struct {
	*fakeRunner
	match string
}

func (a alwaysFail) Run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	if strings.Contains(name+" "+strings.Join(args, " "), a.match) && a.fakeRunner.image != "" && strings.Contains(strings.Join(env, " "), oldDigest) {
		return "", errors.New("injected permanent failure")
	}
	return a.fakeRunner.Run(ctx, env, name, args...)
}

func TestRecoveryIsBounded(t *testing.T) {
	u, r, req := fixture(t)
	r.fail = " up -d " // the swap fails once
	u.Runner = alwaysFail{r, " up -d "}
	for i := 0; i < maxRecoveries+2; i++ {
		_ = u.RunOnce(context.Background())
	}
	s := readStatus(t, u, req.ID)
	if s.State != "failed" || !strings.Contains(s.Error, "manual action") {
		t.Fatal(s)
	}
	if _, e := os.Stat(filepath.Join(u.Config.SharedDir, "requests", req.ID+".json")); !os.IsNotExist(e) {
		t.Fatal("terminal request kept", e)
	}
}

func TestQueueIsBounded(t *testing.T) {
	u, _, _ := fixture(t)
	dir := filepath.Join(u.Config.SharedDir, "requests")
	if e := os.WriteFile(filepath.Join(dir, "junk.bin"), make([]byte, 1024), 0600); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < maxQueue+4; i++ {
		r := Request{ID: "flood-request-" + string(rune('a'+i)) + "xx", Kind: "update", Channel: "latest", RequestedBy: "x", RequestedAt: time.Now().UTC()}
		if e := WriteJSON(u.Config.SharedDir, r, "requests", r.ID+".json"); e != nil {
			t.Fatal(e)
		}
	}
	_ = u.RunOnce(context.Background())
	left, _ := os.ReadDir(dir)
	if len(left) != 0 {
		t.Fatalf("%d files left in requests", len(left))
	}
	status, _ := os.ReadDir(filepath.Join(u.Config.SharedDir, "status"))
	if len(status) > maxQueue {
		t.Fatalf("%d requests processed, want at most %d", len(status), maxQueue)
	}
}

func TestStableNeedsPromotionSignature(t *testing.T) {
	u, r, req := fixture(t)
	u.Config.Cosign = Cosign{Path: "cosign", Identity: "^release$", Issuer: "https://issuer"}
	if e := u.Config.Validate(); e == nil || !strings.Contains(e.Error(), "promote_identity_regexp") {
		t.Fatal(e)
	}
	u.Config.Cosign.PromoteIdentity = "^promote$"
	if e := u.RunOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s := readStatus(t, u, req.ID); s.State != "done" || !strings.Contains(strings.Join(r.calls, "\n"), "--certificate-identity-regexp ^promote$ --certificate-oidc-issuer https://issuer -a channel=stable "+newDigest) {
		t.Fatal(s, r.calls)
	}
}

func TestStateDirOutsideSharedDir(t *testing.T) {
	c := DefaultConfig()
	c.StateDir = c.SharedDir + "/state"
	c.HealthURL, c.HealthFingerprint = "https://localhost/v1/health", strings.Repeat("0", 64)
	if e := c.Validate(); e == nil || !strings.Contains(e.Error(), "state_dir") {
		t.Fatal(e)
	}
}
