package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const oldVersion = "v1.2.3"
const newVersion = "v1.3.0"

var oldDigest = "ghcr.io/test/server@sha256:" + strings.Repeat("a", 64)
var newDigest = "ghcr.io/test/server@sha256:" + strings.Repeat("b", 64)

type fakeRunner struct {
	calls    []string
	fail     string
	failed   bool
	image    string
	label    string
	migrated bool
	restored bool
	crash    string
}

func (r *fakeRunner) Run(_ context.Context, env []string, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, strings.Join(env, " ")+" "+call)
	if r.crash != "" && strings.Contains(call, r.crash) {
		panic("power loss")
	}
	if r.fail != "" && !r.failed && strings.Contains(call, r.fail) {
		r.failed = true
		return "", errors.New("injected failure")
	}
	if strings.HasPrefix(call, "docker image inspect --format {{index .RepoDigests 0}}") {
		if strings.HasSuffix(call, "sha256:running") {
			return oldDigest, nil
		}
		return newDigest, nil
	}
	if strings.Contains(call, "org.opencontainers.image.version") {
		return r.label, nil
	}
	if strings.Contains(call, " ps -q ") {
		return "running-container", nil
	}
	if strings.Contains(call, "docker inspect --format {{.Image}}") {
		return "sha256:running", nil
	}
	if strings.Contains(call, " backup ") {
		b, _ := json.Marshal(map[string]string{"path": filepath.Join(os.TempDir(), "update-backup.db")})
		return string(b), nil
	}
	if strings.Contains(call, " restore ") {
		r.restored = true
	}
	if strings.Contains(call, " up -d ") {
		image := ""
		for _, v := range env {
			if strings.HasPrefix(v, "NN_SERVER_IMAGE=") {
				image = strings.TrimPrefix(v, "NN_SERVER_IMAGE=")
			}
		}
		if image == "" {
			return "", errors.New("missing image override")
		}
		r.image = image
	}
	return "", nil
}
func fixture(t *testing.T) (*Updater, *fakeRunner, Request) {
	t.Helper()
	c := DefaultConfig()
	c.SharedDir = t.TempDir()
	c.ComposeFile = filepath.Join(c.SharedDir, "compose.yaml")
	c.ComposeProject = "test"
	c.ImageRepo = "ghcr.io/test/server"
	c.HealthURL = "https://localhost/v1/health"
	c.HealthFingerprint = strings.Repeat("0", 64)
	c.HealthTimeout = "5ms"
	c.Cosign.Key = "release.pub"
	r := &fakeRunner{label: newVersion, image: oldDigest}
	u, e := New(c, r)
	if e != nil {
		t.Fatal(e)
	}
	if e = u.Init(); e != nil {
		t.Fatal(e)
	}
	u.Health = func(context.Context) (Health, error) {
		if r.image == oldDigest {
			return Health{Version: oldVersion, Schema: 1}, nil
		}
		if r.migrated {
			return Health{Version: "v1.3.1", Schema: 2}, nil
		}
		return Health{Version: newVersion, Schema: 1}, nil
	}
	req := Request{ID: "test-request-1234", Kind: "update", Channel: "stable", RequestedBy: "admin", RequestedAt: time.Now().UTC()}
	if e = WriteJSON(c.SharedDir, req, "requests", req.ID+".json"); e != nil {
		t.Fatal(e)
	}
	return u, r, req
}
func readStatus(t *testing.T, u *Updater, id string) Status {
	t.Helper()
	var s Status
	if e := ReadJSON(u.Config.SharedDir, &s, "status", id+".json"); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestFailurePaths(t *testing.T) {
	for _, tc := range []struct {
		name, fail          string
		downgrade, migrated bool
		want                string
		restore             bool
	}{
		{name: "success", want: "done"},
		{name: "pull", fail: "docker pull", want: "failed"},
		{name: "signature", fail: "cosign verify", want: "failed"},
		{name: "downgrade", downgrade: true, want: "failed"},
		{name: "backup", fail: " backup ", want: "failed"},
		{name: "swap", fail: " up -d ", want: "rolled-back"},
		{name: "migrated", migrated: true, want: "rolled-back", restore: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, r, req := fixture(t)
			r.fail = tc.fail
			r.migrated = tc.migrated
			if tc.downgrade {
				r.label = "v1.0.0"
			}
			_ = u.RunOnce(context.Background())
			s := readStatus(t, u, req.ID)
			if s.State != tc.want {
				t.Fatalf("%+v\n%v", s, r.calls)
			}
			if r.restored != tc.restore {
				t.Fatalf("restore=%v calls=%v", r.restored, r.calls)
			}
			if tc.want == "failed" && r.image != oldDigest {
				t.Fatal("changed image before swap")
			}
			if tc.want == "rolled-back" && r.image != oldDigest {
				t.Fatal("previous digest not restored")
			}
			for _, call := range r.calls {
				if strings.Contains(call, "prune") || strings.Contains(call, "image rm") {
					t.Fatal("removed retained image")
				}
			}
			if tc.want == "done" {
				if s.FromDigest != oldDigest || s.ToDigest != newDigest || s.KeepUntil.Sub(s.FinishedAt) != 7*24*time.Hour {
					t.Fatal(s)
				}
			}
			if _, e := os.Stat(filepath.Join(u.Config.SharedDir, "requests", req.ID+".json")); !os.IsNotExist(e) {
				t.Fatal("terminal request still pending")
			}
		})
	}
}
func TestHealthNeverComesUpRestores(t *testing.T) {
	u, r, req := fixture(t)
	u.Health = func(context.Context) (Health, error) {
		if r.image == oldDigest {
			return Health{Version: oldVersion, Schema: 1}, nil
		}
		return Health{}, errors.New("offline after migrations")
	}
	_ = u.RunOnce(context.Background())
	s := readStatus(t, u, req.ID)
	if s.State != "rolled-back" || !r.restored {
		t.Fatal(s, r.calls)
	}
}
func TestResumeEveryState(t *testing.T) {
	for _, state := range []string{"validate", "resolve", "verify", "downgrade", "backup", "swap", "health", "rollback"} {
		t.Run(state, func(t *testing.T) {
			u, r, req := fixture(t)
			s := State{Status: Status{ID: req.ID, State: state, FromVersion: oldVersion, ToVersion: newVersion, FromDigest: oldDigest, ToDigest: newDigest}, Request: req, Backup: filepath.Join(t.TempDir(), "backup.db"), Schema: 1}
			order := []string{"resolve", "verify", "downgrade", "backup", "swap", "health"}
			for _, name := range order {
				if name == state {
					break
				}
				if state != "validate" {
					s.Steps = append(s.Steps, Step{Name: name, OK: true, At: time.Now()})
				}
			}
			if state == "health" || state == "rollback" {
				r.image = newDigest
			}
			if e := u.save(&s); e != nil {
				t.Fatal(e)
			}
			if e := u.RunOnce(context.Background()); e != nil {
				t.Fatal(e)
			}
			got := readStatus(t, u, req.ID)
			want := "done"
			if state == "swap" || state == "health" || state == "rollback" {
				want = "rolled-back"
			}
			if got.State != want {
				t.Fatal(got, r.calls)
			}
		})
	}
}
func TestCrashAfterExternalSwap(t *testing.T) {
	u, r, req := fixture(t)
	r.crash = " up -d "
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected crash")
			}
		}()
		_ = u.RunOnce(context.Background())
	}()
	r.crash = ""
	r.image = newDigest
	if e := u.RunOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s := readStatus(t, u, req.ID); s.State != "rolled-back" || !r.restored {
		t.Fatal(s)
	}
}
func TestStrictRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"bad id", func(m map[string]any) { m["id"] = "../bad" }}, {"unknown", func(m map[string]any) { m["surprise"] = true }}, {"image", func(m map[string]any) { m["image"] = "evil/image" }}, {"version", func(m map[string]any) { m["version"] = "v1.2" }}, {"channel", func(m map[string]any) { m["channel"] = "edge" }}, {"command", func(m map[string]any) { m["command"] = "sh" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, r, req := fixture(t)
			b, _ := json.Marshal(req)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			tc.edit(m)
			if e := WriteJSON(u.Config.SharedDir, m, "requests", req.ID+".json"); e != nil {
				t.Fatal(e)
			}
			_ = u.RunOnce(context.Background())
			if s := readStatus(t, u, req.ID); s.State != "rejected" {
				t.Fatal(s)
			}
			if len(r.calls) > 0 {
				t.Fatal(r.calls)
			}
		})
	}
}
func TestBadFilenameAndJSONLimits(t *testing.T) {
	u, _, _ := fixture(t)
	p := filepath.Join(u.Config.SharedDir, "requests", "bad.json")
	if e := os.WriteFile(p, []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	_ = u.RunOnce(context.Background())
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("invalid filename was not consumed")
	}
	for _, b := range []string{`{} {}`, `{"unexpected":true}`, strings.Repeat(" ", MaxJSON+1)} {
		var r Request
		if Decode([]byte(b), &r) == nil {
			t.Fatal("accepted hostile JSON")
		}
	}
}
func TestCheckAndExplicitRollback(t *testing.T) {
	u, r, req := fixture(t)
	if e := u.Check(context.Background()); e != nil {
		t.Fatal(e)
	}
	var a Available
	if e := ReadJSON(u.Config.SharedDir, &a, "status", "available.json"); e != nil || a.Version != newVersion {
		t.Fatal(a, e)
	}
	if e := u.RunOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	rollback := Request{ID: "rollback-request-123", Kind: "rollback", To: req.ID, Channel: "stable", RequestedBy: "admin", RequestedAt: time.Now().UTC()}
	if e := WriteJSON(u.Config.SharedDir, rollback, "requests", rollback.ID+".json"); e != nil {
		t.Fatal(e)
	}
	if e := u.RunOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	s := readStatus(t, u, rollback.ID)
	if s.State != "done" || !r.restored || r.image != oldDigest {
		t.Fatal(s, r.calls)
	}
}
func TestReleaseComparison(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{{"v1.2.10", "v1.2.9", true}, {"v2.0.0", "v1.99.99", true}, {"v1.2.3", "v1.2.3", false}, {"dev", "v1.2.3", false}, {"v1.2.3-rc1", "v1.2.2", false}, {"v99999999999999999999999.0.0", "v1.0.0", false}} {
		if Newer(tc.a, tc.b) != tc.want {
			t.Fatal(tc)
		}
	}
}
func TestBinaryFlow(t *testing.T) {
	u, r, req := fixture(t)
	u.Config.Mode = "binary"
	u.Config.BinaryPath = filepath.Join(t.TempDir(), "nn-server")
	u.Config.ServiceUnit = "netnoodle.service"
	if e := os.WriteFile(u.Config.BinaryPath, []byte("old binary"), 0755); e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "new signed binary") }))
	defer ts.Close()
	u.Client = ts.Client()
	u.Config.ReleaseURLTemplate = ts.URL + "/{version}"
	u.Runner = &binaryRunner{fake: r, version: newVersion}
	u.Health = func(context.Context) (Health, error) {
		if len(r.calls) > 0 && strings.Contains(strings.Join(r.calls, " "), "systemctl restart") {
			return Health{Version: newVersion}, nil
		}
		return Health{Version: oldVersion}, nil
	}
	if e := u.RunOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s := readStatus(t, u, req.ID); s.State != "done" {
		t.Fatal(s)
	}
	b, e := os.ReadFile(u.Config.BinaryPath)
	if e != nil || string(b) != "new signed binary" {
		t.Fatal(string(b), e)
	}
	b, e = os.ReadFile(u.Config.BinaryPath + "." + req.ID + ".prev")
	if e != nil || string(b) != "old binary" {
		t.Fatal(string(b), e)
	}
}

type binaryRunner struct {
	fake    *fakeRunner
	version string
}

func (r *binaryRunner) Run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	if len(args) == 1 && args[0] == "version" {
		return r.version + " v1", nil
	}
	return r.fake.Run(ctx, env, name, args...)
}
