package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/pull"
	pullhttps "github.com/JulianStremel/netnoodle/internal/pull/https"
	"github.com/JulianStremel/netnoodle/internal/store"
	"github.com/JulianStremel/netnoodle/internal/version"
)

func TestOnboardConnectionHooks(t *testing.T) {
	for _, kind := range []string{"agent", "scan", "actor-host", "agent-pull"} {
		t.Run(kind, func(t *testing.T) {
			ts, c, _, s := newTestServerS(t)
			key, err := LoadOrCreateOrderKey(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			s.SetOrderKey(key)
			secret, join := RandomToken(32), RandomToken(24)
			o := store.OnboardSession{ID: "connection-test-session", SecretHash: HashToken(secret), Name: "hook-peer", Kind: kind, Platform: "linux", Expires: s.now().Add(30 * time.Minute)}
			if err = s.st.CreateOnboard(t.Context(), o, HashToken(join), onboardRole(kind), s.now()); err != nil {
				t.Fatal(err)
			}
			var peer struct{ Token string }
			if status := doJSON(t, c, "POST", ts.URL+"/v1/enroll", "", fmt.Sprintf(`{"name":"hook-peer","join_token":%q}`, join), &peer); status != 200 {
				t.Fatalf("enroll: %d", status)
			}
			if kind == "agent-pull" {
				cert, fp, err := LoadOrCreatePullCert(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				s.SetPull(map[string]pull.Transport{"https": pullhttps.New(cert, fp)}, fp)
				agent := newFakeAgent(t, fp, `{"version":"v1","source":"ignored","entities":[{"kind":"host","name":"hook-peer"}]}`)
				var response struct{ Code, Fingerprint string }
				body, _ := json.Marshal(map[string]any{"name": "pair", "ok": true, "message": agent.addr()})
				if status := onboardRequest(t, c, "POST", ts.URL+"/v1/onboard/"+o.ID+"/step", secret, string(body), &response); status != 200 || response.Fingerprint != fp || len(response.Code) != 32 {
					t.Fatalf("pair step: %d %+v", status, response)
				}
				agent.code.Store(response.Code)
				saved, err := s.st.GetOnboard(t.Context(), o.ID)
				if err != nil {
					t.Fatal(err)
				}
				pp, err := s.st.GetPullPeer(t.Context(), saved.PeerID)
				if err != nil {
					t.Fatal(err)
				}
				s.pullOne(t.Context(), pp)
			} else {
				path, body := "/v1/observations", `{"version":"v1","source":"ignored","entities":[{"kind":"host","name":"hook-peer","identifiers":[{"kind":"mac","value":"00:11:22:33:44:55","strength":"strong"}]}]}`
				if kind == "actor-host" {
					path, body = "/v1/actor/hello", `{"version":"v1","actor_version":"v1.2.3","capabilities":[]}`
				}
				if status := doJSON(t, c, "POST", ts.URL+path, peer.Token, body, nil); status != 200 {
					t.Fatalf("connection: %d", status)
				}
			}
			saved, err := s.st.GetOnboard(t.Context(), o.ID)
			if err != nil || saved.State != "connected" {
				t.Fatalf("connection hook: %+v %v", saved, err)
			}
			peers, err := s.st.ListPeers(t.Context())
			if err != nil || len(peers) != 1 || !peers[0].Provisional {
				t.Fatalf("not provisional: %+v %v", peers, err)
			}
			devices, err := s.st.ListDevices(t.Context())
			if err != nil || len(devices) != 0 {
				t.Fatalf("provisional inventory ingested: %+v %v", devices, err)
			}
			actors, err := s.st.ListActors(t.Context())
			if err != nil || len(actors) != 0 {
				t.Fatalf("provisional planner actor: %+v %v", actors, err)
			}
			if kind == "actor-host" {
				var orders []any
				if code := doJSON(t, c, "GET", ts.URL+"/v1/orders?wait=0", peer.Token, "", &orders); code != 200 || len(orders) != 0 {
					t.Fatalf("provisional orders: %d %+v", code, orders)
				}
			}
			if code := onboardRequest(t, c, "POST", ts.URL+"/v1/onboard/"+o.ID+"/step", secret, `{"name":"done","ok":true}`, nil); code != 200 {
				t.Fatal(code)
			}
			peers, err = s.st.ListPeers(t.Context())
			if err != nil || len(peers) != 1 || peers[0].Provisional {
				t.Fatalf("not promoted: %+v %v", peers, err)
			}
			if kind == "actor-host" {
				actors, err = s.st.ListActors(t.Context())
				if err != nil || len(actors) != 1 {
					t.Fatalf("actor not promoted: %+v %v", actors, err)
				}
			} else if kind != "agent-pull" {
				if code := doJSON(t, c, "POST", ts.URL+"/v1/observations", peer.Token, `{"version":"v1","entities":[{"kind":"host","name":"normal","identifiers":[{"kind":"mac","value":"00:11:22:33:44:55","strength":"strong"}]}]}`, nil); code != 200 {
					t.Fatal(code)
				}
				devices, err = s.st.ListDevices(t.Context())
				if err != nil || len(devices) != 1 {
					t.Fatalf("normal inventory absent: %+v %v", devices, err)
				}
			}
		})
	}
}

func TestOnboardPeriodicExpiry(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	now := time.Now()
	o := store.OnboardSession{ID: "periodic-expiry-session", SecretHash: HashToken("secret"), Name: "expiring", Kind: "agent", Platform: "linux", Expires: now.Add(30 * time.Minute)}
	if err := s.st.CreateOnboard(t.Context(), o, HashToken("join"), store.RoleAgent, now); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return o.Expires }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.RunPull(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		saved, err := s.st.GetOnboard(t.Context(), o.ID)
		if err != nil {
			t.Fatal(err)
		}
		if saved.State == "expired" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("periodic loop did not expire the session")
}

func TestSetupCodeRoundTrip(t *testing.T) {
	fields := map[string]string{"server": "https://10.0.0.5:7443", "fingerprint": strings.Repeat("a", 64), "spki": strings.Repeat("A", 43) + "=", "session": "0123456789abcdef", "secret": RandomToken(32), "token": RandomToken(24), "name": "web01", "kind": "agent", "version": "v0.1.0", "expires": "2026-11-20T12:00:00Z"}
	code := encodeSetup(fields)
	if strings.Contains(code, "=") {
		t.Fatal("base64 padding in setup code")
	}
	got, err := decodeSetup(code)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range fields {
		if got[key] != want {
			t.Fatalf("%s=%q want %q", key, got[key], want)
		}
	}
	for _, bad := range []string{"bad", strings.Repeat("a", 16385), "nnsetup1:!", "nnsetup1:" + base64.RawURLEncoding.EncodeToString([]byte("name=one\nname=two\n")), "nnsetup1:" + base64.RawURLEncoding.EncodeToString([]byte("name=one\n"))} {
		if _, err = decodeSetup(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func onboardRequest(t *testing.T, c *http.Client, method, url, secret, body string, out any) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-NN-Onboard-Secret", secret)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		if err = json.NewDecoder(res.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode
}
func TestOnboardingAPI(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	anon := &http.Client{Transport: c.Transport}
	s.cfg.DataDir = t.TempDir()
	cert, fp, err := LoadOrCreateCert(s.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	s.fingerprint = fp
	if got := onboardRequest(t, c, "POST", ts.URL+"/api/onboard", "", `{"kind":"agent","name":"web01","platform":"linux","password":"x"}`, nil); got != 401 {
		t.Fatalf("unauthenticated create: %d", got)
	}
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	if got := onboardRequest(t, c, "POST", ts.URL+"/api/onboard", "", `{"kind":"agent","name":"web01","platform":"linux","password":"x"}`, nil); got != 403 {
		t.Fatalf("step-up: %d", got)
	}
	create := func(name, kind, platform string) map[string]string {
		t.Helper()
		var response struct {
			Session   string `json:"session"`
			SetupCode string `json:"setup_code"`
			OneLiner  string `json:"one_liner"`
		}
		body, _ := json.Marshal(map[string]string{"kind": kind, "name": name, "platform": platform, "password": pw})
		if got := onboardRequest(t, c, "POST", ts.URL+"/api/onboard", "", string(body), &response); got != 200 {
			t.Fatalf("create: %d %+v", got, response)
		}
		fields, e := decodeSetup(response.SetupCode)
		if e != nil {
			t.Fatal(e)
		}
		if fields["session"] != response.Session || fields["server"] != ts.URL || fields["fingerprint"] != fp {
			t.Fatalf("setup: %+v", fields)
		}
		spki, e := s.installPins()
		if e != nil {
			t.Fatal(e)
		}
		if fields["spki"] != spki || !strings.Contains(response.OneLiner, spki) {
			t.Fatalf("missing SPKI pin: %s", response.OneLiner)
		}
		if bytes.Contains([]byte(response.OneLiner), []byte(fields["token"])) || strings.Contains(response.OneLiner, fields["secret"]) {
			t.Fatal("one-liner contains a secret")
		}
		return fields
	}
	a := create("scan01", "scan", "linux")
	b := create("scan02", "scan", "linux")
	o, err := s.st.GetOnboard(t.Context(), a["session"])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(o.SecretHash, HashToken(a["secret"])) {
		t.Fatal("secret is not hashed")
	}
	for _, step := range []map[string]any{
		{"name": strings.Repeat("x", 65), "ok": true},
		{"name": "install", "ok": true, "message": strings.Repeat("x", 1025)},
	} {
		body, _ := json.Marshal(step)
		if got := onboardRequest(t, c, "POST", ts.URL+"/v1/onboard/"+a["session"]+"/step", a["secret"], string(body), nil); got != 400 {
			t.Fatalf("oversized progress input: %d", got)
		}
	}
	if got := onboardRequest(t, c, "POST", ts.URL+"/v1/onboard/"+a["session"]+"/abort", a["secret"], fmt.Sprintf(`{"reason":%q}`, strings.Repeat("x", 1025)), nil); got != 400 {
		t.Fatalf("oversized abort input: %d", got)
	}
	for _, secret := range []string{"", RandomToken(32), b["secret"]} {
		for _, action := range []struct{ method, path, body string }{{"GET", "", ""}, {"POST", "/abort", `{"reason":"wrong session"}`}, {"POST", "/step", `{"name":"done","ok":true}`}} {
			if got := onboardRequest(t, ts.Client(), action.method, ts.URL+"/v1/onboard/"+a["session"]+action.path, secret, action.body, nil); got != 401 {
				t.Fatalf("cross-session access %s: %d", action.path, got)
			}
		}
	}
	if got := onboardRequest(t, ts.Client(), "GET", ts.URL+"/v1/onboard/0000000000000000", a["secret"], "", nil); got != 401 {
		t.Fatalf("unknown session: %d", got)
	}
	if got := onboardRequest(t, c, "POST", ts.URL+"/v1/onboard/"+a["session"]+"/step", a["secret"], `{"name":"done","ok":true}`, nil); got != 409 {
		t.Fatalf("skip state: %d", got)
	}
	var peer struct{ Token string }
	if got := doJSON(t, c, "POST", ts.URL+"/v1/enroll", "", fmt.Sprintf(`{"name":"wrong","join_token":%q}`, a["token"]), &peer); got != 200 {
		t.Fatalf("enroll: %d", got)
	}
	o, err = s.st.GetOnboard(t.Context(), a["session"])
	if err != nil || o.State != "enrolled" || o.PeerID == 0 {
		t.Fatalf("enrolled hook: %+v %v", o, err)
	}
	if got := doJSON(t, c, "POST", ts.URL+"/v1/observations", peer.Token, `{"version":"v1","source":"ignored","entities":[]}`, nil); got != 200 {
		t.Fatalf("observation: %d", got)
	}
	var status struct {
		State    string
		PeerSeen bool `json:"peer_seen"`
	}
	if got := onboardRequest(t, c, "GET", ts.URL+"/v1/onboard/"+a["session"], a["secret"], "", &status); got != 200 || status.State != "connected" || !status.PeerSeen {
		t.Fatalf("status: %d %+v", got, status)
	}
	if got := onboardRequest(t, c, "POST", ts.URL+"/v1/onboard/"+a["session"]+"/step", a["secret"], `{"name":"done","ok":true}`, nil); got != 200 {
		t.Fatalf("done: %d", got)
	}
	// A secret does not authorize the operator API.
	if got := onboardRequest(t, anon, "GET", ts.URL+"/api/onboard/"+a["session"], a["secret"], "", nil); got != 401 {
		t.Fatalf("operator API with secret: %d", got)
	}
	var public map[string]any
	onboardRequest(t, c, "GET", ts.URL+"/api/onboard/"+a["session"], "", "", &public)
	for _, key := range []string{"secret", "secret_hash", "token", "join_id"} {
		if _, ok := public[key]; ok {
			t.Fatalf("status leaks %s", key)
		}
	}
	if got := onboardRequest(t, c, "POST", ts.URL+"/api/onboard/"+b["session"]+"/cancel", "", `{}`, nil); got != 200 {
		t.Fatalf("cancel: %d", got)
	}
	if _, err = s.st.Enroll(t.Context(), HashToken(b["token"]), "scan02", HashToken("new"), s.now(), nil); err != store.ErrNotFound {
		t.Fatalf("cancel token: %v", err)
	}
	cancelled := create("scan-aborted", "scan", "linux")
	if got := onboardRequest(t, c, "POST", ts.URL+"/v1/onboard/"+cancelled["session"]+"/abort", cancelled["secret"], `{"reason":"failed"}`, nil); got != 200 {
		t.Fatal(got)
	}
	events, err := s.st.ListEvents(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"onboarding.created", "onboarding.cancelled", "onboarding.aborted", "onboarding.done"} {
		found := false
		for _, event := range events {
			if event.Type == typ {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %s event", typ)
		}
	}
	// Expiry happens on reads even before the periodic job ticks.
	d := create("scan03", "scan", "linux")
	s.now = func() time.Time { return time.Now().Add(31 * time.Minute) }
	if got := onboardRequest(t, c, "GET", ts.URL+"/v1/onboard/"+d["session"], d["secret"], "", &status); got != 200 || status.State != "expired" {
		t.Fatalf("expired status: %d %+v", got, status)
	}
	// The pin is the public key hash, not the certificate hash.
	leaf, err := s.installPins()
	if err != nil {
		t.Fatal(err)
	}
	certHash := sha256.Sum256(cert.Certificate[0])
	if leaf == base64.StdEncoding.EncodeToString(certHash[:]) {
		t.Fatal("SPKI equals certificate hash")
	}
}

func TestInstallManifest(t *testing.T) {
	old := version.Version
	version.Version = "v1.2.3-rc.1"
	t.Cleanup(func() { version.Version = old })
	ts, c, _, s := newTestServerS(t)
	var requests atomic.Int32
	hash := strings.Repeat("a", 64)
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/v1.2.3-rc.1/SHA256SUMS" {
			t.Errorf("unexpected release path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		for _, entry := range []struct{ platform, kind string }{{"linux-x86_64", "agent"}, {"linux-aarch64", "agent-pull"}, {"linux-armv7", "scan"}, {"linux-x86_64", "actor-host"}, {"windows-x86_64", "agent"}, {"windows-arm64", "scan"}} {
			asset, _, err := releaseAsset(version.Version, entry.platform, entry.kind)
			if err != nil {
				t.Error(err)
			}
			fmt.Fprintf(w, "%s  %s\n", hash, asset)
		}
	}))
	defer fixture.Close()
	s.SetInstallReleaseSource(fixture.URL, fixture.Client())
	for _, entry := range []struct{ platform, kind, asset string }{
		{"linux-x86_64", "agent", "nn-agent_v1.2.3-rc.1_linux_x86_64.tar.gz"},
		{"linux-aarch64", "agent-pull", "nn-agent_v1.2.3-rc.1_linux_aarch64.tar.gz"},
		{"linux-armv7", "scan", "netnoodle_v1.2.3-rc.1_linux_armv7.tar.gz"},
		{"linux-x86_64", "actor-host", "netnoodle_v1.2.3-rc.1_linux_amd64.tar.gz"},
		{"windows-x86_64", "agent", "nn-agent_v1.2.3-rc.1_windows_amd64.zip"},
		{"windows-arm64", "scan", "netnoodle_v1.2.3-rc.1_windows_arm64.zip"},
	} {
		var manifest installManifest
		path := ts.URL + "/v1/install/manifest?version=" + version.Version + "&platform=" + entry.platform + "&kind=" + entry.kind
		if got := onboardRequest(t, c, "GET", path, "", "", &manifest); got != 200 {
			t.Fatalf("manifest %s: %d", entry.platform, got)
		}
		if len(manifest.Artifacts) != 1 || manifest.Artifacts[0].URL != fixture.URL+"/"+version.Version+"/"+entry.asset || manifest.Artifacts[0].SHA256 != hash {
			t.Fatalf("manifest: %+v", manifest)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("cache requests: %d", requests.Load())
	}
	for _, query := range []string{"version=v0.0.1&platform=linux-x86_64&kind=agent", "version=dev&platform=linux-x86_64&kind=agent"} {
		if got := get(t, c, ts.URL+"/v1/install/manifest?"+query); got != 503 {
			t.Fatalf("unknown version: %d", got)
		}
	}
	if got := get(t, c, ts.URL+"/v1/install/manifest?version="+version.Version+"&platform=windows-arm64&kind=actor-unifi"); got != 400 {
		t.Fatalf("unsupported platform: %d", got)
	}
	version.Version = "dev"
	if got := get(t, c, ts.URL+"/v1/install/manifest?version=dev&platform=linux-x86_64&kind=agent"); got != 503 {
		t.Fatalf("dev version: %d", got)
	}
	for _, path := range []string{"/install.sh", "/install.ps1"} {
		res, err := c.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || res.Header.Get("Cache-Control") != "no-store" || len(body) < 100 {
			t.Fatalf("script %s: %d %d", path, res.StatusCode, len(body))
		}
	}
}

func TestManifestRejectsMissingAndOversizedHashes(t *testing.T) {
	old := version.Version
	version.Version = "v1.2.3"
	t.Cleanup(func() { version.Version = old })
	ts, c, _, s := newTestServerS(t)
	for _, body := range []string{"", strings.Repeat("x", (1<<20)+1), "invalid  nn-agent_v1.2.3_linux_x86_64.tar.gz\n"} {
		fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		s.SetInstallReleaseSource(fixture.URL, fixture.Client())
		if got := get(t, c, ts.URL+"/v1/install/manifest?version=v1.2.3&platform=linux-x86_64&kind=agent"); got != 503 {
			t.Fatalf("invalid checksums: %d", got)
		}
		fixture.Close()
	}
}

func TestInstallOneLinerPinsAndQuotes(t *testing.T) {
	spki, fp := strings.Repeat("A", 43)+"=", strings.Repeat("a", 64)
	linux := installOneLiner("https://server:7443", "linux", spki, fp)
	if !strings.Contains(linux, "--pinnedpubkey 'sha256//"+spki+"'") || !strings.Contains(linux, "sh -s --") || !strings.Contains(linux, "NN_EXPECTED_FINGERPRINT=") {
		t.Fatalf("Linux bootstrap is not pinned/private: %s", linux)
	}
	windows := installOneLiner("https://server:7443", "windows", spki, fp)
	for _, required := range []string{"ServerCertificateValidationCallback", "SHA256.Create()", "GetRawCertData()", fp, "finally"} {
		if !strings.Contains(windows, required) {
			t.Fatalf("Windows bootstrap missing %s", required)
		}
	}
	if shellQuote("a'b") != `'a'"'"'b'` || powershellQuote("a'b") != `'a''b'` {
		t.Fatal("bootstrap escaping lost a quote")
	}
}

func TestManifestFailureCacheAndConcurrency(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		w.WriteHeader(503)
	}))
	defer fixture.Close()
	s.SetInstallReleaseSource(fixture.URL, fixture.Client())
	done := make(chan error, 1)
	go func() { _, _, err := s.releaseHashes(t.Context(), "v1.2.3"); done <- err }()
	<-entered
	// A second lookup must fail promptly, without waiting on the fetch mutex.
	second := make(chan error, 1)
	go func() { _, _, err := s.releaseHashes(t.Context(), "v1.2.3"); second <- err }()
	select {
	case err := <-second:
		if err == nil {
			t.Error("inflight lookup succeeded")
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("fetch held cache mutex")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("failed fetch succeeded")
	}
	for range 3 {
		if _, _, err := s.releaseHashes(t.Context(), "v1.2.3"); err == nil {
			t.Fatal("failed lookup succeeded")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("failure not cached: %d", calls.Load())
	}
	s.onboard.mu.Lock()
	s.onboard.failureUntil = time.Now().Add(-time.Second)
	s.onboard.mu.Unlock()
	if _, _, err := s.releaseHashes(t.Context(), "v1.2.3"); err == nil {
		t.Fatal("failed retry succeeded")
	}
	if calls.Load() != 2 {
		t.Fatalf("failure cache did not expire: %d", calls.Load())
	}
}

func TestManifestRateLimit(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	for i := 0; i < 31; i++ {
		req := httptest.NewRequest("GET", "https://server/v1/install/manifest?version=invalid", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		s.handleInstallManifest(w, req)
		want := 503
		if i == 30 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	req := httptest.NewRequest("GET", "https://server/v1/install/manifest", nil)
	req.RemoteAddr = "192.0.2.2:1234"
	w := httptest.NewRecorder()
	s.handleInstallManifest(w, req)
	if w.Code == 429 {
		t.Fatal("different IP rate limited")
	}
}

// Exercise Windows PowerShell's native argument marshalling, not just parsing:
// quoted -Command strings silently lose C# double quotes on PowerShell 5.1.
func TestWindowsOneLinerDeliversBootstrap(t *testing.T) {
	ps, err := exec.LookPath("powershell")
	if err != nil {
		t.Skip("Windows PowerShell unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", "exit 0").CombinedOutput(); err != nil {
		t.Skipf("PowerShell cannot run: %v %s", err, out)
	}
	spki, fp := strings.Repeat("A", 43)+"=", strings.Repeat("a", 64)
	one := installOneLiner("https://server:7443", "windows", spki, fp)
	// This test runs without elevation and substitutes the network download. The
	// certificate callback compilation and nested script-block call still run.
	start, end := strings.Index(one, "if (-not "), strings.Index(one, "; $old=")
	if start < 0 || end < start {
		t.Fatal("bootstrap elevation guard missing")
	}
	one = one[:start] + one[end+2:]
	root := t.TempDir()
	output := filepath.Join(root, "bootstrap.txt")
	stub := `param([string]$ExpectedServer,[string]$ExpectedSPKI,[string]$ExpectedFingerprint) [IO.File]::WriteAllText(` + powershellQuote(output) + `, $ExpectedServer+'|'+$ExpectedSPKI+'|'+$ExpectedFingerprint)`
	download := `(New-Object Net.WebClient).DownloadString('https://server:7443/install.ps1')`
	if !strings.Contains(one, download) {
		t.Fatal("download fixture not substituted")
	}
	one = strings.Replace(one, download, powershellQuote(stub), 1)
	file := filepath.Join(root, "bootstrap.ps1")
	if err := os.WriteFile(file, []byte(one), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file).CombinedOutput()
	if err != nil {
		t.Fatalf("bootstrap execution: %v\n%s", err, out)
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != "https://server:7443|"+spki+"|"+fp {
		t.Fatalf("bootstrap parameters: %s %v\n%s", got, err, out)
	}
}
