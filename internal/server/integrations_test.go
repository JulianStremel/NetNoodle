package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/source"
	_ "github.com/JulianStremel/netnoodle/internal/source/homeassistant"
	_ "github.com/JulianStremel/netnoodle/internal/source/proxmox"
	_ "github.com/JulianStremel/netnoodle/internal/source/tailscale"
	_ "github.com/JulianStremel/netnoodle/internal/source/unifi"
)

const integrationTestSecret = "never-return-this-integration-credential"
const integrationTestType = "integration-contract-test"

var integrationHooks = struct {
	sync.Mutex
	hooks map[string]chan string
}{hooks: map[string]chan string{}}

type integrationFixture struct {
	name, mode, secret string
	hook               chan string
}

func (f *integrationFixture) Name() string { return f.name }
func (f *integrationFixture) Poll(ctx context.Context, emit func(proto.Observation) error) error {
	if f.hook != nil {
		f.hook <- "start:" + f.name
		defer func() { f.hook <- "stop:" + f.name }()
	}
	switch f.mode {
	case "error":
		return fmt.Errorf("remote reflected %s / %x", f.secret, f.secret)
	case "panic":
		panic(f.secret)
	case "wait":
		<-ctx.Done()
		return ctx.Err()
	}
	return emit(proto.Observation{Entities: []proto.Entity{{Name: "test only", Identifiers: []proto.Identifier{{Kind: "mac", Value: "00:11:22:33:44:55", Strength: proto.Strong}}, Children: []proto.Entity{{Name: "child"}}}}})
}

func init() {
	source.Registry.RegisterWithSchema(integrationTestType, func(name string, raw json.RawMessage) (source.Source, error) {
		var cfg struct {
			Mode string `json:"mode"`
			Key  string `json:"key"`
		}
		if err := registry.Decode(raw, &cfg); err != nil {
			return nil, err
		}
		if cfg.Key == "" || cfg.Mode == "invalid" {
			return nil, fmt.Errorf("invalid credential: %s / %x", cfg.Key, cfg.Key)
		}
		integrationHooks.Lock()
		hook := integrationHooks.hooks[name]
		integrationHooks.Unlock()
		return &integrationFixture{name: name, mode: cfg.Mode, secret: cfg.Key, hook: hook}, nil
	}, source.SettingsSchema(source.Field{Key: "key", Label: "Key", Type: "secret", Required: true}, source.Field{Key: "mode", Label: "Mode", Type: "string", Default: "ok"}))
}

func integrationCall(t *testing.T, c *http.Client, method, url string, body any) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	r, err := http.NewRequest(method, url, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{integrationTestSecret, hex.EncodeToString([]byte(integrationTestSecret))} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("credential in %s %s response: %s", method, url, b)
		}
	}
	return res.StatusCode, b
}

func integrationBody(password, name, mode, key string) map[string]any {
	return map[string]any{"type": integrationTestType, "name": name, "settings": map[string]any{"mode": mode}, "secrets": map[string]string{"key": key}, "password": password}
}

func TestIntegrationAPIRoutesAndSecrets(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("probe sent an HTTP request") }))
	defer fixture.Close()
	paths := []struct {
		method, path string
		body         any
	}{
		{"GET", "", nil}, {"GET", "/types", nil}, {"POST", "/probe", map[string]string{"url": fixture.URL}},
		{"POST", "/test", integrationBody("", "test", "error", integrationTestSecret)},
		{"POST", "", integrationBody(pw, "stored", "ok", integrationTestSecret)},
		{"PUT", "/1", integrationBody(pw, "stored", "ok", "")}, {"DELETE", "/1", map[string]string{"password": pw}},
		{"POST", "/1/enable", map[string]string{"password": pw}}, {"POST", "/1/disable", map[string]string{"password": pw}},
	}
	for _, p := range paths {
		code, _ := integrationCall(t, c, p.method, ts.URL+"/api/integrations"+p.path, p.body)
		if code != 401 {
			t.Fatalf("anonymous %s %s: %d", p.method, p.path, code)
		}
	}
	// Every route requires the admin account, even the read and probe routes.
	hash, err := HashPassword("operator-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.st.CreateUser(t.Context(), "operator", hash); err != nil {
		t.Fatal(err)
	}
	doJSON(t, c, "POST", ts.URL+"/api/login", "", `{"user":"operator","password":"operator-password"}`, nil)
	for _, p := range paths {
		code, _ := integrationCall(t, c, p.method, ts.URL+"/api/integrations"+p.path, p.body)
		if code != 403 {
			t.Fatalf("non-admin %s %s: %d", p.method, p.path, code)
		}
	}
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	// Each mutating route checks the password, including enable and disable.
	for _, p := range paths {
		if p.method == "GET" || p.path == "/probe" || p.path == "/test" {
			continue
		}
		body := map[string]any{"password": "wrong"}
		if p.path == "" || p.method == "PUT" {
			body = integrationBody("wrong", "stored", "ok", integrationTestSecret)
		}
		code, _ := integrationCall(t, c, p.method, ts.URL+"/api/integrations"+p.path, body)
		if code != 403 {
			t.Fatalf("step-up %s %s: %d", p.method, p.path, code)
		}
	}
	for _, p := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/types", nil}, {"POST", "/probe", map[string]string{"url": fixture.URL}},
		{"POST", "/test", integrationBody("", "test", "error", integrationTestSecret)},
		{"POST", "/test", integrationBody("", "test", "panic", integrationTestSecret)},
		{"POST", "/test", integrationBody("", "test", "ok", integrationTestSecret)},
		{"POST", "", integrationBody(pw, "stored", "ok", integrationTestSecret)},
		{"GET", "", nil}, {"PUT", "/1", integrationBody(pw, "stored", "ok", "")},
		{"POST", "/1/disable", map[string]string{"password": pw}},
		{"POST", "/1/enable", map[string]string{"password": pw}},
	} {
		code, b := integrationCall(t, c, p.method, ts.URL+"/api/integrations"+p.path, p.body)
		if code != 200 {
			t.Fatalf("%s %s: %d %s", p.method, p.path, code, b)
		}
		if p.method == "GET" && p.path == "" && (!strings.Contains(string(b), `"set":true`) || strings.Contains(string(b), `"key":"`)) {
			t.Fatalf("secret flags: %s", b)
		}
		if p.path == "/test" && strings.Contains(string(b), `"ok":true`) && !strings.Contains(string(b), `"entities":2`) {
			t.Fatalf("nested count: %s", b)
		}
	}
	i, err := s.st.GetIntegration(t.Context(), 1)
	if err != nil || !strings.Contains(string(i.Secrets), integrationTestSecret) || strings.Contains(string(i.Settings), integrationTestSecret) {
		t.Fatalf("secret retention/separation: %+v %v", i, err)
	}
	// Edit tests reuse saved credentials, but never send them back.
	edit := integrationBody("", "stored", "ok", "")
	edit["id"] = i.ID
	if code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations/test", edit); code != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Fatal(code, string(b))
	}
	devices, err := s.st.ListDevices(t.Context())
	if err != nil || len(devices) != 0 {
		t.Fatalf("dry poll ingested: %v %v", devices, err)
	}
	for _, path := range []string{"", "/test"} {
		code, _ := integrationCall(t, c, "POST", ts.URL+"/api/integrations"+path, integrationBody(pw, "invalid", "invalid", integrationTestSecret))
		if code != 400 {
			t.Fatalf("constructor validation: %d", code)
		}
	}
	if code, _ := integrationCall(t, c, "POST", ts.URL+"/api/integrations", integrationBody(pw, "STORED", "ok", integrationTestSecret)); code != 409 {
		t.Fatal(code)
	}
	// Reject attempts to smuggle secret fields into public settings or file paths.
	for _, settings := range []map[string]any{{"key": integrationTestSecret}, {"key_file": "/some/file"}, {"mode": true}, {"interval": "1s"}, {"mode": nil}} {
		body := integrationBody(pw, "invalid", "ok", integrationTestSecret)
		body["settings"] = settings
		if code, _ := integrationCall(t, c, "POST", ts.URL+"/api/integrations", body); code != 400 {
			t.Fatal(code)
		}
	}
	if code, _ := integrationCall(t, c, "DELETE", ts.URL+"/api/integrations/1", map[string]string{"password": pw}); code != 200 {
		t.Fatal(code)
	}
	for _, p := range paths {
		if p.path != "/1" && p.path != "/1/enable" && p.path != "/1/disable" {
			continue
		}
		if code, _ := integrationCall(t, c, p.method, ts.URL+"/api/integrations"+p.path, p.body); code != 404 {
			t.Fatal(code)
		}
	}
	// Other API answers cannot accidentally include constructor/poll failures.
	for _, path := range []string{"/api/events", "/api/overview", "/api/peers", "/api/integrations"} {
		integrationCall(t, c, "GET", ts.URL+path, nil)
	}
}

func TestIntegrationSupervisorLifecycle(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	hook := make(chan string, 32)
	integrationHooks.Lock()
	for _, name := range []string{"changing", "renamed", "config-source"} {
		integrationHooks.hooks[name] = hook
	}
	integrationHooks.Unlock()
	t.Cleanup(func() {
		integrationHooks.Lock()
		for _, name := range []string{"changing", "renamed", "config-source"} {
			delete(integrationHooks.hooks, name)
		}
		integrationHooks.Unlock()
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	specs := []SourceSpec{
		{Spec: registry.Spec{Type: integrationTestType, Name: "config-source", Settings: json.RawMessage(`{"key":"config-credential","mode":"wait"}`)}},
		{Spec: registry.Spec{Type: integrationTestType, Name: "broken-config", Settings: json.RawMessage(`{"key":"config-credential","mode":"invalid"}`)}},
	}
	if err := s.RunSources(ctx, specs); err != nil {
		t.Fatal(err)
	}
	wait := func(want string) {
		t.Helper()
		select {
		case got := <-hook:
			if got != want {
				t.Fatalf("got %s want %s", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("missing %s", want)
		}
	}
	wait("start:config-source")
	call := func(method, path string, body any) {
		t.Helper()
		code, b := integrationCall(t, c, method, ts.URL+"/api/integrations"+path, body)
		if code != 200 {
			t.Fatalf("%d %s", code, b)
		}
	}
	call("POST", "", integrationBody(pw, "changing", "wait", integrationTestSecret))
	wait("start:changing")
	call("PUT", "/1", integrationBody(pw, "renamed", "wait", ""))
	wait("stop:changing")
	wait("start:renamed")
	call("POST", "/1/disable", map[string]string{"password": pw})
	wait("stop:renamed")
	call("POST", "/1/enable", map[string]string{"password": pw})
	wait("start:renamed")
	// Direct store changes are also reconciled without a server restart.
	i, _ := s.st.GetIntegration(t.Context(), 1)
	i.UpdatedAt = time.Now().UTC()
	i.Settings = json.RawMessage(`{"mode":"wait","interval":"1m"}`)
	if err := s.st.UpdateIntegration(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	wait("stop:renamed")
	wait("start:renamed")
	call("DELETE", "/1", map[string]string{"password": pw})
	wait("stop:renamed")
	call("POST", "", integrationBody(pw, "changing", "wait", integrationTestSecret))
	wait("start:changing")
	rows, _ := s.st.ListIntegrations(t.Context())
	if err := s.st.DeleteIntegration(t.Context(), rows[0].ID); err != nil {
		t.Fatal(err)
	}
	wait("stop:changing")
	// A poll error and a constructor error leave the config source alive.
	call("POST", "", integrationBody(pw, "failing", "error", integrationTestSecret))
	call("POST", "", integrationBody(pw, "healthy", "ok", integrationTestSecret))
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, b := integrationCall(t, c, "GET", ts.URL+"/api/integrations", nil)
		var views []integrationView
		if err := json.Unmarshal(b, &views); err != nil {
			t.Fatal(err)
		}
		good, bad, config, broken := false, false, false, false
		for _, v := range views {
			switch v.Name {
			case "healthy":
				good = v.Running && !v.LastPoll.IsZero() && !v.LastOKAt.IsZero() && v.LastError == ""
			case "failing":
				bad = v.Running && !v.LastPoll.IsZero() && v.LastError != ""
			case "config-source":
				config = v.FromConfig && v.Running
			case "broken-config":
				broken = v.FromConfig && !v.Running && v.LastError != ""
			}
		}
		if good && bad && config && broken {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("state: %s", b)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	wait("stop:config-source")
}

func TestIntegrationProbeLimits(t *testing.T) {
	var requests atomic.Int32
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write(make([]byte, 2<<20)) }))
	defer fixture.Close()
	fp, subject, err := probeIntegration(t.Context(), fixture.URL+"/large-body")
	want := sha256.Sum256(fixture.Certificate().Raw)
	if err != nil || fp != hex.EncodeToString(want[:]) || subject != fixture.Certificate().Subject.String() || requests.Load() != 0 {
		t.Fatalf("probe: %s %s %v HTTP=%d", fp, subject, err, requests.Load())
	}
	for _, bad := range []string{"http://127.0.0.1", "file:///etc/passwd", "https://user:pass@localhost", "https://localhost/?token=secret", "https://localhost/#secret", fixture.URL + "/" + strings.Repeat("x", 4096)} {
		if _, _, err := probeIntegration(t.Context(), bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	// A valid TLS handshake with an oversized subject is still refused.
	cert := *fixture.Certificate()
	cert.Subject = pkix.Name{CommonName: strings.Repeat("x", 4097)}
	cert.RawSubject = nil
	der, err := x509.CreateCertificate(rand.Reader, &cert, &cert, cert.PublicKey, fixture.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	large := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("probe sent HTTP") }))
	large.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: fixture.TLS.Certificates[0].PrivateKey}}}
	large.StartTLS()
	defer large.Close()
	if _, _, err := probeIntegration(t.Context(), large.URL); err == nil {
		t.Fatal("accepted oversized certificate subject")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := probeIntegration(ctx, "https://"+listener.Addr().String()); err == nil || time.Since(start) > time.Second {
		t.Fatal("probe did not honor handshake timeout", err)
	}
	<-done
	if integrationProbeTimeout != 10*time.Second {
		t.Fatal("probe timeout must be 10s")
	}
}

func TestIntegrationDryPollTimeout(t *testing.T) {
	_, _, _, s := newTestServerS(t)
	ctx, cancel := context.WithTimeout(t.Context(), integrationPollTimeout+5*time.Second)
	defer cancel()
	b, _ := json.Marshal(integrationBody("", "timeout", "wait", integrationTestSecret))
	r := httptest.NewRequest("POST", "/api/integrations/test", strings.NewReader(string(b))).WithContext(ctx)
	w := httptest.NewRecorder()
	start := time.Now()
	s.handleIntegrationTest(w, r)
	elapsed := time.Since(start)
	if elapsed < 29*time.Second || elapsed > 33*time.Second || w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":false`) || !strings.Contains(w.Body.String(), "timed out") {
		t.Fatalf("timeout: %d %s", w.Code, w.Body.String())
	}
	if integrationPollTimeout != 30*time.Second {
		t.Fatal("dry poll must be limited to 30s")
	}
	if ctx.Err() != nil {
		t.Fatalf("test used parent deadline instead of 30s poll timeout: %v", ctx.Err())
	}
}

func TestIntegrationConfigViews(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	s.cfg.Sources = []SourceSpec{
		{Spec: registry.Spec{Type: "unifi", Name: "config-unifi", Settings: json.RawMessage(`{"url":"https://controller","api_key":"` + integrationTestSecret + `"}`)}},
		{Spec: registry.Spec{Type: "proxmox", Name: "config-proxmox", Settings: json.RawMessage(`{"url":"https://pve:8006","token_secret":"` + integrationTestSecret + `"}`)}},
		{Spec: registry.Spec{Type: "tailscale", Name: "config-tailscale", Settings: json.RawMessage(`{"api_key_file":"private-key-file"}`)}},
		{Spec: registry.Spec{Type: "homeassistant", Name: "config-ha", Settings: json.RawMessage(`{"token":"` + integrationTestSecret + `","token_file":"private-token-file"}`)}},
	}
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	code, b := integrationCall(t, c, "GET", ts.URL+"/api/integrations", nil)
	var views []integrationView
	if code != 200 || json.Unmarshal(b, &views) != nil || len(views) != 4 {
		t.Fatal(code, string(b))
	}
	for _, v := range views {
		if !v.FromConfig || v.ID != 0 || v.Kind != "source" {
			t.Fatalf("config metadata: %+v", v)
		}
		for _, flag := range v.Secrets {
			if !flag.Set {
				t.Fatal("config credential not marked set", v.Name)
			}
		}
	}
	for _, path := range []string{"private-key-file", "private-token-file"} {
		if strings.Contains(string(b), path) {
			t.Fatal("config credential path returned")
		}
	}
	if code, _ := integrationCall(t, c, "DELETE", ts.URL+"/api/integrations/0", map[string]string{"password": pw}); code != 404 {
		t.Fatal("config source is mutable", code)
	}
}
