package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/JulianStremel/netnoodle/internal/store/sqlite"
)

func newTestServer(t *testing.T) (*httptest.Server, *http.Client, string) {
	t.Helper()
	ts, c, pw, _ := newTestServerS(t)
	return ts, c, pw
}

// newTestServerS also returns the *Server.
func newTestServerS(t *testing.T) (*httptest.Server, *http.Client, string, *Server) {
	t.Helper()
	ctx := context.Background()
	st, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pw, err := EnsureAdmin(ctx, st)
	if err != nil || pw == "" {
		t.Fatalf("EnsureAdmin = %q, %v", pw, err)
	}
	ui := fstest.MapFS{"index.html": {Data: []byte("<html>ui</html>")}}
	s := New(DefaultConfig(), st, ui, "fp", slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	c := ts.Client()
	c.Jar, _ = cookiejar.New(nil)
	return ts, c, pw, s
}

func post(t *testing.T, c *http.Client, url, ctype, body string) *http.Response {
	t.Helper()
	res, err := c.Post(url, ctype, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func get(t *testing.T, c *http.Client, url string) int {
	t.Helper()
	res, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestLoginFlow(t *testing.T) {
	ts, c, pw := newTestServer(t)

	if code := get(t, c, ts.URL+"/api/me"); code != http.StatusUnauthorized {
		t.Fatalf("/api/me before login = %d", code)
	}
	if code := get(t, c, ts.URL+"/v1/health"); code != http.StatusOK {
		t.Fatalf("/v1/health = %d", code)
	}
	if code := get(t, c, ts.URL+"/"); code != http.StatusOK {
		t.Fatalf("/ = %d", code)
	}

	// Form posts are refused (CSRF protection).
	if r := post(t, c, ts.URL+"/api/login", "application/x-www-form-urlencoded", "user=admin"); r.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("form login = %d", r.StatusCode)
	}
	if r := post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"wrong"}`); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d", r.StatusCode)
	}
	if r := post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"`+pw+`"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("login = %d", r.StatusCode)
	}
	if code := get(t, c, ts.URL+"/api/me"); code != http.StatusOK {
		t.Fatalf("/api/me after login = %d", code)
	}
	if code := get(t, c, ts.URL+"/api/events"); code != http.StatusOK {
		t.Fatalf("/api/events = %d", code)
	}
	if r := post(t, c, ts.URL+"/api/logout", "application/json", `{}`); r.StatusCode != http.StatusOK {
		t.Fatalf("logout = %d", r.StatusCode)
	}
	if code := get(t, c, ts.URL+"/api/me"); code != http.StatusUnauthorized {
		t.Fatalf("/api/me after logout = %d", code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts, c, _ := newTestServer(t)
	var last int
	for i := 0; i < 12; i++ {
		last = post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"x"}`).StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after 12 failures = %d, want 429", last)
	}
}

func doJSON(t *testing.T, c *http.Client, method, url, bearer, body string, out any) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func TestEnrollAndIngest(t *testing.T) {
	ts, c, pw := newTestServer(t)
	post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"`+pw+`"}`)

	// Operator creates join tokens.
	var jt struct{ Token string }
	if code := doJSON(t, c, "POST", ts.URL+"/api/join-tokens", "", `{"role":"agent","uses":2}`, &jt); code != 200 || jt.Token == "" {
		t.Fatalf("join token: %d %+v", code, jt)
	}
	var st struct{ Token string }
	doJSON(t, c, "POST", ts.URL+"/api/join-tokens", "", `{"role":"source","name":"scan-lan"}`, &st)

	anon := ts.Client() // no cookies
	var agent, scanner struct{ Name, Role, Token string }
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/enroll", "", `{"join_token":"`+jt.Token+`","name":"web1"}`, &agent); code != 200 || agent.Role != "agent" {
		t.Fatalf("enroll agent: %d %+v", code, agent)
	}
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/enroll", "", `{"join_token":"`+jt.Token+`","name":"web1"}`, nil); code != http.StatusConflict {
		t.Fatalf("duplicate name = %d", code)
	}
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/enroll", "", `{"join_token":"`+st.Token+`","name":"ignored"}`, &scanner); code != 200 || scanner.Name != "scan-lan" {
		t.Fatalf("enroll scanner: %d %+v", code, scanner)
	}
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/enroll", "", `{"join_token":"`+st.Token+`","name":"again"}`, nil); code != http.StatusUnauthorized {
		t.Fatalf("used token = %d", code)
	}

	// Scanner sees a host with a MAC.
	scan := `{"version":"v1","source":"x","observed_at":"2026-11-19T10:00:00Z","entities":[
		{"kind":"unknown","identifiers":[{"kind":"ip","value":"10.0.0.5","strength":"weak"},{"kind":"mac","value":"00:1a:2b:00:00:05","strength":"strong"}],
		 "services":[{"port":22,"proto":"tcp","product":"openssh","version":"9.2p1"}]}]}`
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", scanner.Token, scan, nil); code != 200 {
		t.Fatalf("scan observation = %d", code)
	}
	// The agent may not send two entities.
	two := `{"version":"v1","source":"web1","observed_at":"2026-11-19T10:00:00Z","entities":[
		{"kind":"host","identifiers":[{"kind":"agent","value":"other","strength":"strong"}]},
		{"kind":"host","identifiers":[{"kind":"agent","value":"x","strength":"strong"}]}]}`
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", agent.Token, two, nil); code != http.StatusBadRequest {
		t.Fatalf("two entities = %d", code)
	}
	// The agent claims another agent id; the server replaces it with its own.
	rep := `{"version":"v1","source":"spoof","observed_at":"2026-11-19T10:01:00Z","complete":true,"entities":[
		{"kind":"host","name":"web1","identifiers":[{"kind":"agent","value":"other","strength":"strong"}],
		 "interfaces":[{"name":"eth0","mac":"00:1a:2b:00:00:05","ips":["10.0.0.5"]}],
		 "components":[{"purl":"pkg:deb/debian/openssh-server@9.2p1-2","name":"openssh-server","version":"9.2p1-2"}]}]}`
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", agent.Token, rep, nil); code != 200 {
		t.Fatalf("agent report = %d", code)
	}
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", "bad", rep, nil); code != http.StatusUnauthorized {
		t.Fatalf("bad token = %d", code)
	}

	var devs []struct {
		ID          int64
		Name        string
		Sources     []string
		Identifiers []struct{ Kind, Value string }
	}
	doJSON(t, c, "GET", ts.URL+"/api/devices", "", "", &devs)
	if len(devs) != 1 || devs[0].Name != "web1" || len(devs[0].Sources) != 2 {
		t.Fatalf("devices = %+v", devs)
	}
	for _, id := range devs[0].Identifiers {
		if id.Kind == "agent" && id.Value != "web1" {
			t.Fatalf("spoofed agent id kept: %+v", devs[0].Identifiers)
		}
	}
	var evs []struct{ Type string }
	doJSON(t, c, "GET", ts.URL+"/api/events", "", "", &evs)
	newDev := 0
	for _, e := range evs {
		if e.Type == "device.new" {
			newDev++
		}
	}
	if newDev != 1 {
		t.Fatalf("device.new events = %d", newDev)
	}
}
