package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"netnoodle/internal/store/sqlite"
)

func newTestServer(t *testing.T) (*httptest.Server, *http.Client, string) {
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
	return ts, c, pw
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
