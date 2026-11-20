package unifiactor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/proto"
)

const testKey = "secret-unifi-api-key-never-echo"
const testMAC = "aa:bb:cc:dd:ee:01"

type fixture struct {
	prefix        string
	command       string
	devices       string
	devicesStatus int
	post          string
	postStatus    int
	users         string
	usersStatus   int
	deviceCalls   atomic.Int32
	postCalls     atomic.Int32
	userCalls     atomic.Int32
}

func newFixture() *fixture {
	return &fixture{
		prefix: "/proxy/network/api/s/default", command: "block-sta",
		devices: `{"meta":{"rc":"ok"},"data":[]}`, devicesStatus: 200,
		post: `{"meta":{"rc":"ok"}}`, postStatus: 200,
		users: `{"data":[{"blocked":true}]}`, usersStatus: 200,
	}
}

func (f *fixture) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != testKey {
			t.Error("missing API key header")
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("missing JSON accept header")
		}
		switch r.URL.Path {
		case f.prefix + "/stat/device":
			f.deviceCalls.Add(1)
			if r.Method != http.MethodGet {
				t.Error("device lookup must use GET")
			}
			w.WriteHeader(f.devicesStatus)
			_, _ = io.WriteString(w, f.devices)
		case f.prefix + "/cmd/stamgr":
			f.postCalls.Add(1)
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				t.Error("command must use POST with JSON content type")
			}
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(payload, map[string]string{"cmd": f.command, "mac": testMAC}) {
				t.Errorf("unexpected command: %v", payload)
			}
			w.WriteHeader(f.postStatus)
			_, _ = io.WriteString(w, f.post)
		case f.prefix + "/stat/user/" + testMAC:
			f.userCalls.Add(1)
			if r.Method != http.MethodGet {
				t.Error("verification must use GET")
			}
			w.WriteHeader(f.usersStatus)
			_, _ = io.WriteString(w, f.users)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func serverSettings(srv *httptest.Server) Settings {
	fp := sha256.Sum256(srv.Certificate().Raw)
	return Settings{URL: srv.URL, APIKey: testKey, Fingerprint: hex.EncodeToString(fp[:]), Site: "default", ClassicPath: "/proxy/network/api"}
}

func build(t *testing.T, s Settings) *Backend {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := actor.Registry.Build("unifi", "test-unifi", raw)
	if err != nil {
		t.Fatal(err)
	}
	out := b.(*Backend)
	t.Cleanup(out.client.CloseIdleConnections)
	return out
}

func order(action, mac string) proto.Order {
	return proto.Order{Action: action, Targets: []proto.Identifier{{Kind: "mac", Value: mac}}}
}

func TestExecute(t *testing.T) {
	for _, tc := range []struct {
		name, action, command, users, message string
	}{
		{"block", "isolate", "block-sta", `{"data":[{"blocked":true}]}`, "blocked " + testMAC + "; verified"},
		{"unblock", "unisolate", "unblock-sta", `{"data":[{"blocked":false}]}`, "unblocked " + testMAC + "; verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.command, f.users = tc.command, tc.users
			b := build(t, serverSettings(f.serve(t)))
			msg, err := b.Execute(context.Background(), order(tc.action, strings.ToUpper(testMAC)))
			if err != nil || msg != tc.message {
				t.Fatalf("message=%q err=%v", msg, err)
			}
			if f.deviceCalls.Load() != 1 || f.postCalls.Load() != 1 || f.userCalls.Load() != 1 {
				t.Fatal("expected infrastructure check, command, and verification")
			}
		})
	}
}

func TestCommandAndVerificationFailures(t *testing.T) {
	for _, tc := range []struct {
		name, post, users, want string
		postStatus, usersStatus int
	}{
		{name: "rc error", post: `{"meta":{"rc":"error","msg":"permission denied"}}`, want: "permission denied"},
		{name: "missing rc", post: `{}`, want: "API rc"},
		{name: "invalid command JSON", post: `{`, want: "invalid command response"},
		{name: "HTTP command error", postStatus: 403, want: "HTTP 403"},
		{name: "HTTP API error", postStatus: 403, post: `{"meta":{"rc":"error","msg":"permission denied"}}`, want: "permission denied"},
		{name: "key in HTTP error", postStatus: 403, post: `{"meta":{"rc":"error","msg":"` + testKey + `"}}`, want: "[redacted]"},
		{name: "verify mismatch", users: `{"data":[{"blocked":false}]}`, want: "verification failed"},
		{name: "verify missing field", users: `{"data":[{}]}`, want: "verification failed"},
		{name: "verify rc error", users: `{"meta":{"rc":"error","msg":"verify denied"},"data":[]}`, want: "verify denied"},
		{name: "verify invalid JSON", users: `{`, want: "invalid verification response"},
		{name: "verify HTTP error", usersStatus: 500, want: "HTTP 500"},
		{name: "key in rc", post: `{"meta":{"rc":"` + testKey + `","msg":"echo ` + testKey + `"}}`, want: "[redacted]"},
		{name: "key in verify", users: `{"meta":{"rc":"error","msg":"` + testKey + `"}}`, want: "[redacted]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			if tc.post != "" {
				f.post = tc.post
			}
			if tc.users != "" {
				f.users = tc.users
			}
			if tc.postStatus != 0 {
				f.postStatus = tc.postStatus
			}
			if tc.usersStatus != 0 {
				f.usersStatus = tc.usersStatus
			}
			b := build(t, serverSettings(f.serve(t)))
			_, err := b.Execute(context.Background(), order("isolate", testMAC))
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), testKey) {
				t.Fatalf("expected %q with no key, got %v", tc.want, err)
			}
			if (tc.post != "" || tc.postStatus != 0) && f.userCalls.Load() != 0 {
				t.Fatal("verification sent after command failure")
			}
		})
	}
}

func TestUnknownClient(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"404", "unknown client", 404}, {"empty data", `{"data":[]}`, 200}, {"empty body", "", 200},
	} {
		for _, action := range []string{"isolate", "unisolate"} {
			t.Run(tc.name+"/"+action, func(t *testing.T) {
				f := newFixture()
				f.users, f.usersStatus = tc.body, tc.status
				state := "blocked"
				if action == "unisolate" {
					f.command, state = "unblock-sta", "unblocked"
				}
				b := build(t, serverSettings(f.serve(t)))
				msg, err := b.Execute(context.Background(), order(action, testMAC))
				if err != nil || msg != state+" (not verified: client unknown to stat/user)" {
					t.Fatalf("message=%q err=%v", msg, err)
				}
			})
		}
	}
}

func TestProtectedTargets(t *testing.T) {
	for _, protection := range []string{"never_block", "adopted device"} {
		for _, action := range []string{"isolate", "unisolate"} {
			t.Run(protection+"/"+action, func(t *testing.T) {
				f := newFixture()
				if protection == "adopted device" {
					f.devices = `{"data":[{"mac":"AA:BB:CC:DD:EE:01"}]}`
				}
				s := serverSettings(f.serve(t))
				if protection == "never_block" {
					s.NeverBlock = []string{testMAC}
				}
				b := build(t, s)
				if _, err := b.Execute(context.Background(), order(action, testMAC)); err == nil {
					t.Fatal("protected target accepted")
				}
				if f.postCalls.Load() != 0 || f.userCalls.Load() != 0 {
					t.Fatal("protected target changed")
				}
				if protection == "never_block" && f.deviceCalls.Load() != 0 {
					t.Fatal("local protection made a request")
				}
			})
		}
	}
}

func TestInvalidOrders(t *testing.T) {
	f := newFixture()
	b := build(t, serverSettings(f.serve(t)))
	for _, o := range []proto.Order{
		order("isolate", "garbage"), order("isolate", "aa:bb:cc:dd:ee:ff:00:11"),
		{Action: "isolate"},
		{Action: "isolate", Targets: []proto.Identifier{{Kind: "mac", Value: testMAC}, {Kind: "mac", Value: testMAC}}},
		{Action: "isolate", Targets: []proto.Identifier{{Kind: "ip", Value: "192.0.2.1"}}},
		order("reboot", testMAC),
	} {
		if _, err := b.Execute(context.Background(), o); err == nil {
			t.Errorf("invalid order accepted: %+v", o)
		}
	}
	if f.deviceCalls.Load() != 0 || f.postCalls.Load() != 0 {
		t.Fatal("invalid order made a request")
	}
}

func TestInfrastructureCache(t *testing.T) {
	f := newFixture()
	b := build(t, serverSettings(f.serve(t)))
	for i := 0; i < 2; i++ {
		if _, err := b.Execute(context.Background(), order("isolate", testMAC)); err != nil {
			t.Fatal(err)
		}
	}
	if f.deviceCalls.Load() != 1 {
		t.Fatal("device list was not cached")
	}
	b.devicesAt = time.Now().Add(-deviceCacheTTL)
	if _, err := b.Execute(context.Background(), order("isolate", testMAC)); err != nil {
		t.Fatal(err)
	}
	if f.deviceCalls.Load() != 2 {
		t.Fatal("expired device cache was not refreshed")
	}
}

func TestInfrastructureFailsClosed(t *testing.T) {
	for _, body := range []string{`{`, `{}`, `{"data":[{}]}`, `{"meta":{"rc":"error","msg":"` + testKey + `"},"data":[]}`} {
		t.Run(body, func(t *testing.T) {
			f := newFixture()
			f.devices = body
			b := build(t, serverSettings(f.serve(t)))
			for i := 0; i < 2; i++ {
				_, err := b.Execute(context.Background(), order("isolate", testMAC))
				if err == nil || strings.Contains(err.Error(), testKey) {
					t.Fatalf("unsafe error: %v", err)
				}
			}
			if f.postCalls.Load() != 0 || f.deviceCalls.Load() != 2 {
				t.Fatal("failed device fetch was used or cached")
			}
		})
	}
}

func TestSettings(t *testing.T) {
	for _, raw := range []string{
		`{"url":"https://example.com","api_key":"` + testKey + `","api_key_file":"key"}`,
		`{"url":"https://example.com"}`,
		`{"url":"http://example.com","api_key":"` + testKey + `"}`,
		`{"url":"https://user:pass@example.com","api_key":"` + testKey + `"}`,
		`{"url":"https://example.com?key=` + testKey + `","api_key":"` + testKey + `"}`,
		`{"url":"https://example.com","api_key":"` + testKey + `","` + testKey + `":true}`,
		`{"url":"https://example.com","api_key":"` + testKey + `"} {}`,
		`{"url":"https://example.com","api_key":"` + testKey + `","never_block":["invalid"]}`,
		`{"url":"https://example.com","api_key":"` + testKey + `","site":"../other"}`,
		`{"url":"https://example.com","api_key":"` + testKey + `","classic_path":"/api/../other"}`,
		`{"url":"https://example.com","api_key":"` + testKey + `","fingerprint":"invalid"}`,
	} {
		if _, err := New("test", json.RawMessage(raw)); err == nil || strings.Contains(err.Error(), testKey) {
			t.Errorf("settings accepted or unsafe error: %v", err)
		}
	}
	b, err := New("defaults", json.RawMessage(`{"url":"https://example.com/","api_key":"`+testKey+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	u := b.(*Backend)
	t.Cleanup(u.client.CloseIdleConnections)
	if u.base != "https://example.com/proxy/network/api/s/default" || u.client.Timeout != 20*time.Second {
		t.Fatalf("unexpected defaults: %s %v", u.base, u.client.Timeout)
	}
	if b.Name() != "defaults" || !reflect.DeepEqual(b.Capabilities(), []proto.Capability{
		{Action: "isolate", TargetIDKinds: []string{"mac"}, Reversible: true, RevertAction: "unisolate"},
		{Action: "unisolate", TargetIDKinds: []string{"mac"}},
	}) {
		t.Fatal("incorrect name or capabilities")
	}
}

func TestKeyFileAndClassicPath(t *testing.T) {
	f := newFixture()
	f.prefix = "/api/s/lab"
	s := serverSettings(f.serve(t))
	s.APIKey, s.APIKeyFile = "", filepath.Join(t.TempDir(), "key")
	s.Site, s.ClassicPath = "lab", "/api"
	if err := os.WriteFile(s.APIKeyFile, []byte(testKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	b := build(t, s)
	if err := os.Remove(s.APIKeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Execute(context.Background(), order("isolate", testMAC)); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	if _, err := New("missing file", raw); err == nil || strings.Contains(err.Error(), testKey) {
		t.Fatalf("error=%v", err)
	}
	if err := os.WriteFile(s.APIKeyFile, []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New("empty file", raw); err == nil {
		t.Fatal("empty key accepted")
	}
}

func TestResponseLimit(t *testing.T) {
	for _, endpoint := range []string{"device", "post", "user"} {
		t.Run(endpoint, func(t *testing.T) {
			f := newFixture()
			body := strings.Repeat(" ", maxResponseBody+1)
			switch endpoint {
			case "device":
				f.devices = body
			case "post":
				f.post = body
			case "user":
				f.users = body
			}
			b := build(t, serverSettings(f.serve(t)))
			if _, err := b.Execute(context.Background(), order("isolate", testMAC)); err == nil || !strings.Contains(err.Error(), "4 MiB") {
				t.Fatalf("oversized response error=%v", err)
			}
		})
	}
}

func TestTLSAndNoRedirects(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/proxy/network/api/s/default/stat/device" {
			t.Error("followed redirect")
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	s := serverSettings(srv)
	b := build(t, s)
	if _, err := b.Execute(context.Background(), order("isolate", testMAC)); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("redirect followed")
	}
	for _, mode := range []string{"wrong pin", "system roots"} {
		t.Run(mode, func(t *testing.T) {
			s := serverSettings(srv)
			s.Fingerprint = ""
			if mode == "wrong pin" {
				s.Fingerprint = strings.Repeat("00", 32)
			}
			b := build(t, s)
			if _, err := b.Execute(context.Background(), order("isolate", testMAC)); err == nil || strings.Contains(err.Error(), testKey) {
				t.Fatalf("TLS error=%v", err)
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatal("TLS verification bypassed")
	}
	s.Fingerprint, s.Insecure = "", true
	b = build(t, s)
	if _, err := b.Execute(context.Background(), order("isolate", testMAC)); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("insecure opt-in error=%v", err)
	}
}
