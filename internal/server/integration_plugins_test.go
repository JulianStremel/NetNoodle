package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	_ "github.com/JulianStremel/netnoodle/internal/intel/epss"
	_ "github.com/JulianStremel/netnoodle/internal/intel/kev"
	_ "github.com/JulianStremel/netnoodle/internal/intel/msrc"
	_ "github.com/JulianStremel/netnoodle/internal/intel/osv"
	"github.com/JulianStremel/netnoodle/internal/notify"
	_ "github.com/JulianStremel/netnoodle/internal/notify/webhook"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
)

type secretMatcher struct{ name, key string }

func (m *secretMatcher) Name() string { return m.name }
func (m *secretMatcher) Match(context.Context, []proto.Component) ([]intel.Hit, error) {
	return nil, nil
}
func (m *secretMatcher) Refresh(context.Context) error { return fmt.Errorf("reflected %s", m.key) }
func init() {
	intel.Matchers.RegisterWithSchema("secret-test", func(name string, raw json.RawMessage) (intel.Matcher, error) {
		var s struct {
			Key string `json:"key"`
		}
		if err := registry.Decode(raw, &s); err != nil {
			return nil, err
		}
		return &secretMatcher{name, s.Key}, nil
	}, registry.Schema{Fields: []registry.Field{{Key: "key", Label: "Key", Type: "secret", Required: true}}})
}

func TestAllIntegrationKindsAPI(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	var sent atomic.Int32
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hook":
			if r.Header.Get("X-Key") != integrationTestSecret {
				t.Error("missing webhook credential")
			}
			var e notify.Event
			json.NewDecoder(r.Body).Decode(&e)
			if e.Type != "integration.test" {
				t.Error(e.Type)
			}
			sent.Add(1)
		case "/v1/chat/completions", "/v1/messages":
			var req map[string]any
			json.NewDecoder(r.Body).Decode(&req)
			if req["model"] != "entered-model" || !strings.Contains(fmt.Sprint(req["messages"]), "Reply with OK") {
				t.Error(req)
			}
			if r.URL.Path == "/v1/messages" {
				if r.Header.Get("X-Api-Key") != integrationTestSecret {
					t.Error("anthropic key")
				}
				fmt.Fprint(w, `{"content":[{"type":"text","text":"`+integrationTestSecret+`"}]}`)
			} else {
				if r.Header.Get("Authorization") != "Bearer "+integrationTestSecret {
					t.Error("openai key")
				}
				fmt.Fprint(w, `{"choices":[{"message":{"content":"`+integrationTestSecret+`"}}]}`)
			}
		case "/v1/querybatch":
			fmt.Fprint(w, `{"results":[]}`)
		case "/cvrf/v3.0/updates":
			fmt.Fprint(w, `{"value":[{"ID":"2026-Nov","InitialReleaseDate":"2026-11-10T08:00:00Z"}]}`)
		case "/cvrf/v3.0/cvrf/2026-Nov":
			b, err := os.ReadFile("../intel/msrc/testdata/2026-Nov.json")
			if err != nil {
				t.Error(err)
			}
			w.Write(b)
		case "/kev":
			fmt.Fprint(w, `{"vulnerabilities":[{"cveID":"CVE-2026-0001"}]}`)
		case "/epss":
			fmt.Fprint(w, "cve,epss,percentile\nCVE-2026-0001,0.1,0.2\n")
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer remote.Close()
	originalTransport := http.DefaultTransport
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = remote.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	transport.TLSClientConfig.RootCAs.AddCert(remote.Certificate())
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = originalTransport; transport.CloseIdleConnections() })
	cases := []struct {
		kind, typ string
		settings  map[string]any
		secrets   map[string]string
		testOK    bool
	}{
		{"source", integrationTestType, map[string]any{"mode": "ok"}, map[string]string{"key": integrationTestSecret}, true},
		{"notify", "webhook", map[string]any{"types": []string{"device."}}, map[string]string{"url": remote.URL + "/hook", "headers_json": `{"X-Key":"` + integrationTestSecret + `"}`}, true},
		{"notify", "mqtt", map[string]any{"broker": "mqtts://127.0.0.1:1"}, map[string]string{"password": integrationTestSecret}, false},
		{"intel", "secret-test", map[string]any{}, map[string]string{"key": integrationTestSecret}, false},
		{"intel", "osv", map[string]any{"url": remote.URL, "concurrency": 2}, nil, true},
		{"intel", "msrc", map[string]any{"url": remote.URL, "months": 1}, nil, true},
		{"intel", "kev", map[string]any{"url": remote.URL + "/kev"}, nil, true},
		{"intel", "epss", map[string]any{"url": remote.URL + "/epss"}, nil, true},
		{"llm", "openai", map[string]any{"base_url": remote.URL, "model": "entered-model"}, map[string]string{"api_key": integrationTestSecret}, true},
		{"llm", "anthropic", map[string]any{"base_url": remote.URL, "model": "entered-model"}, map[string]string{"api_key": integrationTestSecret}, true},
	}
	code, b := integrationCall(t, c, "GET", ts.URL+"/api/integrations/types", nil)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	for _, tc := range cases {
		t.Run(tc.kind+"/"+tc.typ, func(t *testing.T) {
			body := map[string]any{"kind": tc.kind, "type": tc.typ, "name": "saved-" + tc.typ, "settings": tc.settings, "secrets": tc.secrets, "password": pw, "enabled": false}
			code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations", body)
			if code != 200 {
				t.Fatal(code, string(b))
			}
			var saved struct{ ID int64 }
			json.Unmarshal(b, &saved)
			path := fmt.Sprintf("%s/api/integrations/%d", ts.URL, saved.ID)
			blank := map[string]string{}
			for key := range tc.secrets {
				blank[key] = ""
			}
			body["secrets"] = blank
			code, b = integrationCall(t, c, "PUT", path, body)
			if code != 200 {
				t.Fatal(code, string(b))
			}
			row, err := s.st.GetIntegration(t.Context(), saved.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.secrets) > 0 && !strings.Contains(string(row.Secrets), integrationTestSecret) {
				t.Fatal("secret lost")
			}
			body["id"] = saved.ID
			code, b = integrationCall(t, c, "POST", ts.URL+"/api/integrations/test", body)
			if code != 200 || strings.Contains(string(b), `"ok":true`) != tc.testOK {
				t.Fatal(code, string(b))
			}
			if tc.kind == "llm" && (!strings.Contains(string(b), `"reply_length":`) || !strings.Contains(string(b), `"latency_ms":`)) {
				t.Fatal(string(b))
			}
			delete(body, "id")
			for _, path := range []string{"/api/integrations", "/api/overview", "/api/events", "/api/peers"} {
				integrationCall(t, c, "GET", ts.URL+path, nil)
			}
			for _, action := range []string{"enable", "disable"} {
				code, b = integrationCall(t, c, "POST", path+"/"+action, map[string]string{"password": pw})
				if code != 200 {
					t.Fatal(code, string(b))
				}
			}
			code, b = integrationCall(t, c, "DELETE", path, map[string]string{"password": pw})
			if code != 200 {
				t.Fatal(code, string(b))
			}
		})
	}
	if sent.Load() != 1 {
		t.Fatal("test notifier delivery", sent.Load())
	}
	devices, _ := s.st.ListDevices(t.Context())
	findings, _ := s.st.ListFindings(t.Context(), store.FindingFilter{})
	if len(devices) != 0 || len(findings) != 0 {
		t.Fatal("test saved results")
	}
}

func TestNotificationAndIntelReload(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	events := make(chan string, 16)
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/hook") {
			events <- r.URL.Path
			return
		}
		fmt.Fprint(w, `{"vulnerabilities":[{"cveID":"`+strings.TrimPrefix(r.URL.Path, "/")+`"}]}`)
	}))
	defer remote.Close()
	originalTransport := http.DefaultTransport
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = remote.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	transport.TLSClientConfig.RootCAs.AddCert(remote.Certificate())
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = originalTransport; transport.CloseIdleConnections() })
	s.cfg.Notifiers = []registry.Spec{{Type: "webhook", Name: "file-hook", Settings: json.RawMessage(`{"url":"` + remote.URL + `/hook-config"}`)}}
	s.cfg.Enrichers = []registry.Spec{{Type: "kev", Name: "file-kev", Settings: json.RawMessage(`{"url":"` + remote.URL + `/CVE-config"}`)}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := s.RunSources(ctx, nil); err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body any) []byte {
		t.Helper()
		code, b := integrationCall(t, c, method, ts.URL+"/api/integrations"+path, body)
		if code != 200 {
			t.Fatal(code, string(b))
		}
		return b
	}
	for _, kind := range []string{"notify", "intel"} {
		typ, endpoint := "webhook", "/hook-first"
		if kind == "intel" {
			typ, endpoint = "kev", "/CVE-first"
		}
		body := map[string]any{"kind": kind, "type": typ, "name": "live-" + typ, "settings": map[string]any{"url": remote.URL + endpoint}, "password": pw}
		if kind == "notify" {
			body["settings"] = map[string]any{}
			body["secrets"] = map[string]string{"url": remote.URL + endpoint}
		}
		var saved struct{ ID int64 }
		json.Unmarshal(call("POST", "", body), &saved)
		path := fmt.Sprintf("/%d", saved.ID)
		verify := func(endpoint string) {
			t.Helper()
			if kind == "notify" {
				ns := s.notifierSnapshot()
				if len(ns) != 2 {
					t.Fatal(len(ns))
				}
				for _, n := range ns {
					if n.Name() == "live-webhook" {
						if err := n.Notify(ctx, notify.Event{Type: "device.new"}); err != nil {
							t.Fatal(err)
						}
					}
				}
				select {
				case got := <-events:
					if got != endpoint {
						t.Fatal(got)
					}
				case <-time.After(time.Second):
					t.Fatal("missing event")
				}
			} else {
				_, es := s.intelPlugins()
				if len(es) != 2 {
					t.Fatal(len(es))
				}
				for _, e := range es {
					if e.Name() == "live-kev" {
						if err := e.Refresh(ctx); err != nil {
							t.Fatal(err)
						}
						v := intel.Vuln{ID: strings.TrimPrefix(endpoint, "/")}
						e.Enrich(&v)
						if !v.KEV {
							t.Fatal("old feed still installed")
						}
					}
				}
			}
		}
		verify(endpoint)
		if kind == "notify" {
			endpoint = "/hook-second"
		} else {
			endpoint = "/CVE-second"
		}
		body["settings"] = map[string]any{"url": remote.URL + endpoint}
		if kind == "notify" {
			body["settings"] = map[string]any{}
			body["secrets"] = map[string]string{"url": remote.URL + endpoint}
		} else {
			body["secrets"] = map[string]string{"url": remote.URL + endpoint}
		}
		call("PUT", path, body)
		verify(endpoint)
		call("POST", path+"/disable", map[string]string{"password": pw})
		if kind == "notify" {
			if len(s.notifierSnapshot()) != 1 {
				t.Fatal("notifier not disabled")
			}
		} else {
			_, es := s.intelPlugins()
			if len(es) != 1 {
				t.Fatal("enricher not disabled")
			}
		}
		call("POST", path+"/enable", map[string]string{"password": pw})
		verify(endpoint)
		call("DELETE", path, map[string]string{"password": pw})
	}
	// Concurrent readers hold immutable slices while writers replace them.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				ns := s.notifierSnapshot()
				s.SetNotifiers(ns)
				s.intelPlugins()
			}
		})
	}
	wg.Wait()
}

func TestAllKindsConfigReadOnly(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	s.cfg.Notifiers = []registry.Spec{
		{Type: "webhook", Name: "config-webhook", Settings: json.RawMessage(`{"url":"https://hook.example","headers":{"Authorization":"` + integrationTestSecret + `"}}`)},
		{Type: "mqtt", Name: "config-mqtt", Settings: json.RawMessage(`{"broker":"mqtts://broker.example","password_file":"private-mqtt-path"}`)},
	}
	s.cfg.Matchers = []registry.Spec{{Type: "osv", Name: "config-osv", Settings: json.RawMessage(`{"url":"https://osv.example","cache_ttl":"2h","concurrency":3}`)}}
	s.cfg.LLMs = []registry.Spec{{Type: "anthropic", Name: "config-llm", Settings: json.RawMessage(`{"model":"entered","api_key":"` + integrationTestSecret + `"}`)}}
	s.cfg.MQTT = json.RawMessage(`{"broker":"mqtts://legacy.example","password_file":"private-mqtt-path"}`)
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	code, b := integrationCall(t, c, "GET", ts.URL+"/api/integrations", nil)
	var rows []integrationView
	if code != 200 || json.Unmarshal(b, &rows) != nil || len(rows) != 5 || strings.Contains(string(b), "private-mqtt-path") {
		t.Fatal(code, string(b))
	}
	for _, row := range rows {
		if !row.FromConfig || row.ID != 0 {
			t.Fatal(row)
		}
		for _, flag := range row.Secrets {
			if !flag.Set {
				t.Fatal("config secret flag", row.Name)
			}
		}
		if !s.reservedName(row.Name) {
			t.Fatal("unreserved config name", row.Name)
		}
	}
	for _, action := range []string{"/enable", "/disable", ""} {
		method := "POST"
		if action == "" {
			method = "DELETE"
		}
		code, b = integrationCall(t, c, method, ts.URL+"/api/integrations/0"+action, map[string]string{"password": pw})
		if code != 404 {
			t.Fatal(code, string(b))
		}
	}
}

func TestIntelMatcherReloadAndSafeErrors(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := s.RunSources(ctx, nil); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"kind": "intel", "type": "secret-test", "name": "live-matcher", "secrets": map[string]string{"key": integrationTestSecret}, "password": pw}
	code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations", body)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	var saved struct{ ID int64 }
	json.Unmarshal(b, &saved)
	path := fmt.Sprintf("%s/api/integrations/%d", ts.URL, saved.ID)
	ms, _ := s.intelPlugins()
	if len(ms) != 1 {
		t.Fatal("matcher not installed")
	}
	old := ms[0]
	s.refreshFeeds(ctx)
	for _, p := range []string{"/api/integrations", "/api/events", "/api/overview"} {
		integrationCall(t, c, "GET", ts.URL+p, nil)
	}
	body["secrets"] = map[string]string{"key": ""}
	code, b = integrationCall(t, c, "PUT", path, body)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	ms, _ = s.intelPlugins()
	if len(ms) != 1 || ms[0] == old {
		t.Fatal("matcher was not replaced")
	}
	if ms[0].(*secretMatcher).key != integrationTestSecret {
		t.Fatal("matcher lost credentials")
	}
	for _, action := range []string{"disable", "enable"} {
		code, b = integrationCall(t, c, "POST", path+"/"+action, map[string]string{"password": pw})
		if code != 200 {
			t.Fatal(code, string(b))
		}
		ms, _ = s.intelPlugins()
		want := 0
		if action == "enable" {
			want = 1
		}
		if len(ms) != want {
			t.Fatal(action, "matcher count", len(ms))
		}
	}
	code, b = integrationCall(t, c, "DELETE", path, map[string]string{"password": pw})
	if code != 200 {
		t.Fatal(code, string(b))
	}
	ms, _ = s.intelPlugins()
	if len(ms) != 0 {
		t.Fatal("deleted matcher still installed")
	}
}

func TestManagedMQTTLifecycle(t *testing.T) {
	ts, c, pw, s := newTestServerS(t)
	doJSON(t, c, "POST", ts.URL+"/api/login", "", fmt.Sprintf(`{"user":"admin","password":%q}`, pw), nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := s.RunSources(ctx, nil); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"kind": "notify", "type": "mqtt", "name": "managed-mqtt", "settings": map[string]any{"broker": "mqtts://127.0.0.1:1"}, "password": pw}
	code, b := integrationCall(t, c, "POST", ts.URL+"/api/integrations", body)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	var saved struct{ ID int64 }
	json.Unmarshal(b, &saved)
	path := fmt.Sprintf("%s/api/integrations/%d", ts.URL, saved.ID)
	active := func() *activeIntegration {
		s.integrations.mu.Lock()
		defer s.integrations.mu.Unlock()
		return s.integrations.plugins[integrationKey(saved.ID)]
	}
	first := active()
	if first == nil || first.cancel == nil || len(s.notifierSnapshot()) != 1 {
		t.Fatal("publisher not started")
	}
	body["settings"] = map[string]any{"broker": "mqtts://127.0.0.1:1", "topic_prefix": "changed"}
	code, b = integrationCall(t, c, "PUT", path, body)
	if code != 200 {
		t.Fatal(code, string(b))
	}
	select {
	case <-first.done:
	default:
		t.Fatal("old publisher still running")
	}
	second := active()
	if second == first || second.cancel == nil {
		t.Fatal("publisher not replaced")
	}
	code, b = integrationCall(t, c, "POST", path+"/disable", map[string]string{"password": pw})
	if code != 200 {
		t.Fatal(code, string(b))
	}
	select {
	case <-second.done:
	default:
		t.Fatal("disabled publisher still running")
	}
	if len(s.notifierSnapshot()) != 0 {
		t.Fatal("disabled publisher still receives events")
	}
	code, b = integrationCall(t, c, "POST", path+"/enable", map[string]string{"password": pw})
	if code != 200 {
		t.Fatal(code, string(b))
	}
	third := active()
	code, b = integrationCall(t, c, "DELETE", path, map[string]string{"password": pw})
	if code != 200 {
		t.Fatal(code, string(b))
	}
	select {
	case <-third.done:
	default:
		t.Fatal("deleted publisher still running")
	}
	if len(s.notifierSnapshot()) != 0 {
		t.Fatal("deleted publisher still receives events")
	}
}
