package pveactor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/proto"
)

const (
	testSecret  = "pve-secret-never-echo"
	testTokenID = "nn-actor@pve!act"
	testUPID    = "UPID:pve1:00012345:00012345:00012345:qmsnapshot:100:nn-actor@pve!act:"
)

type fixture struct {
	mu                                sync.Mutex
	cluster, resources                string
	guestType                         string
	config                            map[string]any
	verify                            map[string]any
	want                              url.Values
	putStatus                         int
	putBody                           string
	putReason                         string
	responseEndpoint, responseBody    string
	getCalls, putCalls, snapshotCalls atomic.Int32
}

func newFixture() *fixture {
	return &fixture{
		cluster:   `[{"type":"cluster","name":"lab"},{"type":"node","name":"pve1"}]`,
		resources: `[{"vmid":100,"node":"pve1","type":"qemu","template":0}]`,
		guestType: "qemu",
		config: map[string]any{
			"digest": "original-digest", "memory": 2048,
			"net0":  "virtio=BC:24:11:00:00:01,bridge=vmbr0,link_down=0,firewall=1,tag=42",
			"net1":  "e1000=BC:24:11:00:00:02,bridge=vmbr1,rate=12.5",
			"net-1": "not an interface", "net1foo": "not an interface",
		},
		want: url.Values{
			"digest": {"original-digest"},
			"net0":   {"virtio=BC:24:11:00:00:01,bridge=vmbr0,link_down=1,firewall=1,tag=42"},
			"net1":   {"e1000=BC:24:11:00:00:02,bridge=vmbr1,rate=12.5,link_down=1"},
		},
		putStatus: 200, putBody: `{"data":null}`,
	}
}

func (f *fixture) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "PVEAPIToken="+testTokenID+"="+testSecret {
			t.Error("missing API token authorization")
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("missing JSON accept header")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			f.getCalls.Add(1)
		}
		if r.Method+" "+r.URL.Path == f.responseEndpoint {
			_, _ = io.WriteString(w, f.responseBody)
			return
		}
		base := "/api2/json/nodes/pve1/" + f.guestType + "/100"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/status":
			_, _ = io.WriteString(w, `{"data":`+f.cluster+`}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/resources":
			if r.URL.RawQuery != "type=vm" {
				t.Error("missing VM resource filter")
			}
			_, _ = io.WriteString(w, `{"data":`+f.resources+`}`)
		case r.Method == http.MethodGet && r.URL.Path == base+"/config":
			cfg := f.config
			if f.putCalls.Load() > 0 && f.verify != nil {
				cfg = f.verify
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": cfg})
		case (r.Method == http.MethodPut && r.URL.Path == base+"/config") || (r.Method == http.MethodPost && r.URL.Path == base+"/snapshot"):
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("mutation must be form-encoded")
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(r.PostForm, f.want) {
				t.Errorf("form = %v, want %v", r.PostForm, f.want)
			}
			if r.Method == http.MethodPost {
				f.snapshotCalls.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": testUPID})
				return
			}
			f.putCalls.Add(1)
			if f.putStatus == 200 {
				for key, values := range r.PostForm {
					if key != "digest" {
						f.config[key] = values[0]
					}
				}
			}
			if f.putReason != "" {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, _ = fmt.Fprintf(rw, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", f.putStatus, f.putReason, len(f.putBody), f.putBody)
				_ = rw.Flush()
				return
			}
			w.WriteHeader(f.putStatus)
			_, _ = io.WriteString(w, f.putBody)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func serverSettings(srv *httptest.Server) Settings {
	fp := sha256.Sum256(srv.Certificate().Raw)
	return Settings{URL: srv.URL, TokenID: testTokenID, TokenSecret: testSecret, Fingerprint: hex.EncodeToString(fp[:]), Source: "pve"}
}

func build(t *testing.T, s Settings) *Backend {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := actor.Registry.Build("proxmox", "test-pve", raw)
	if err != nil {
		t.Fatal(err)
	}
	p := b.(*Backend)
	t.Cleanup(p.client.CloseIdleConnections)
	return p
}

func order(action string) proto.Order {
	return proto.Order{ID: "12345678-abcd-4321-bbbb-0123456789ab", Action: action, Targets: []proto.Identifier{{Kind: "proxmox.guest", Value: "pve/lab/100"}}}
}

func TestNetwork(t *testing.T) {
	for _, name := range []string{"qemu isolate", "lxc isolate", "unisolate", "protected unisolate", "standalone", "only changed keys"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			o := order("isolate")
			state := "isolated"
			if name == "only changed keys" {
				f.config["net1"] = f.want.Get("net1")
				f.want.Del("net1")
			}
			if name == "lxc isolate" {
				f.guestType = "lxc"
				f.resources = `[{"vmid":100,"node":"pve1","type":"lxc"}]`
				f.config = map[string]any{"digest": "original-digest", "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=192.0.2.1/24,ip6=auto,firewall=1"}
				f.want = url.Values{"digest": {"original-digest"}, "net0": {"name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=192.0.2.1/24,ip6=auto,firewall=1,link_down=1"}}
			}
			if strings.Contains(name, "unisolate") {
				o.Action, state = "unisolate", "unisolated"
				f.config["net0"] = "virtio=BC:24:11:00:00:01,bridge=vmbr0,link_down=1,firewall=1,tag=42"
				f.config["net1"] = "link_down=1,e1000=BC:24:11:00:00:02,bridge=vmbr1,rate=12.5"
				f.want.Set("net0", "virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1,tag=42")
				f.want.Set("net1", "e1000=BC:24:11:00:00:02,bridge=vmbr1,rate=12.5")
			}
			if name == "standalone" {
				f.cluster = `[{"type":"node","name":"pve1"}]`
				o.Targets[0].Value = "pve/standalone/100"
			}
			s := serverSettings(f.serve(t))
			if name == "protected unisolate" {
				s.NeverIsolate = []int{100}
			}
			b := build(t, s)
			msg, err := b.Execute(context.Background(), o)
			interfaces := "net0, net1"
			if name == "lxc isolate" {
				interfaces = "net0"
			}
			if err != nil || msg != state+" "+interfaces+"; verified" {
				t.Fatalf("message=%q err=%v", msg, err)
			}
			if f.putCalls.Load() != 1 || f.getCalls.Load() != 4 {
				t.Fatalf("PUT=%d GET=%d", f.putCalls.Load(), f.getCalls.Load())
			}
		})
	}
}

func TestNoOpNetwork(t *testing.T) {
	for _, action := range []string{"isolate", "unisolate"} {
		t.Run(action, func(t *testing.T) {
			f := newFixture()
			if action == "isolate" {
				f.config["net0"], f.config["net1"] = f.want.Get("net0"), f.want.Get("net1")
			} else {
				f.config["net0"] = "virtio=BC:24:11:00:00:01,bridge=vmbr0"
			}
			b := build(t, serverSettings(f.serve(t)))
			if _, err := b.Execute(context.Background(), order(action)); err != nil {
				t.Fatal(err)
			}
			if f.putCalls.Load() != 0 || f.getCalls.Load() != 4 {
				t.Fatal("no-op must skip PUT but still verify")
			}
		})
	}
}

func TestNetworkFailures(t *testing.T) {
	for _, name := range []string{"verify mismatch", "verify missing interface", "verify added interface", "verify other options changed", "digest conflict", "digest conflict reason", "API error secret", "escaped API error secret", "HTTP reason secret", "invalid PUT response"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			want := "verification failed"
			switch name {
			case "verify mismatch":
				f.verify = map[string]any{"net0": f.config["net0"], "net1": f.want.Get("net1")}
			case "verify missing interface":
				f.verify = map[string]any{"net0": f.want.Get("net0")}
			case "verify added interface":
				f.verify = map[string]any{"net0": f.want.Get("net0"), "net1": f.want.Get("net1"), "net2": "virtio=BC:24:11:00:00:03"}
			case "verify other options changed":
				f.verify = map[string]any{"net0": strings.ReplaceAll(f.want.Get("net0"), "vmbr0", "vmbr9"), "net1": f.want.Get("net1")}
			case "digest conflict":
				f.putStatus, f.putBody, want = 500, `{"data":null,"message":"checksum mismatch (file changed by other user?)"}`, "checksum mismatch"
			case "digest conflict reason":
				f.putStatus, f.putBody, f.putReason, want = 500, `{"data":null}`, "checksum mismatch (file changed by other user?)", "checksum mismatch"
			case "API error secret":
				f.putStatus, f.putBody, want = 403, `{"message":"`+testSecret+`","errors":{"net0":"PVEAPIToken=`+testTokenID+`=`+testSecret+`"}}`, "[redacted]"
			case "escaped API error secret":
				f.putStatus, f.putBody, want = 403, `{"errors":{"net0":"\u0070ve-secret-never-echo"}}`, "[redacted]"
			case "HTTP reason secret":
				f.putStatus, f.putBody, f.putReason, want = 500, `{"data":null}`, "PVEAPIToken="+testTokenID+"="+testSecret, "[redacted]"
			case "invalid PUT response":
				f.putBody, want = `{`, "invalid API response"
			}
			b := build(t, serverSettings(f.serve(t)))
			_, err := b.Execute(context.Background(), order("isolate"))
			if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), testSecret) {
				t.Fatalf("want %q without secret, got %v", want, err)
			}
			if f.putCalls.Load() != 1 {
				t.Fatal("expected one PUT")
			}
			if (f.putStatus != 200 || name == "invalid PUT response") && f.getCalls.Load() != 3 {
				t.Fatal("verified after failed PUT")
			}
		})
	}
}

func TestRefusedGuests(t *testing.T) {
	for _, name := range []string{"template", "protected", "wrong source", "wrong cluster", "not found", "ambiguous", "invalid type", "invalid node", "no interfaces", "missing digest", "invalid interface", "invalid link_down", "duplicate link_down"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			o := order("isolate")
			want := name
			switch name {
			case "template":
				f.resources = `[{"vmid":100,"node":"pve1","type":"qemu","template":1}]`
			case "protected":
				want = "never_isolate"
			case "wrong source":
				o.Targets[0].Value = "other/lab/100"
				want = "configured source"
			case "wrong cluster":
				o.Targets[0].Value = "pve/other/100"
				want = "cluster"
			case "not found":
				f.resources = `[]`
			case "ambiguous":
				f.resources = `[{"vmid":100,"node":"pve1","type":"qemu"},{"vmid":100,"node":"pve2","type":"qemu"}]`
			case "invalid type":
				f.resources = `[{"vmid":100,"node":"pve1","type":"node"}]`
				want = "invalid"
			case "invalid node":
				f.resources = `[{"vmid":100,"node":"..","type":"qemu"}]`
				want = "invalid"
			case "no interfaces":
				f.config = map[string]any{"digest": "original-digest"}
				want = "no network interfaces"
			case "missing digest":
				delete(f.config, "digest")
				want = "missing digest"
			case "invalid interface":
				f.config["net0"] = 123
				want = "invalid network"
			case "invalid link_down":
				f.config["net0"] = "virtio=BC:24:11:00:00:01,link_down=2"
				want = "link_down"
			case "duplicate link_down":
				f.config["net0"] = "virtio=BC:24:11:00:00:01,link_down=0,link_down=1"
				want = "link_down"
			}
			s := serverSettings(f.serve(t))
			if name == "protected" {
				s.NeverIsolate = []int{100}
			}
			b := build(t, s)
			_, err := b.Execute(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("want %q, got %v", want, err)
			}
			if f.putCalls.Load() != 0 || f.snapshotCalls.Load() != 0 {
				t.Fatal("refused guest mutated")
			}
			if (name == "protected" || name == "wrong source") && f.getCalls.Load() != 0 {
				t.Fatal("local refusal made a request")
			}
			if name == "wrong cluster" && f.getCalls.Load() != 1 {
				t.Fatal("wrong cluster queried resources")
			}
		})
	}
}

func TestSnapshot(t *testing.T) {
	for _, guestType := range []string{"qemu", "lxc"} {
		for _, id := range []string{"12345678-abcd-4321-bbbb-0123456789ab", "a_B-9"} {
			t.Run(guestType+"/"+id, func(t *testing.T) {
				f := newFixture()
				f.guestType = guestType
				f.resources = `[{"vmid":100,"node":"pve1","type":"` + guestType + `"}]`
				o := order("snapshot")
				o.ID = id
				prefix := id
				if len(prefix) > 12 {
					prefix = prefix[:12]
				}
				f.want = url.Values{"snapname": {"nn-" + prefix}, "description": {"netnoodle order " + id}}
				s := serverSettings(f.serve(t))
				s.NeverIsolate = []int{100}
				b := build(t, s)
				msg, err := b.Execute(context.Background(), o)
				if err != nil || msg != testUPID {
					t.Fatalf("message=%q err=%v", msg, err)
				}
				if f.snapshotCalls.Load() != 1 || f.putCalls.Load() != 0 || f.getCalls.Load() != 2 {
					t.Fatal("snapshot must return immediately without polling")
				}
			})
		}
	}
}

func TestInvalidOrders(t *testing.T) {
	f := newFixture()
	b := build(t, serverSettings(f.serve(t)))
	orders := []proto.Order{{Action: "isolate"}, order("reboot")}
	for _, value := range []string{"pve/lab/99", "pve/lab/1000000000", "pve/lab/+100", "pve/lab/0100", "pve/lab/100/extra", "pve/lab/abc", "pve//100", "pve/../100", "pve/lab/-100"} {
		o := order("isolate")
		o.Targets[0].Value = value
		orders = append(orders, o)
	}
	o := order("isolate")
	o.Targets = append(o.Targets, o.Targets[0])
	orders = append(orders, o)
	o = order("isolate")
	o.Targets[0].Kind = "mac"
	orders = append(orders, o)
	for _, id := range []string{"", "bad/id", "bad id", "äbc"} {
		o := order("snapshot")
		o.ID = id
		orders = append(orders, o)
	}
	for _, o := range orders {
		if _, err := b.Execute(context.Background(), o); err == nil {
			t.Errorf("accepted invalid order: %+v", o)
		}
	}
	if f.getCalls.Load() != 0 || f.putCalls.Load() != 0 || f.snapshotCalls.Load() != 0 {
		t.Fatal("invalid order made a request")
	}
}

func TestInvalidAPIResponses(t *testing.T) {
	for _, tc := range []struct{ endpoint, body string }{
		{"GET /api2/json/cluster/status", `{`},
		{"GET /api2/json/cluster/status", `{}`},
		{"GET /api2/json/cluster/status", `{"data":null}`},
		{"GET /api2/json/cluster/resources", `{"data":{}}`},
		{"GET /api2/json/nodes/pve1/qemu/100/config", `{"data":"` + testSecret + `"}`},
		{"POST /api2/json/nodes/pve1/qemu/100/snapshot", `{"data":"missing UPID"}`},
	} {
		t.Run(tc.endpoint+tc.body, func(t *testing.T) {
			f := newFixture()
			f.responseEndpoint, f.responseBody = tc.endpoint, tc.body
			b := build(t, serverSettings(f.serve(t)))
			action := "isolate"
			if strings.HasPrefix(tc.endpoint, "POST") {
				action = "snapshot"
			}
			_, err := b.Execute(context.Background(), order(action))
			if err == nil || strings.Contains(err.Error(), testSecret) {
				t.Fatalf("error=%v", err)
			}
			if f.putCalls.Load() != 0 {
				t.Fatal("invalid API response permitted mutation")
			}
		})
	}
}

func TestSettings(t *testing.T) {
	valid := Settings{URL: "https://pve1:8006/", TokenID: testTokenID, TokenSecret: testSecret, Source: "pve"}
	for _, name := range []string{"both secrets", "no secret", "blank secret", "newline secret", "bad token", "newline token", "no URL", "http", "userinfo", "path", "query", "fragment", "no source", "bad source", "low protected VMID", "high protected VMID", "bad fingerprint"} {
		t.Run(name, func(t *testing.T) {
			s := valid
			switch name {
			case "both secrets":
				s.TokenSecretFile = testSecret
			case "no secret":
				s.TokenSecret = ""
			case "blank secret":
				s.TokenSecret = " "
			case "newline secret":
				s.TokenSecret += "\n"
			case "bad token":
				s.TokenID = "bad-token"
			case "newline token":
				s.TokenID += "\n"
			case "no URL":
				s.URL = ""
			case "http":
				s.URL = "http://pve1:8006"
			case "userinfo":
				s.URL = "https://user:" + testSecret + "@pve1:8006"
			case "path":
				s.URL += "api2/json"
			case "query":
				s.URL += "?key=" + testSecret
			case "fragment":
				s.URL += "#" + testSecret
			case "no source":
				s.Source = ""
			case "bad source":
				s.Source = "pve/other"
			case "low protected VMID":
				s.NeverIsolate = []int{99}
			case "high protected VMID":
				s.NeverIsolate = []int{1000000000}
			case "bad fingerprint":
				s.Fingerprint = testSecret
			}
			raw, _ := json.Marshal(s)
			if _, err := New("test", raw); err == nil || strings.Contains(err.Error(), testSecret) {
				t.Fatalf("settings accepted or unsafe error: %v", err)
			}
		})
	}
	for _, raw := range []string{`{`, `null`, `[]`, `{"token_secret":"` + testSecret + `","` + testSecret + `":true}`, `{"token_secret":123}`, `{} {}`} {
		if _, err := New("test", json.RawMessage(raw)); err == nil || strings.Contains(err.Error(), testSecret) {
			t.Fatalf("settings accepted or unsafe error: %v", err)
		}
	}
	b := build(t, valid)
	if b.Name() != "test-pve" || b.base != "https://pve1:8006/api2/json" || b.client.Timeout != 30*time.Second {
		t.Fatal("incorrect name, base or timeout")
	}
	if !reflect.DeepEqual(b.Capabilities(), []proto.Capability{
		{Action: "isolate", TargetIDKinds: []string{"proxmox.guest"}, Reversible: true, RevertAction: "unisolate"},
		{Action: "unisolate", TargetIDKinds: []string{"proxmox.guest"}},
		{Action: "snapshot", TargetIDKinds: []string{"proxmox.guest"}},
	}) {
		t.Fatal("incorrect capabilities")
	}
}

func TestSecretFile(t *testing.T) {
	f := newFixture()
	s := serverSettings(f.serve(t))
	s.TokenSecret, s.TokenSecretFile = "", filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(s.TokenSecretFile, []byte(testSecret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	b := build(t, s)
	if err := os.Remove(s.TokenSecretFile); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Execute(context.Background(), order("isolate")); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	if _, err := New("test", raw); err == nil || strings.Contains(err.Error(), s.TokenSecretFile) {
		t.Fatalf("unsafe missing-file error=%v", err)
	}
	if err := os.WriteFile(s.TokenSecretFile, []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New("test", raw); err == nil {
		t.Fatal("empty secret file accepted")
	}
}

func TestResponseLimit(t *testing.T) {
	for _, endpoint := range []string{"GET /api2/json/cluster/status", "GET /api2/json/cluster/resources", "GET /api2/json/nodes/pve1/qemu/100/config", "PUT /api2/json/nodes/pve1/qemu/100/config", "POST /api2/json/nodes/pve1/qemu/100/snapshot"} {
		t.Run(endpoint, func(t *testing.T) {
			f := newFixture()
			f.responseEndpoint, f.responseBody = endpoint, strings.Repeat(" ", maxResponseBody+1)
			b := build(t, serverSettings(f.serve(t)))
			action := "isolate"
			if strings.HasPrefix(endpoint, "POST") {
				action = "snapshot"
			}
			_, err := b.Execute(context.Background(), order(action))
			if err == nil || !strings.Contains(err.Error(), "4 MiB") {
				t.Fatalf("response limit error=%v", err)
			}
		})
	}
}

func TestTLSAndNoRedirects(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api2/json/cluster/status" {
			t.Error("followed redirect")
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	s := serverSettings(srv)
	b := build(t, s)
	if _, err := b.Execute(context.Background(), order("isolate")); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("followed redirect")
	}
	for _, mode := range []string{"wrong pin", "system roots", "wrong pin with insecure"} {
		t.Run(mode, func(t *testing.T) {
			s := serverSettings(srv)
			s.Fingerprint = ""
			if strings.HasPrefix(mode, "wrong pin") {
				s.Fingerprint = strings.Repeat("00", 32)
			}
			s.Insecure = strings.HasSuffix(mode, "with insecure")
			b := build(t, s)
			if _, err := b.Execute(context.Background(), order("isolate")); err == nil || strings.Contains(err.Error(), testSecret) {
				t.Fatalf("TLS error=%v", err)
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatal("TLS verification bypassed")
	}
	s.Fingerprint, s.Insecure = "", true
	b = build(t, s)
	if _, err := b.Execute(context.Background(), order("isolate")); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("insecure opt-in error=%v", err)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport echoed PVEAPIToken=" + testTokenID + "=" + testSecret)
}

func TestTransportErrorRedacted(t *testing.T) {
	f := newFixture()
	b := build(t, serverSettings(f.serve(t)))
	b.client.Transport = failingTransport{}
	_, err := b.Execute(context.Background(), order("isolate"))
	if err == nil || strings.Contains(err.Error(), testSecret) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("unsafe transport error=%v", err)
	}
}

func TestExampleConfig(t *testing.T) {
	f, err := os.Open("../../../deploy/nn-actor.proxmox.example.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var cfg actor.Config
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	var enabled int
	for _, spec := range cfg.Backends {
		if spec.Disabled {
			continue
		}
		enabled++
		var settings Settings
		d := json.NewDecoder(strings.NewReader(string(spec.Settings)))
		d.DisallowUnknownFields()
		if err := d.Decode(&settings); err != nil {
			t.Fatal(err)
		}
		if spec.Type != "proxmox" || settings.Source != "pve" {
			t.Fatal("incorrect example backend")
		}
	}
	if enabled != 1 || cfg.DryRun == nil || !*cfg.DryRun {
		t.Fatal("example must enable one backend in dry-run")
	}
}
