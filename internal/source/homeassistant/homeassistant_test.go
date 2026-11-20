package homeassistant

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const secret = "do-not-print-this-ha-token"

func tokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

type fixture struct {
	devices     []device
	supervisor  bool
	badAuth     bool
	failCommand string
}

func fakeHA(t *testing.T, f fixture) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/websocket" {
			t.Errorf("path = %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		wsjson.Write(ctx, c, map[string]string{"type": "auth_required"})
		var auth map[string]string
		if wsjson.Read(ctx, c, &auth) != nil {
			return
		}
		if auth["type"] != "auth" || auth["access_token"] != secret {
			t.Error("incorrect authentication")
			return
		}
		if f.badAuth {
			c.Close(websocket.StatusPolicyViolation, secret)
			return
		}
		wsjson.Write(ctx, c, map[string]string{"type": "auth_ok"})
		last := 0
		for {
			var req struct {
				ID       int    `json:"id"`
				Type     string `json:"type"`
				Endpoint string `json:"endpoint"`
				Method   string `json:"method"`
			}
			if wsjson.Read(ctx, c, &req) != nil {
				return
			}
			if req.ID <= last {
				t.Error("IDs not increasing")
				return
			}
			last = req.ID
			var result any
			success := true
			switch req.Type {
			case "config/device_registry/list":
				result = f.devices
			case "config/entity_registry/list":
				result = []registryEntity{{"device_tracker.router", "physical"}, {"sensor.unrelated", "physical"}, {"device_tracker.orphan", ""}}
			case "get_states":
				result = []map[string]any{
					{"entity_id": "device_tracker.router", "attributes": map[string]string{"ip": "192.168.1.20", "mac": "AA-BB-CC-00-11-22", "host_name": "router.local"}},
					{"entity_id": "sensor.unrelated", "attributes": map[string]string{"ip": "192.168.1.99"}},
					{"entity_id": "sensor.other", "attributes": map[string]any{"ip": 12345, "host_name": []string{"unrelated"}}},
				}
			case "get_config":
				result = config{Version: "2026.11.0", LocationName: "Home", InternalURL: "http://192.168.1.2:8123"}
			case "supervisor/api":
				if req.Method != "get" {
					t.Error("supervisor method")
				}
				success = f.supervisor
				switch req.Endpoint {
				case "/os/info":
					result = map[string]any{"data": map[string]string{"version": "16.3"}, "result": "ok"}
				case "/core/info":
					result = map[string]any{"version": "2026.11.0"}
				case "/addons":
					result = map[string]any{"addons": []map[string]string{{"slug": "core_mosquitto", "name": "Mosquitto", "version": "6.5.2"}}}
				default:
					t.Error("unexpected Supervisor endpoint")
				}
			default:
				t.Errorf("unexpected command %s", req.Type)
			}
			if req.Type == f.failCommand {
				success = false
			}
			if wsjson.Write(ctx, c, map[string]any{"id": req.ID, "type": "result", "success": success, "result": result, "error": map[string]string{"message": secret}}) != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sampleDevices() []device {
	return []device{
		{ID: "physical", Name: "Old name", NameByUser: "Router", Manufacturer: "Acme Inc", Model: "Router Pro", SW: "1.2.3", HW: "v2", Area: "office", Connections: [][]string{{"mac", "AA:BB:CC:00:11:22"}, {"mac", "aa:bb:cc:00:11:23"}, {"zigbee", "ignored"}}},
		{ID: "virtual", Name: "Virtual bridge", EntryType: "service"},
	}
}

func sourceFor(t *testing.T, srv *httptest.Server, extra map[string]any) *Source {
	t.Helper()
	fp := sha256.Sum256(srv.Certificate().Raw)
	settings := map[string]any{"url": srv.URL, "token_file": tokenFile(t), "fingerprint": fmt.Sprintf("%x", fp)}
	for k, v := range extra {
		settings[k] = v
	}
	b, _ := json.Marshal(settings)
	s, err := New("ha-home", b)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Source)
}

func hasID(e proto.Entity, kind, value string, strength proto.Strength) bool {
	for _, id := range e.Identifiers {
		if id.Kind == kind && id.Value == value && id.Strength == strength {
			return true
		}
	}
	return false
}

func TestPoll(t *testing.T) {
	for _, supervisor := range []bool{false, true} {
		t.Run(fmt.Sprint(supervisor), func(t *testing.T) {
			srv := fakeHA(t, fixture{devices: sampleDevices(), supervisor: supervisor})
			s := sourceFor(t, srv, nil)
			var got proto.Observation
			if err := s.Poll(context.Background(), func(o proto.Observation) error { got = o; return nil }); err != nil {
				t.Fatal(err)
			}
			if len(got.Entities) != 2 {
				t.Fatalf("entities = %+v", got.Entities)
			}
			host, physical := got.Entities[0], got.Entities[1]
			if host.Kind != proto.KindHost || host.Name != "Home" || !hasID(host, "homeassistant.instance", "ha-home", proto.Strong) || !hasID(host, "ip", "192.168.1.2", proto.Weak) || len(host.Children) != 1 || host.Children[0].Name != "Virtual bridge" {
				t.Fatalf("host = %+v", host)
			}
			want := 1
			if supervisor {
				want = 3
			}
			if len(host.Components) != want || host.Components[0].PURL != "pkg:pypi/homeassistant@2026.11.0" {
				t.Fatalf("components = %+v", host.Components)
			}
			if supervisor && (host.Components[1].PURL != "pkg:generic/home-assistant/haos@16.3" || host.Components[2].PURL != "pkg:generic/home-assistant-addon/core_mosquitto@6.5.2") {
				t.Fatalf("supervisor components = %+v", host.Components)
			}
			if physical.Name != "Router" || physical.Kind != proto.KindNetworkDevice || !hasID(physical, "homeassistant.device", "ha-home/physical", proto.Strong) || !hasID(physical, "mac", "aa:bb:cc:00:11:22", proto.Strong) || !hasID(physical, "mac", "aa:bb:cc:00:11:23", proto.Strong) || !hasID(physical, "ip", "192.168.1.20", proto.Weak) || !hasID(physical, "hostname", "router.local", proto.Weak) {
				t.Fatalf("physical = %+v", physical)
			}
			if hasID(physical, "ip", "192.168.1.99", proto.Weak) || physical.Attributes["ha.manufacturer"] != "Acme Inc" || physical.Attributes["ha.hw_version"] != "v2" || physical.Attributes["ha.area"] != "office" || len(physical.Components) != 1 || physical.Components[0].Confidence != proto.Low || physical.Components[0].PURL != "pkg:generic/acme-inc/router-pro@1.2.3" {
				t.Fatalf("mapping = %+v", physical)
			}
		})
	}
}

func TestSettingsValidation(t *testing.T) {
	file := tokenFile(t)
	for _, tc := range []struct {
		url       string
		allow, ok bool
	}{
		{"https://ha.local:8123", false, true}, {"http://ha.local:8123", false, false}, {"http://ha.local:8123", true, false}, {"http://127.0.0.1:8123", true, true},
		{"http://127.0.0.1:8123", true, true}, {"http://[::1]:8123", true, true}, {"http://localhost", true, false},
		{"http://example.com", true, false}, {"http://192.168.1.2", true, false}, {"ws://ha.local", true, false},
		{"https://user:secret@ha.local", false, false}, {"https://ha.local/path", false, false}, {"https://ha.local?token=secret", false, false},
	} {
		b, _ := json.Marshal(map[string]any{"url": tc.url, "allow_http": tc.allow, "token_file": file})
		_, err := New("ha", b)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.url, err)
		}
	}
	for _, raw := range []string{`{"url":"https://ha.local"}`, `{"token":"` + secret + `"}`, `{"url":"https://ha.local","token_file":"missing"}`, `{} {}`, `null`} {
		_, err := New("ha", json.RawMessage(raw))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("settings error = %v", err)
		}
	}
}

func TestCapsAndTrackersDisabled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		devices []device
		fail    bool
	}{
		{"device_count", make([]device, maxDevices+1), true},
		{"connections", []device{{ID: "x", Connections: make([][]string, maxConnections+1)}}, true},
		{"id", []device{{ID: strings.Repeat("x", maxField+1)}}, true},
		{"fields", []device{{ID: "x", Name: strings.Repeat("é", maxField), Manufacturer: strings.Repeat("m", 300)}}, false},
		{"trackers_disabled", sampleDevices(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sourceFor(t, fakeHA(t, fixture{devices: tc.devices}), map[string]any{"include_trackers": false})
			var got proto.Observation
			err := s.Poll(context.Background(), func(o proto.Observation) error { got = o; return nil })
			if (err != nil) != tc.fail {
				t.Fatalf("error = %v", err)
			}
			if !tc.fail {
				for _, e := range got.Entities {
					if len(e.Name) > maxField || len(e.Attributes["ha.manufacturer"]) > maxField || hasID(e, "ip", "192.168.1.20", proto.Weak) {
						t.Fatalf("caps/trackers = %+v", e)
					}
				}
			}
		})
	}
}

func TestErrorsNeverContainToken(t *testing.T) {
	s := sourceFor(t, fakeHA(t, fixture{badAuth: true}), nil)
	err := s.Poll(context.Background(), func(proto.Observation) error { t.Error("unexpected emit"); return nil })
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v", err)
	}
	s = sourceFor(t, fakeHA(t, fixture{failCommand: "get_config"}), nil)
	err = s.Poll(context.Background(), func(proto.Observation) error { t.Error("unexpected emit"); return nil })
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("command error = %v", err)
	}
	s = sourceFor(t, fakeHA(t, fixture{}), map[string]any{"fingerprint": strings.Repeat("0", 64)})
	if err := s.Poll(context.Background(), func(proto.Observation) error { return nil }); err == nil {
		t.Fatal("bad pin accepted")
	}
}

func TestMaximumRegistryFitsIngest(t *testing.T) {
	for _, virtual := range []bool{false, true} {
		t.Run(fmt.Sprint(virtual), func(t *testing.T) {
			devices := make([]device, maxDevices)
			for i := range devices {
				devices[i] = device{ID: fmt.Sprintf("d%d", i)}
				if virtual {
					devices[i].EntryType = "service"
				}
			}
			s := sourceFor(t, fakeHA(t, fixture{devices: devices}), map[string]any{"include_trackers": false})
			calls, physical, children := 0, 0, 0
			err := s.Poll(context.Background(), func(o proto.Observation) error {
				calls++
				n := len(o.Entities)
				for _, e := range o.Entities {
					n += len(e.Children)
					children += len(e.Children)
					if e.Kind != proto.KindHost {
						physical++
					}
				}
				if n > maxDevices {
					t.Errorf("observation contains %d entities", n)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 2 || physical+children != maxDevices || (virtual && children != maxDevices) {
				t.Fatalf("calls %d, physical %d, virtual %d", calls, physical, children)
			}
		})
	}
}
