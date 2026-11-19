package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netnoodle/internal/inventory"
	"netnoodle/internal/proto"
	"netnoodle/internal/store/sqlite"
)

const token = "PVEAPIToken=nn@pve!audit=secret-uuid"

func fakePVE(t *testing.T) *httptest.Server {
	t.Helper()
	data := map[string]string{
		"/api2/json/cluster/status": `[{"type":"cluster","name":"lab"},
			{"type":"node","name":"pve1","ip":"10.0.0.11","online":1},{"type":"node","name":"pve2","ip":"10.0.0.12","online":0}]`,
		"/api2/json/cluster/resources": `[
			{"id":"qemu/100","type":"qemu","node":"pve1","vmid":100,"name":"web","status":"running","tags":"prod"},
			{"id":"lxc/101","type":"lxc","node":"pve1","vmid":101,"name":"dns","status":"running"},
			{"id":"qemu/9000","type":"qemu","node":"pve2","vmid":9000,"name":"tpl","status":"stopped","template":1},
			{"id":"qemu/102","type":"qemu","node":"pve2","vmid":102,"name":"old","status":"stopped"},
			{"id":"storage/pve1/local","type":"storage","node":"pve1"}]`,
		"/api2/json/nodes/pve1/version":         `{"version":"8.2.4","release":"8.2"}`,
		"/api2/json/nodes/pve1/qemu/100/config": `{"net0":"virtio=BC:24:11:00:01:00,bridge=vmbr0,firewall=1","ostype":"l26","name":"web"}`,
		"/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces": `{"result":[{"name":"lo","hardware-address":"00:00:00:00:00:00","ip-addresses":[{"ip-address":"127.0.0.1"}]},
			{"name":"ens18","hardware-address":"bc:24:11:00:01:00","ip-addresses":[{"ip-address":"10.0.0.50"},{"ip-address":"fe80::1"}]}]}`,
		"/api2/json/nodes/pve1/qemu/100/agent/get-osinfo": `{"result":{"pretty-name":"Debian GNU/Linux 12 (bookworm)","id":"debian","version-id":"12"}}`,
		"/api2/json/nodes/pve1/lxc/101/config":            `{"net0":"name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:01:01,ip=10.0.0.53/24,type=veth","ostype":"alpine"}`,
		"/api2/json/nodes/pve1/lxc/101/interfaces":        `[{"name":"lo","hwaddr":"00:00:00:00:00:00","inet":"127.0.0.1/8"},{"name":"eth0","hwaddr":"bc:24:11:00:01:01","inet":"10.0.0.53/24"}]`,
		"/api2/json/nodes/pve2/qemu/102/config":           `{"net0":"e1000=BC:24:11:00:01:02,bridge=vmbr1"}`,
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != token {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api2/json/cluster/resources" && r.URL.Query().Get("type") != "vm" {
			http.Error(w, "type", http.StatusBadRequest)
			return
		}
		d, ok := data[r.URL.Path]
		if !ok {
			http.Error(w, "not found", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"data":` + d + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newSource(t *testing.T, srv *httptest.Server, secret string) *Source {
	t.Helper()
	sum := sha256.Sum256(srv.Certificate().Raw)
	raw, _ := json.Marshal(Settings{URL: srv.URL, TokenID: "nn@pve!audit", TokenSecret: secret, FP: hex.EncodeToString(sum[:])})
	s, err := New("pve", raw)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Source)
}

func TestPoll(t *testing.T) {
	srv := fakePVE(t)
	src := newSource(t, srv, "secret-uuid")
	var obs []proto.Observation
	if err := src.Poll(context.Background(), func(o proto.Observation) error { obs = append(obs, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("observations = %d", len(obs))
	}
	n1 := obs[0].Entities[0]
	if n1.Name != "pve1" || n1.Identifiers[0].Value != "lab/pve1" || n1.Attributes["pve.version"] != "8.2.4" || len(n1.Children) != 2 {
		t.Fatalf("node pve1 = %+v", n1)
	}
	web := n1.Children[0]
	if web.Kind != proto.KindVM || web.Identifiers[0].Value != "lab/100" || web.Attributes["os.id"] != "debian" ||
		len(web.Interfaces) != 1 || web.Interfaces[0].MAC != "bc:24:11:00:01:00" ||
		strings.Join(web.Interfaces[0].IPs, ",") != "10.0.0.50,fe80::1" {
		t.Fatalf("web = %+v", web)
	}
	dns := n1.Children[1]
	if dns.Kind != proto.KindContainer || strings.Join(dns.Interfaces[0].IPs, ",") != "10.0.0.53" {
		t.Fatalf("dns = %+v", dns)
	}
	n2 := obs[1].Entities[0]
	if len(n2.Children) != 1 || n2.Children[0].Attributes["proxmox.status"] != "stopped" {
		t.Fatalf("pve2 children = %+v (template must be skipped)", n2.Children)
	}

	// The tree lands in the inventory: guests are children of their node.
	ctx := context.Background()
	st, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, o := range obs {
		if _, err := inventory.Ingest(ctx, st, o, nil, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	devs, _ := st.ListDevices(ctx)
	byName := map[string]int64{}
	parent := map[string]int64{}
	for _, d := range devs {
		byName[d.Name] = d.ID
		parent[d.Name] = d.ParentID
	}
	if len(devs) != 5 || parent["web"] != byName["pve1"] || parent["dns"] != byName["pve1"] || parent["old"] != byName["pve2"] {
		t.Fatalf("tree = %+v", devs)
	}
}

func TestBadToken(t *testing.T) {
	srv := fakePVE(t)
	err := newSource(t, srv, "wrong").Poll(context.Background(), func(proto.Observation) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
}

func TestSettings(t *testing.T) {
	for _, raw := range []string{
		`{"url":"http://pve:8006","token_id":"a@pam!b","token_secret":"x"}`,
		`{"url":"https://pve:8006","token_id":"nobang","token_secret":"x"}`,
		`{"url":"https://pve:8006","token_id":"a@pam!b"}`,
	} {
		if _, err := New("pve", json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
