package unifi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

// fakeController serves a minimal Integration API with paging.
func fakeController(t *testing.T, key string) *httptest.Server {
	t.Helper()
	sites := []map[string]any{{"id": "s-1", "internalReference": "default", "name": "Default"}}
	devices := []map[string]any{{
		"id": "d-1", "name": "Gateway", "model": "UDM Pro", "macAddress": "74:ac:b9:00:00:01",
		"ipAddress": "192.168.1.1", "state": "ONLINE", "firmwareVersion": "4.0.21",
	}}
	var clients []map[string]any
	for i := 0; i < 250; i++ { // more than one page
		clients = append(clients, map[string]any{
			"id": fmt.Sprintf("c-%d", i), "type": "WIRED", "name": fmt.Sprintf("host%d", i),
			"macAddress": fmt.Sprintf("00:1a:2b:00:%02x:%02x", i/256, i%256), "ipAddress": fmt.Sprintf("192.168.1.%d", 10+i%240),
			"uplinkDeviceId": "d-1",
		})
	}
	pageOf := func(w http.ResponseWriter, r *http.Request, data []map[string]any) {
		off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		lim, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		end := min(off+lim, len(data))
		if off > len(data) {
			off = len(data)
		}
		json.NewEncoder(w).Encode(map[string]any{"offset": off, "limit": lim, "count": end - off, "totalCount": len(data), "data": data[off:end]})
	}
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-API-KEY") != key {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	base := "/proxy/network/integration/v1"
	mux.HandleFunc(base+"/sites", auth(func(w http.ResponseWriter, r *http.Request) { pageOf(w, r, sites) }))
	mux.HandleFunc(base+"/sites/s-1/devices", auth(func(w http.ResponseWriter, r *http.Request) { pageOf(w, r, devices) }))
	mux.HandleFunc(base+"/sites/s-1/clients", auth(func(w http.ResponseWriter, r *http.Request) { pageOf(w, r, clients) }))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func fingerprintOf(srv *httptest.Server) string {
	return fmt.Sprintf("%x", sha256sum(srv.Certificate().Raw))
}

func TestPoll(t *testing.T) {
	srv := fakeController(t, "secret")
	settings := fmt.Sprintf(`{"url":%q,"api_key":"secret","fingerprint":%q}`, srv.URL, fingerprintOf(srv))
	src, err := New("unifi-home", json.RawMessage(settings))
	if err != nil {
		t.Fatal(err)
	}
	var got []proto.Observation
	if err := src.Poll(context.Background(), func(o proto.Observation) error { got = append(got, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Entities) != 251 {
		t.Fatalf("observations = %d, entities = %d", len(got), len(got[0].Entities))
	}
	gw := got[0].Entities[0]
	if gw.Kind != proto.KindNetworkDevice || gw.Attributes["firmware"] != "4.0.21" || len(gw.Components) != 1 ||
		gw.Components[0].PURL != "pkg:generic/ubiquiti/udm-pro@4.0.21" {
		t.Fatalf("gateway = %+v", gw)
	}
}

func TestBadKeyAndPin(t *testing.T) {
	srv := fakeController(t, "secret")
	ctx := context.Background()
	src, _ := New("u", json.RawMessage(fmt.Sprintf(`{"url":%q,"api_key":"wrong","fingerprint":%q}`, srv.URL, fingerprintOf(srv))))
	if err := src.Poll(ctx, func(proto.Observation) error { return nil }); err == nil {
		t.Fatal("wrong key accepted")
	}
	bad := "00" + fingerprintOf(srv)[2:]
	src, _ = New("u", json.RawMessage(fmt.Sprintf(`{"url":%q,"api_key":"secret","fingerprint":%q}`, srv.URL, bad)))
	if err := src.Poll(ctx, func(proto.Observation) error { return nil }); err == nil {
		t.Fatal("wrong pin accepted")
	}
}

func TestSelectSites(t *testing.T) {
	all := []site{{ID: "a", Name: "Default"}, {ID: "b", Name: "Office"}}
	if s, err := selectSites(all, []string{"office"}); err != nil || len(s) != 1 || s[0].ID != "b" {
		t.Fatalf("got %v %v", s, err)
	}
	if _, err := selectSites(all, []string{"nope"}); err == nil {
		t.Fatal("missing site accepted")
	}
}

func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }
