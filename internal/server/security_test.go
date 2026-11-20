package server

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// Regression tests for the adversarial review of 2026-11-19.

func enrollPeer(t *testing.T, c, anon *http.Client, url, role, name string) string {
	t.Helper()
	var jt struct{ Token string }
	if code := doJSON(t, c, "POST", url+"/api/join-tokens", "", `{"role":"`+role+`"}`, &jt); code != 200 {
		t.Fatalf("join token: %d", code)
	}
	var p struct{ Token string }
	if code := doJSON(t, anon, "POST", url+"/v1/enroll", "", `{"join_token":"`+jt.Token+`","name":"`+name+`"}`, &p); code != 200 {
		t.Fatalf("enroll %s: %d", name, code)
	}
	return p.Token
}

type devRow struct {
	ID          int64
	Name        string
	Identifiers []struct{ Kind, Value, Strength string }
}

func devices(t *testing.T, c *http.Client, url string) []devRow {
	t.Helper()
	var ds []devRow
	doJSON(t, c, "GET", url+"/api/devices", "", "", &ds)
	return ds
}

func TestAgentCannotHijackDevices(t *testing.T) {
	ts, c, pw := newTestServer(t)
	post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"`+pw+`"}`)
	anon := &http.Client{Transport: ts.Client().Transport}

	victim := enrollPeer(t, c, anon, ts.URL, "agent", "db01")
	evil := enrollPeer(t, c, anon, ts.URL, "agent", "evil")
	scan := enrollPeer(t, c, anon, ts.URL, "source", "scan-lan")

	obs := func(entity string) string {
		return `{"version":"v1","source":"x","observed_at":"2026-11-19T10:00:00Z","entities":[` + entity + `]}`
	}
	// The victim agent and a scanned gateway.
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", victim, obs(
		`{"kind":"host","name":"db01","identifiers":[],"interfaces":[{"mac":"00:1a:2b:00:00:01"}]}`), nil); code != 200 {
		t.Fatalf("victim report = %d", code)
	}
	if code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", scan, obs(
		`{"kind":"network-device","name":"gw","identifiers":[{"kind":"mac","value":"00:1a:2b:00:00:fe","strength":"strong"}]}`), nil); code != 200 {
		t.Fatalf("scan report = %d", code)
	}

	// 1. Spoofed agent identifier in another spelling, plus the victim's MAC.
	code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", evil, obs(
		`{"kind":"host","name":"evil","identifiers":[{"kind":" AGENT ","value":"db01","strength":"strong"},
		  {"kind":"mac","value":"00:1a:2b:00:00:01","strength":"strong"}]}`), nil)
	if code != 200 {
		t.Fatalf("evil report = %d", code)
	}
	ds := devices(t, c, ts.URL)
	if len(ds) != 3 {
		t.Fatalf("want 3 separate devices, got %d: %+v", len(ds), ds)
	}
	for _, d := range ds {
		for _, id := range d.Identifiers {
			if id.Kind == "mac" && id.Value == "00:1a:2b:00:00:01" && d.Name != "db01" {
				t.Fatalf("victim MAC moved to %q", d.Name)
			}
			if id.Kind == "agent" && id.Value == "db01" && d.Name != "db01" {
				t.Fatalf("spoofed agent id on %q", d.Name)
			}
		}
	}

	// 1b. Claiming the victim's MAC as "weak" or a foreign kind must not work either.
	doJSON(t, anon, "POST", ts.URL+"/v1/observations", evil, obs(
		`{"kind":"host","identifiers":[{"kind":"mac","value":"00:1a:2b:00:00:01","strength":"weak"},
		  {"kind":"mac","value":"00:1a:2b:00:00:fe","strength":"weak"},
		  {"kind":"proxmox.guest","value":"lab/100","strength":"strong"}]}`), nil)
	for _, d := range devices(t, c, ts.URL) {
		for _, id := range d.Identifiers {
			if id.Kind == "mac" && id.Value == "00:1a:2b:00:00:01" && d.Name != "db01" {
				t.Fatalf("weak claim moved victim MAC to %q", d.Name)
			}
			if id.Kind == "mac" && id.Value == "00:1a:2b:00:00:fe" && d.Name != "gw" {
				t.Fatalf("weak claim moved gateway MAC to %q", d.Name)
			}
			if id.Kind == "proxmox.guest" {
				t.Fatalf("agent set a foreign identifier kind on %q", d.Name)
			}
		}
	}

	// 2. Identifier flood: the server's agent identifier must survive the cap.
	var ids []string
	for i := 0; i < 300; i++ {
		ids = append(ids, fmt.Sprintf(`{"kind":"x.junk","value":"%d","strength":"strong"}`, i))
	}
	doJSON(t, anon, "POST", ts.URL+"/v1/observations", evil, obs(`{"kind":"host","identifiers":[`+strings.Join(ids, ",")+`]}`), nil)
	found := false
	for _, d := range devices(t, c, ts.URL) {
		for _, id := range d.Identifiers {
			if id.Kind == "agent" && id.Value == "evil" {
				found = true
			}
		}
	}
	if !found || len(devices(t, c, ts.URL)) != 3 {
		t.Fatal("agent identifier lost or new device made by identifier flood")
	}

	// 3. Children, parent links and unknown fields are refused.
	for _, bad := range []string{
		obs(`{"kind":"host","identifiers":[],"children":[{"kind":"vm","identifiers":[{"kind":"mac","value":"00:1a:2b:00:00:fe","strength":"strong"}]}]}`),
		obs(`{"kind":"host","identifiers":[],"parent":[{"kind":"mac","value":"00:1a:2b:00:00:fe","strength":"strong"}]}`),
		`{"version":"v1","source":"x","observed_at":"2026-11-19T10:00:00Z","padding":"xxxx","entities":[{"kind":"host","identifiers":[]}]}`,
	} {
		if code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", evil, bad, nil); code != http.StatusBadRequest {
			t.Errorf("bad observation accepted: %d", code)
		}
	}

	// 4. A source cannot assign agent identifiers.
	doJSON(t, anon, "POST", ts.URL+"/v1/observations", scan, obs(
		`{"kind":"host","identifiers":[{"kind":"agent","value":"db01","strength":"strong"},{"kind":"mac","value":"00:1a:2b:00:00:99","strength":"strong"}]}`), nil)
	for _, d := range devices(t, c, ts.URL) {
		n := 0
		for _, id := range d.Identifiers {
			if id.Kind == "agent" && id.Value == "db01" {
				n++
			}
		}
		if n > 0 && d.Name != "db01" {
			t.Fatalf("source set agent id on device %+v", d)
		}
	}
}

func TestLoginLimiterHoldsUnderParallelRequests(t *testing.T) {
	ts, _, _ := newTestServer(t)
	anon := &http.Client{Transport: ts.Client().Transport}
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := post(t, anon, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"wrong"}`)
			mu.Lock()
			codes[res.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[http.StatusUnauthorized] > 10 {
		t.Fatalf("%d password checks ran, limit is 10 (codes %v)", codes[http.StatusUnauthorized], codes)
	}
}

func TestSmallBodyLimitOnLogin(t *testing.T) {
	ts, _, _ := newTestServer(t)
	anon := &http.Client{Transport: ts.Client().Transport}
	big := `{"user":"admin","password":"` + strings.Repeat("a", 100<<10) + `"}`
	if res := post(t, anon, ts.URL+"/api/login", "application/json", big); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("100 KiB login body = %d, want 400", res.StatusCode)
	}
}

func TestAgentContainerChildren(t *testing.T) {
	ts, c, pw := newTestServer(t)
	post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"`+pw+`"}`)
	anon := &http.Client{Transport: ts.Client().Transport}
	pve1 := enrollPeer(t, c, anon, ts.URL, "agent", "pve1")
	pve2 := enrollPeer(t, c, anon, ts.URL, "agent", "pve2")
	src := enrollPeer(t, c, anon, ts.URL, "source", "proxmox")
	obs := func(entity string) string {
		return `{"version":"v1","source":"x","observed_at":"2026-11-20T10:00:00Z","entities":[` + entity + `]}`
	}
	send := func(tok, body string) int { return doJSON(t, anon, "POST", ts.URL+"/v1/observations", tok, body, nil) }
	byName := func() map[string]devRow {
		m := map[string]devRow{}
		for _, d := range devices(t, c, ts.URL) {
			m[d.Name] = d
		}
		return m
	}

	// Host agents, then the Proxmox import puts guest "ct101" (MAC ...:01) under pve1
	// and "ct201" (MAC ...:02) under pve2.
	send(pve1, obs(`{"kind":"host","name":"pve1","identifiers":[{"kind":"mac","value":"00:1a:2b:00:10:01","strength":"strong"}]}`))
	send(pve2, obs(`{"kind":"host","name":"pve2","identifiers":[{"kind":"mac","value":"00:1a:2b:00:20:01","strength":"strong"}]}`))
	send(src, obs(`{"kind":"host","name":"pve1","identifiers":[{"kind":"mac","value":"00:1a:2b:00:10:01","strength":"strong"}],
		"children":[{"kind":"container","name":"ct101","identifiers":[{"kind":"mac","value":"bc:24:11:00:00:01","strength":"strong"}]}]}`))
	send(src, obs(`{"kind":"host","name":"pve2","identifiers":[{"kind":"mac","value":"00:1a:2b:00:20:01","strength":"strong"}],
		"children":[{"kind":"container","name":"ct201","identifiers":[{"kind":"mac","value":"bc:24:11:00:00:02","strength":"strong"}]}]}`))
	before := len(devices(t, c, ts.URL))

	// pve1 reports its container with packages: it claims ct101 (same host).
	if code := send(pve1, obs(`{"kind":"host","name":"pve1","identifiers":[],"children":[
		{"kind":"vm","name":"dns","identifiers":[{"kind":"container.id","value":"lxc/101"},{"kind":"mac","value":"bc:24:11:00:00:01","strength":"strong"}],
		 "components":[{"purl":"pkg:deb/debian/bind9@1","name":"bind9","version":"1"}]}]}`)); code != 200 {
		t.Fatalf("container report = %d", code)
	}
	ds := byName()
	ct := ds["ct101"]
	if len(devices(t, c, ts.URL)) != before || ct.ID == 0 {
		t.Fatalf("container did not claim the Proxmox guest: %+v", ds)
	}
	hasID := func(d devRow, kind, value string) bool {
		for _, id := range d.Identifiers {
			if id.Kind == kind && id.Value == value {
				return true
			}
		}
		return false
	}
	if !hasID(ct, "agent.child", "pve1/lxc/101") {
		t.Fatalf("no server child id: %+v", ct.Identifiers)
	}

	// pve1 cannot claim ct201 (guest of pve2) by its MAC: a new device is
	// made and the MAC stays where it is.
	send(pve1, obs(`{"kind":"host","identifiers":[],"children":[
		{"kind":"container","name":"steal","identifiers":[{"kind":"container.id","value":"lxc/201"},{"kind":"mac","value":"bc:24:11:00:00:02","strength":"strong"}]}]}`))
	ds = byName()
	if !hasID(ds["ct201"], "mac", "bc:24:11:00:00:02") || hasID(ds["steal"], "mac", "bc:24:11:00:00:02") {
		t.Fatalf("pve1 took the MAC of a pve2 guest: %+v / %+v", ds["ct201"], ds["steal"])
	}

	// pve2 cannot address pve1's container by naming the same container.id.
	send(pve2, obs(`{"kind":"host","identifiers":[],"children":[{"kind":"container","name":"x","identifiers":[{"kind":"container.id","value":"lxc/101"}]}]}`))
	if hasID(byName()["x"], "agent.child", "pve1/lxc/101") {
		t.Fatal("pve2 reached pve1's container")
	}

	// Bad shapes are refused.
	for _, bad := range []string{
		`{"kind":"host","identifiers":[],"children":[{"kind":"container","identifiers":[]}]}`,
		`{"kind":"host","identifiers":[],"children":[{"kind":"container","identifiers":[{"kind":"container.id","value":"../etc"}]}]}`,
		`{"kind":"host","identifiers":[],"children":[{"kind":"container","identifiers":[{"kind":"container.id","value":"lxc/1"},{"kind":"container.id","value":"lxc/2"}]}]}`,
		`{"kind":"host","identifiers":[],"children":[{"kind":"container","identifiers":[{"kind":"container.id","value":"lxc/1"}],"children":[{"kind":"container","identifiers":[{"kind":"container.id","value":"lxc/2"}]}]}]}`,
	} {
		if code := send(pve1, obs(bad)); code != http.StatusBadRequest {
			t.Errorf("accepted %s: %d", bad, code)
		}
	}

	// A source cannot set agent.child identifiers.
	send(src, obs(`{"kind":"host","name":"fake","identifiers":[{"kind":"agent.child","value":"pve1/lxc/101","strength":"strong"},{"kind":"mac","value":"00:1a:2b:00:99:01","strength":"strong"}]}`))
	if hasID(byName()["fake"], "agent.child", "pve1/lxc/101") {
		t.Fatal("source set an agent.child identifier")
	}
}

func TestAgentChildrenTotalLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	ts, c, pw := newTestServer(t)
	post(t, c, ts.URL+"/api/login", "application/json", `{"user":"admin","password":"`+pw+`"}`)
	anon := &http.Client{Transport: ts.Client().Transport}
	tok := enrollPeer(t, c, anon, ts.URL, "agent", "host1")
	report := func(from, n int) {
		var kids []string
		for i := from; i < from+n; i++ {
			kids = append(kids, fmt.Sprintf(`{"kind":"container","identifiers":[{"kind":"container.id","value":"lxc/%d"}]}`, i))
		}
		body := `{"version":"v1","source":"x","observed_at":"2026-11-20T10:00:00Z","entities":[{"kind":"host","name":"host1","identifiers":[],"children":[` + strings.Join(kids, ",") + `]}]}`
		if code := doJSON(t, anon, "POST", ts.URL+"/v1/observations", tok, body, nil); code != 200 {
			t.Fatalf("report = %d", code)
		}
	}
	report(0, 1000)
	report(1000, 1000)
	report(2000, 1000)
	if n := len(devices(t, c, ts.URL)); n != 1+2000 {
		t.Fatalf("devices = %d, want %d (host + limit)", n, 1+2000)
	}
}
