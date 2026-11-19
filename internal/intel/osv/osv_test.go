package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"netnoodle/internal/proto"
)

func TestQueryFor(t *testing.T) {
	cases := []struct {
		purl, version string
		want          Query
		ok            bool
	}{
		{"pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl", "",
			Query{"Debian:12", "openssl", "3.0.11-1~deb12u2"}, true},
		{"pkg:deb/debian/python3-six@1.16.0-4?distro=debian-12&upstream=six%401.16.0-3", "",
			Query{"Debian:12", "six", "1.16.0-3"}, true},
		{"pkg:deb/debian/bash@5.2.37-1?distro=debian-trixie", "",
			Query{"Debian:13", "bash", "5.2.37-1"}, true},
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?distro=ubuntu-22.04", "",
			Query{"Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.15"}, true},
		{"pkg:deb/ubuntu/openssl@3.3.1-2ubuntu2?distro=ubuntu-24.10", "",
			Query{"Ubuntu:24.10", "openssl", "3.3.1-2ubuntu2"}, true},
		{"pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1&upstream=openssl", "",
			Query{"Alpine:v3.19", "openssl", "3.1.4-r5"}, true},
		{"pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=rocky-9.3&epoch=1", "1:3.0.7-24.el9",
			Query{"Rocky Linux:9", "openssl-libs", "1:3.0.7-24.el9"}, true},
		{"pkg:rpm/fedora/bash@5.2-1?distro=fedora-40", "", Query{}, false},
		{"pkg:generic/ubiquiti/U7PG2@6.6.55", "", Query{}, false},
		{"pkg:deb/debian/foo@1?distro=debian", "", Query{}, false},
	}
	for _, c := range cases {
		got, ok := QueryFor(proto.Component{PURL: c.purl, Version: c.version})
		if ok != c.ok || got != c.want {
			t.Errorf("QueryFor(%s) = %+v, %v; want %+v, %v", c.purl, got, ok, c.want, c.ok)
		}
	}
}

// fakeOSV serves querybatch and vuln records.
func fakeOSV(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	records := map[string]string{
		// Debian record: no CVSS, only the upstream CVE.
		"DEBIAN-CVE-2024-0001": `{"id":"DEBIAN-CVE-2024-0001","details":"Buffer overflow in X.\nMore text.",
			"upstream":["CVE-2024-0001"],"modified":"2026-01-01T00:00:00Z",
			"affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-1~deb12u1"}]}]}]}`,
		"CVE-2024-0001": `{"id":"CVE-2024-0001","summary":"X overflow",
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`,
		// Debian record without fix and without any CVE record at OSV.
		"DEBIAN-CVE-2024-0002": `{"id":"DEBIAN-CVE-2024-0002","summary":"Minor issue","upstream":["CVE-2024-0002"],
			"affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
		// Withdrawn records are skipped.
		"DEBIAN-CVE-2024-0003": `{"id":"DEBIAN-CVE-2024-0003","withdrawn":"2026-01-01T00:00:00Z"}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			Queries []batchQuery `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var out []string
		for _, q := range req.Queries {
			if q.Package.Ecosystem == "Debian:12" && q.Package.Name == "openssl" && q.Version == "3.0.11-1~deb12u2" {
				out = append(out, `{"vulns":[{"id":"DEBIAN-CVE-2024-0001"},{"id":"DEBIAN-CVE-2024-0002"},{"id":"DEBIAN-CVE-2024-0003"}]}`)
			} else {
				out = append(out, `{}`)
			}
		}
		w.Write([]byte(`{"results":[` + strings.Join(out, ",") + `]}`))
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		rec, ok := records[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(rec))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestMatch(t *testing.T) {
	var calls atomic.Int32
	srv := fakeOSV(t, &calls)
	m, err := New("osv", json.RawMessage(`{"url":"`+srv.URL+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	comps := []proto.Component{
		{PURL: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl", Name: "libssl3", Version: "3.0.11-1~deb12u2"},
		{PURL: "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12", Name: "openssl", Version: "3.0.11-1~deb12u2"},
		{PURL: "pkg:deb/debian/bash@5.2.15-2?arch=amd64&distro=debian-12", Name: "bash", Version: "5.2.15-2"},
		{PURL: "pkg:generic/x/y@1", Name: "y", Version: "1"},
	}
	hits, err := m.Match(context.Background(), comps)
	if err != nil {
		t.Fatal(err)
	}
	// Two packages (libssl3, openssl) x two live vulns.
	if len(hits) != 4 {
		t.Fatalf("got %d hits, want 4: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.Vuln.ID != "DEBIAN-CVE-2024-0001" || h.Vuln.Score != 9.8 || h.Fixed != "3.0.13-1~deb12u1" {
		t.Errorf("hit 0 = %+v", h)
	}
	if h.Vuln.Summary != "Buffer overflow in X." || len(h.Vuln.Aliases) != 1 || h.Vuln.Aliases[0] != "CVE-2024-0001" {
		t.Errorf("vuln 0 = %+v", h.Vuln)
	}
	if h.Vuln.Facts["score.source"] != "CVE-2024-0001" {
		t.Errorf("score source = %q", h.Vuln.Facts["score.source"])
	}
	if hits[1].Vuln.ID != "DEBIAN-CVE-2024-0002" || hits[1].Vuln.Score != 0 || hits[1].Fixed != "" {
		t.Errorf("hit 1 = %+v", hits[1])
	}

	// A second match within the TTL uses only the cache.
	before := calls.Load()
	if _, err := m.Match(context.Background(), comps); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before {
		t.Errorf("second match made %d requests", calls.Load()-before)
	}
}

func TestMatchErrorIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	m, _ := New("osv", json.RawMessage(`{"url":"`+srv.URL+`"}`))
	_, err := m.Match(context.Background(), []proto.Component{
		{PURL: "pkg:deb/debian/bash@5.2.15-2?distro=debian-12", Version: "5.2.15-2"},
	})
	if err == nil {
		t.Fatal("want error when OSV is down")
	}
}
