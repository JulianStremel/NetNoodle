package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netnoodle/internal/intel"
)

const testCatalog = `{"catalogVersion":"2026.11.19","vulnerabilities":[
	{"cveID":"CVE-2024-3094","vendorProject":"XZ","product":"XZ Utils","vulnerabilityName":"Earlier vulnerability","dateAdded":"2024-03-29","dueDate":"2024-04-19","knownRansomwareCampaignUse":"Known"},
	{"cveID":"CVE-2025-0001","vulnerabilityName":"Later vulnerability","dateAdded":"2025-01-01","dueDate":"2025-01-22","knownRansomwareCampaignUse":"Unknown"}
]}`

func newTestEnricher(t *testing.T, url string) intel.Enricher {
	t.Helper()
	raw, err := json.Marshal(Settings{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	e, err := New("test-kev", raw)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestNew(t *testing.T) {
	e, err := intel.Enrichers.Build("kev", "cisa", nil)
	if err != nil {
		t.Fatal(err)
	}
	k := e.(*enricher)
	if k.Name() != "cisa" || k.url != defaultURL || k.c.Timeout != 60*time.Second {
		t.Fatalf("unexpected defaults: %+v", k)
	}
	for _, raw := range []string{`{"unknown":true}`, `{"url":42}`, `{`} {
		if _, err := New("bad", json.RawMessage(raw)); err == nil {
			t.Errorf("New accepted invalid settings %s", raw)
		}
	}
}

func TestRefreshAndEnrich(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.UserAgent() != "netnoodle" {
			t.Errorf("unexpected request: %s, User-Agent %q", r.Method, r.UserAgent())
		}
		fmt.Fprint(w, testCatalog)
	}))
	e := newTestEnricher(t, srv.URL)
	if err := e.Refresh(context.Background()); err != nil {
		srv.Close()
		t.Fatal(err)
	}
	srv.Close() // Enrich must use the snapshot without network access.
	for _, v := range []intel.Vuln{
		{ID: "CVE-2024-3094"},
		{ID: "GHSA-test", Aliases: []string{"CVE-2025-0001", "CVE-2024-3094"}},
		{ID: "CVE-2024-3094", Aliases: []string{"CVE-2025-0001"}},
	} {
		v.SetFact("existing", "preserved")
		e.Enrich(&v)
		want := map[string]string{
			"existing": "preserved", "kev.added": "2024-03-29", "kev.due": "2024-04-19",
			"kev.ransomware": "Known", "kev.name": "Earlier vulnerability",
		}
		if !v.KEV || !reflect.DeepEqual(v.Facts, want) {
			t.Errorf("unexpected enrichment: %+v", v)
		}
	}
	v := intel.Vuln{ID: "CVE-1999-0001"}
	e.Enrich(&v)
	if v.KEV || v.Facts != nil {
		t.Errorf("unmatched vulnerability changed: %+v", v)
	}
}

func TestRefreshKeepsOldDataOnError(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		status     int
	}{
		{"http error", "unavailable", http.StatusServiceUnavailable},
		{"empty", `{"vulnerabilities":[]}`, http.StatusOK},
		{"malformed", `{"vulnerabilities":[`, http.StatusOK},
		{"trailing garbage", testCatalog + "garbage", http.StatusOK},
		{"missing CVE", `{"vulnerabilities":[{}]}`, http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var failed atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failed.Load() {
					w.WriteHeader(tt.status)
					fmt.Fprint(w, tt.body)
					return
				}
				fmt.Fprint(w, testCatalog)
			}))
			defer srv.Close()
			e := newTestEnricher(t, srv.URL)
			if err := e.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			failed.Store(true)
			if err := e.Refresh(context.Background()); err == nil {
				t.Fatal("Refresh accepted bad data")
			}
			v := intel.Vuln{ID: "CVE-2024-3094"}
			e.Enrich(&v)
			if !v.KEV || v.Facts["kev.name"] != "Earlier vulnerability" {
				t.Errorf("lost old data: %+v", v)
			}
		})
	}
}

func TestRefreshBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Valid JSON padded beyond the limit must still be rejected.
		fmt.Fprint(w, testCatalog)
		chunk := strings.Repeat(" ", 1<<20)
		for range 64 {
			if _, err := fmt.Fprint(w, chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	e := newTestEnricher(t, srv.URL)
	if err := e.Refresh(context.Background()); err == nil {
		t.Fatal("accepted oversized catalog")
	}
}

func TestRefreshReplacesSnapshot(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			fmt.Fprint(w, testCatalog)
		} else {
			fmt.Fprint(w, `{"vulnerabilities":[{"cveID":"CVE-2026-0001","dateAdded":"2026-01-01"}]}`)
		}
	}))
	defer srv.Close()
	e := newTestEnricher(t, srv.URL)
	for range 2 {
		if err := e.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	old := intel.Vuln{ID: "CVE-2024-3094"}
	e.Enrich(&old)
	current := intel.Vuln{ID: "CVE-2026-0001"}
	e.Enrich(&current)
	if old.KEV || !current.KEV {
		t.Fatalf("snapshot not replaced: old=%+v current=%+v", old, current)
	}
}

func TestConcurrentRefreshAndEnrich(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, testCatalog)
	}))
	defer srv.Close()
	e := newTestEnricher(t, srv.URL)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 10 {
				if err := e.Refresh(context.Background()); err != nil {
					t.Error(err)
				}
			}
		})
		wg.Go(func() {
			for range 100 {
				v := intel.Vuln{ID: "CVE-2024-3094"}
				e.Enrich(&v)
			}
		})
	}
	wg.Wait()
}
