package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netnoodle/internal/intel"
)

const testCSV = "#model_version:v2025.03.14,score_date:2026-11-19T00:00:00+0000\n" +
	"cve,epss,percentile\nCVE-2024-3094,0.85432,0.99321\nCVE-2025-0001,0.1,0.4\nCVE-2026-0001,0,0\n"

func newTestEnricher(t *testing.T, url string) intel.Enricher {
	t.Helper()
	raw, err := json.Marshal(Settings{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	e, err := New("test-epss", raw)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func gzipData(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestNew(t *testing.T) {
	e, err := intel.Enrichers.Build("epss", "first", nil)
	if err != nil {
		t.Fatal(err)
	}
	p := e.(*enricher)
	if p.Name() != "first" || p.url != defaultURL || p.c.Timeout != 120*time.Second {
		t.Fatalf("unexpected defaults: %+v", p)
	}
	for _, raw := range []string{`{"unknown":true}`, `{"url":42}`, `{`} {
		if _, err := New("bad", json.RawMessage(raw)); err == nil {
			t.Errorf("New accepted invalid settings %s", raw)
		}
	}
}

func TestRefreshAndEnrich(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(fmt.Sprintf("gzip=%t", compressed), func(t *testing.T) {
			body := []byte(testCSV)
			if compressed {
				body = gzipData(t, testCSV)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.UserAgent() != "netnoodle" {
					t.Errorf("unexpected request: %s, User-Agent %q", r.Method, r.UserAgent())
				}
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, "/scores", http.StatusFound)
					return
				}
				// No Content-Encoding: the refresher must sniff gzip magic.
				w.Write(body)
			}))
			e := newTestEnricher(t, srv.URL+"/redirect")
			if err := e.Refresh(context.Background()); err != nil {
				srv.Close()
				t.Fatal(err)
			}
			srv.Close()
			for _, v := range []intel.Vuln{
				{ID: "CVE-2024-3094"},
				{ID: "GHSA-test", Aliases: []string{"CVE-2025-0001", "CVE-2024-3094"}},
				{ID: "CVE-2024-3094", Aliases: []string{"CVE-2025-0001"}},
			} {
				v.SetFact("existing", "preserved")
				e.Enrich(&v)
				if v.EPSS != float64(float32(0.85432)) || v.EPSSPct != float64(float32(0.99321)) ||
					v.Facts["epss.date"] != "2026-11-19T00:00:00+0000" || v.Facts["existing"] != "preserved" {
					t.Errorf("unexpected enrichment: %+v", v)
				}
			}
			zero := intel.Vuln{ID: "CVE-2026-0001"}
			e.Enrich(&zero)
			if zero.EPSS != 0 || zero.EPSSPct != 0 || zero.Facts["epss.date"] == "" {
				t.Errorf("zero score was not matched: %+v", zero)
			}
			unknown := intel.Vuln{ID: "CVE-1999-0001", EPSS: 0.3, EPSSPct: 0.7}
			e.Enrich(&unknown)
			if unknown.EPSS != 0.3 || unknown.EPSSPct != 0.7 || unknown.Facts != nil {
				t.Errorf("unmatched vulnerability changed: %+v", unknown)
			}
		})
	}
}

func TestRefreshKeepsOldDataOnError(t *testing.T) {
	corruptGzip := gzipData(t, testCSV)
	corruptGzip[len(corruptGzip)-8] ^= 0xff
	for _, tt := range []struct {
		name, body string
		status     int
	}{
		{"http error", "unavailable", http.StatusServiceUnavailable},
		{"empty", "cve,epss,percentile\n", http.StatusOK},
		{"empty body", "", http.StatusOK},
		{"bad header", "cve,percentile,epss\nCVE-2024-3094,0.1,0.2\n", http.StatusOK},
		{"short header", "cve,epss\n", http.StatusOK},
		{"bad score", "cve,epss,percentile\nCVE-2024-3094,garbage,0.2\n", http.StatusOK},
		{"bad percentile", "cve,epss,percentile\nCVE-2024-3094,0.1,garbage\n", http.StatusOK},
		{"NaN", "cve,epss,percentile\nCVE-2024-3094,NaN,0.2\n", http.StatusOK},
		{"infinity", "cve,epss,percentile\nCVE-2024-3094,0.1,+Inf\n", http.StatusOK},
		{"out of range", "cve,epss,percentile\nCVE-2024-3094,-0.1,0.2\n", http.StatusOK},
		{"percentile out of range", "cve,epss,percentile\nCVE-2024-3094,0.1,1.1\n", http.StatusOK},
		{"bad CVE", "cve,epss,percentile\nunknown,0.1,0.2\n", http.StatusOK},
		{"short row", "cve,epss,percentile\nCVE-2024-3094,0.1\n", http.StatusOK},
		{"partial new data", "cve,epss,percentile\nCVE-2024-3094,0.9,0.9\nbroken\n", http.StatusOK},
		{"truncated gzip", "\x1f\x8b", http.StatusOK},
		{"bad gzip checksum", string(corruptGzip), http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var failed atomic.Bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failed.Load() {
					w.WriteHeader(tt.status)
					fmt.Fprint(w, tt.body)
					return
				}
				fmt.Fprint(w, testCSV)
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
			if v.EPSS != float64(float32(0.85432)) || v.Facts["epss.date"] != "2026-11-19T00:00:00+0000" {
				t.Errorf("lost old data: %+v", v)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDefaultFeedMinimum(t *testing.T) {
	for _, count := range []int{999, 1000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var body strings.Builder
			body.WriteString("cve,epss,percentile\n")
			for i := range count {
				fmt.Fprintf(&body, "CVE-2026-%04d,0.1,0.2\n", i)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, body.String())
			}))
			defer srv.Close()
			e := newTestEnricher(t, "").(*enricher)
			endpoint, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			// Retain the default feed policy while routing the request to the test server.
			e.c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				local := r.Clone(r.Context())
				local.URL = endpoint
				return http.DefaultTransport.RoundTrip(local)
			})
			if err := e.Refresh(context.Background()); (err != nil) != (count < 1000) {
				t.Fatalf("Refresh with %d entries returned %v", count, err)
			}
		})
	}
}

func TestRefreshReplacesSnapshotAndDate(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			fmt.Fprint(w, testCSV)
		} else {
			fmt.Fprint(w, "cve,epss,percentile\nCVE-2026-0002,0.7,0.8\n")
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
	current := intel.Vuln{ID: "CVE-2026-0002"}
	e.Enrich(&current)
	if old.EPSS != 0 || current.EPSS != float64(float32(0.7)) || current.Facts != nil {
		t.Fatalf("snapshot/date not replaced: old=%+v current=%+v", old, current)
	}
}

func TestConcurrentRefreshAndEnrich(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, testCSV)
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
