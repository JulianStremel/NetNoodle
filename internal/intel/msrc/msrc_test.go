package msrc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/proto"
)

// Deliberately oldest first; CurrentReleaseDate must not determine ordering.
const testUpdates = `{"value":[
	{"ID":"2026-Oct","InitialReleaseDate":"2026-10-13T07:00:00Z","CurrentReleaseDate":"2026-12-01T00:00:00Z","CvrfUrl":"https://example.invalid/ignored"},
	{"ID":"2026-Nov","InitialReleaseDate":"2026-11-10T08:00:00Z","CurrentReleaseDate":"2026-11-10T08:00:00Z"}
]}`

type testAPI struct {
	srv     *httptest.Server
	mu      sync.Mutex
	calls   map[string]int
	fault   atomic.Int32
	nov     []byte
	oct     []byte
	gate    <-chan struct{}
	started chan<- struct{}
}

func fakeMSRC(t *testing.T) *testAPI {
	t.Helper()
	a := &testAPI{calls: map[string]int{}}
	var err error
	a.nov, err = os.ReadFile("testdata/2026-Nov.json")
	if err != nil {
		t.Fatal(err)
	}
	a.oct, err = os.ReadFile("testdata/2026-Oct.json")
	if err != nil {
		t.Fatal(err)
	}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" || r.UserAgent() != "netnoodle" {
			t.Errorf("unexpected request: %s %+v", r.Method, r.Header)
		}
		a.mu.Lock()
		a.calls[r.URL.Path]++
		gate, started := a.gate, a.started
		nov, oct := a.nov, a.oct
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/cvrf/v3.0/updates":
			if started != nil {
				select {
				case started <- struct{}{}:
				default:
				}
			}
			if gate != nil {
				select {
				case <-gate:
				case <-r.Context().Done():
					return
				}
			}
			fmt.Fprint(w, testUpdates)
		case "/cvrf/v3.0/cvrf/2026-Nov":
			w.Write(nov)
		case "/cvrf/v3.0/cvrf/2026-Oct":
			switch a.fault.Load() {
			case 1:
				// Valid JSON followed by padding beyond 64 MiB must be rejected.
				w.Write(oct)
				chunk := strings.Repeat(" ", 1<<20)
				for range 64 {
					if _, err := io.WriteString(w, chunk); err != nil {
						return
					}
				}
			case 2:
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			case 3:
				fmt.Fprint(w, `{"Vulnerability":[`)
			case 4:
				w.Write(oct)
				fmt.Fprint(w, "garbage")
			case 5:
				fmt.Fprint(w, `{}`)
			default:
				w.Write(oct)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *testAPI) counts() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]int{}
	for path, n := range a.calls {
		out[path] = n
	}
	return out
}

func newTestMatcher(t *testing.T, base string, months int) *Matcher {
	t.Helper()
	raw, err := json.Marshal(Settings{URL: base, Months: months})
	if err != nil {
		t.Fatal(err)
	}
	m, err := New("test-msrc", raw)
	if err != nil {
		t.Fatal(err)
	}
	m.(*Matcher).background = false
	return m.(*Matcher)
}

func windows(version, kind, release string) proto.Component {
	return proto.Component{
		PURL: "pkg:generic/microsoft/windows@" + version + "?edition=Professional&type=" + kind + "&release=" + release,
		Name: "Windows", Version: "ignored; use PURL version",
	}
}

func TestNew(t *testing.T) {
	m, err := intel.Matchers.Build("msrc", "microsoft", nil)
	if err != nil {
		t.Fatal(err)
	}
	x := m.(*Matcher)
	if x.Name() != "microsoft" || x.base != defaultURL || x.months != 24 || x.hc.Timeout != 120*time.Second || x.hc.CheckRedirect == nil {
		t.Fatalf("unexpected defaults: %+v", x)
	}
	for _, raw := range []string{`{"unknown":true}`, `{"months":121}`, `{"months":-1}`, `{"months":"2"}`, `{"url":42}`, `{`} {
		if _, err := New("bad", json.RawMessage(raw)); err == nil {
			t.Errorf("accepted invalid settings %s", raw)
		}
	}
	for _, n := range []int{0, 1, 120} {
		newTestMatcher(t, "http://127.0.0.1:12345/", n)
	}
}

func TestMatch(t *testing.T) {
	a := fakeMSRC(t)
	m := newTestMatcher(t, a.srv.URL+"/", 2)
	c := windows("10.0.26100.2300", "client", "24H2")
	hits, err := m.Match(context.Background(), []proto.Component{c})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("got %d hits: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.Component != c || h.Confidence != proto.High || h.Fixed != "10.0.26100.2314" || h.Vuln.ID != "CVE-2026-0001" {
		t.Fatalf("unexpected hit: %+v", h)
	}
	v := h.Vuln
	if v.Summary != "Windows example vulnerability" || v.Score != 9.8 || v.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("unexpected vulnerability: %+v", v)
	}
	wantFacts := map[string]string{
		"msrc.kb": "KB5046617", "msrc.severity": "Critical", "msrc.exploited": "yes",
		"msrc.product": "Windows 11 Version 24H2 for x64-based Systems",
	}
	if !reflect.DeepEqual(v.Facts, wantFacts) || !v.Published.Equal(time.Date(2026, 10, 13, 7, 0, 0, 0, time.UTC)) {
		t.Errorf("unexpected facts or publication date: %+v", v)
	}
	if !reflect.DeepEqual(v.Refs, []string{"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-0001", "https://support.microsoft.com/help/5046617"}) {
		t.Errorf("references = %v", v.Refs)
	}
	before := a.counts()
	// Mutating a returned hit must not corrupt the cached snapshot.
	hits[0].Vuln.Facts["msrc.kb"] = "changed"
	hits[0].Vuln.Refs[0] = "changed"
	again, err := m.Match(context.Background(), []proto.Component{c})
	if err != nil || !reflect.DeepEqual(again[0].Vuln.Facts, wantFacts) || !reflect.DeepEqual(before, a.counts()) {
		t.Fatalf("cached match changed or made requests: hits=%+v err=%v counts=%v", again, err, a.counts())
	}
	// The October fix is lower; an installed UBR above it but below November
	// still needs the highest fix across both documents.
	if before["/cvrf/v3.0/cvrf/2026-Oct"] != 1 || before["/cvrf/v3.0/cvrf/2026-Nov"] != 1 {
		t.Fatalf("did not load both months: %v", before)
	}
}

func TestMatchFilters(t *testing.T) {
	a := fakeMSRC(t)
	m := newTestMatcher(t, a.srv.URL, 2)
	for _, tt := range []struct {
		name, version, kind, release, wantID string
	}{
		{"equal fix", "10.0.26100.2314", "client", "24H2", ""},
		{"above fix", "10.0.26100.3000", "client", "24H2", ""},
		{"different build", "10.0.22631.1", "client", "24H2", ""},
		{"release mismatch", "10.0.26100.1", "client", "23H2", ""},
		{"release case", "10.0.26100.1", "client", "24h2", "CVE-2026-0001"},
		{"no release", "10.0.26100.1", "client", "", "CVE-2026-0001"},
		{"server only", "10.0.26100.1", "server", "24H2", "CVE-2026-0002"},
		{"server no version token", "10.0.26100.1", "server", "21H2", "CVE-2026-0002"},
		{"server fixed", "10.0.26100.2500", "server", "", ""},
		{"invalid type", "10.0.26100.1", "other", "", ""},
		{"missing type", "10.0.26100.1", "", "", ""},
		{"invalid version", "10.0.26100", "client", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			hits, err := m.Match(context.Background(), []proto.Component{windows(tt.version, tt.kind, tt.release)})
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantID == "" {
				if len(hits) != 0 {
					t.Fatalf("unexpected hits: %+v", hits)
				}
				return
			}
			if len(hits) != 1 || hits[0].Vuln.ID != tt.wantID {
				t.Fatalf("hits = %+v; want only %s", hits, tt.wantID)
			}
			if tt.kind == "server" && (hits[0].Vuln.Score != 7.5 || hits[0].Vuln.Vector != "" || hits[0].Vuln.Facts["msrc.exploited"] != "no" || hits[0].Vuln.Facts["msrc.kb"] != "KB5049999") {
				t.Errorf("severity fallback or server facts = %+v", hits[0].Vuln)
			}
		})
	}
}

func TestIgnoredComponentsDoNotLoad(t *testing.T) {
	a := fakeMSRC(t)
	m := newTestMatcher(t, a.srv.URL, 2)
	var comps []proto.Component
	for _, purl := range []string{
		"pkg:generic/microsoft/office@10.0.26100.1?type=client",
		"pkg:generic/other/windows@10.0.26100.1?type=client",
		"pkg:deb/microsoft/windows@10.0.26100.1?type=client",
		"pkg:generic/microsoft/windows@broken?type=client",
		"invalid",
	} {
		comps = append(comps, proto.Component{PURL: purl, Version: "10.0.26100.1"})
	}
	hits, err := m.Match(context.Background(), comps)
	if err != nil || len(hits) != 0 || len(a.counts()) != 0 {
		t.Fatalf("ignored components: hits=%v err=%v requests=%v", hits, err, a.counts())
	}
}

func TestMonthsLimit(t *testing.T) {
	a := fakeMSRC(t)
	m := newTestMatcher(t, a.srv.URL, 1)
	if err := m.load(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"/cvrf/v3.0/updates": 1, "/cvrf/v3.0/cvrf/2026-Nov": 1}
	if !reflect.DeepEqual(a.counts(), want) {
		t.Errorf("requests = %v; want %v", a.counts(), want)
	}
	hits, err := m.Match(context.Background(), []proto.Component{windows("10.0.26100.1", "client", "24H2")})
	if err != nil || len(hits) != 1 || !hits[0].Vuln.Published.Equal(time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("wrong snapshot: hits=%+v err=%v", hits, err)
	}
}

func TestHighestFixInOlderDocument(t *testing.T) {
	a := fakeMSRC(t)
	// Document ordering must not determine the chosen build or KB.
	a.oct = []byte(strings.ReplaceAll(string(a.oct), "10.0.26100.2200", "10.0.26100.3000"))
	m := newTestMatcher(t, a.srv.URL, 2)
	hits, err := m.Match(context.Background(), []proto.Component{windows("10.0.26100.2400", "client", "24H2")})
	if err != nil || len(hits) != 1 {
		t.Fatalf("Match: hits=%+v err=%v", hits, err)
	}
	if hits[0].Fixed != "10.0.26100.3000" || hits[0].Vuln.Facts["msrc.kb"] != "KB5040000" || hits[0].Vuln.Score != 9.8 {
		t.Fatalf("wrong fix or maximum product score: %+v", hits[0])
	}
}

func TestRefreshKeepsOldDataOnError(t *testing.T) {
	for _, tt := range []struct {
		name  string
		fault int32
	}{
		{"oversized", 1}, {"HTTP failure", 2}, {"malformed", 3}, {"trailing garbage", 4}, {"missing vulnerability array", 5},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := fakeMSRC(t)
			m := newTestMatcher(t, a.srv.URL, 2)
			c := []proto.Component{windows("10.0.26100.1", "client", "24H2")}
			before, err := m.Match(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			a.fault.Store(tt.fault)
			m.docs = nil // documents changed: no cache
			if err := m.load(context.Background(), true); err == nil {
				t.Fatal("Refresh accepted bad data")
			}
			counts := a.counts()
			after, err := m.Match(context.Background(), c)
			if err != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(counts, a.counts()) {
				t.Fatalf("old snapshot lost: hits=%+v err=%v requests=%v", after, err, a.counts())
			}
		})
	}
}

func TestLazyLoadSingleFlight(t *testing.T) {
	a := fakeMSRC(t)
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	a.mu.Lock()
	a.gate, a.started = gate, started
	a.mu.Unlock()
	m := newTestMatcher(t, a.srv.URL, 2)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			hits, err := m.Match(context.Background(), []proto.Component{windows("10.0.26100.1", "client", "24H2")})
			if err != nil || len(hits) != 1 {
				t.Errorf("Match: hits=%+v err=%v", hits, err)
			}
		})
	}
	<-started
	// A waiting refresh can stop without disturbing the active download.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.load(ctx, true); err != context.DeadlineExceeded {
		t.Errorf("waiting Refresh = %v", err)
	}
	close(gate)
	wg.Wait()
	for path, n := range a.counts() {
		if n != 1 {
			t.Errorf("%s requested %d times", path, n)
		}
	}
}

func TestMatchDuringRefresh(t *testing.T) {
	a := fakeMSRC(t)
	m := newTestMatcher(t, a.srv.URL, 2)
	if err := m.load(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	a.mu.Lock()
	a.gate, a.started = gate, started
	a.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- m.load(context.Background(), true) }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	hits, err := m.Match(ctx, []proto.Component{windows("10.0.26100.1", "client", "24H2")})
	close(gate)
	refreshErr := <-done
	if err != nil || len(hits) != 1 || refreshErr != nil {
		t.Fatalf("matching during refresh: hits=%+v err=%v refreshErr=%v", hits, err, refreshErr)
	}
}

func TestRefreshReplacesSnapshot(t *testing.T) {
	a := fakeMSRC(t)
	m := newTestMatcher(t, a.srv.URL, 2)
	comps := []proto.Component{windows("10.0.26100.1", "client", "24H2")}
	hits, err := m.Match(context.Background(), comps)
	if err != nil || len(hits) != 1 {
		t.Fatalf("initial snapshot: hits=%+v err=%v", hits, err)
	}
	a.mu.Lock()
	a.nov, a.oct = []byte(`{"Vulnerability":[]}`), []byte(`{"Vulnerability":[]}`)
	a.mu.Unlock()
	m.docs = nil // documents changed: no cache
	if err := m.load(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	counts := a.counts()
	hits, err = m.Match(context.Background(), comps)
	if err != nil || len(hits) != 0 || !reflect.DeepEqual(counts, a.counts()) {
		t.Fatalf("replacement snapshot: hits=%+v err=%v requests=%v", hits, err, a.counts())
	}
}

func TestFailedInitialLoadCanRetry(t *testing.T) {
	a := fakeMSRC(t)
	a.fault.Store(2)
	m := newTestMatcher(t, a.srv.URL, 2)
	comps := []proto.Component{windows("10.0.26100.1", "client", "24H2")}
	if _, err := m.Match(context.Background(), comps); err == nil {
		t.Fatal("Match suppressed a failed initial load")
	}
	a.fault.Store(0)
	hits, err := m.Match(context.Background(), comps)
	if err != nil || len(hits) != 1 {
		t.Fatalf("retry: hits=%+v err=%v", hits, err)
	}
}

func TestUpdatesLimitAndEmptySnapshot(t *testing.T) {
	var oversized atomic.Bool
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"value":[]}`)
		if oversized.Load() {
			io.WriteString(w, strings.Repeat(" ", maxUpdates))
		}
	}))
	defer srv.Close()
	m := newTestMatcher(t, srv.URL, 2)
	comps := []proto.Component{windows("10.0.26100.1", "client", "24H2")}
	for range 2 {
		if hits, err := m.Match(context.Background(), comps); err != nil || len(hits) != 0 {
			t.Fatalf("empty snapshot: hits=%+v err=%v", hits, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("empty snapshot was reloaded %d times", calls.Load())
	}
	oversized.Store(true)
	if err := m.load(context.Background(), true); err == nil {
		t.Fatal("accepted oversized updates list")
	}
}

func TestCompactionLimits(t *testing.T) {
	fixture, err := os.ReadFile("testdata/2026-Nov.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc document
	if err := json.Unmarshal(fixture, &doc); err != nil {
		t.Fatal(err)
	}
	data := map[string]*record{}
	count := maxFixes - 2 // this document expands to exactly two Windows fixes
	if err := compact(data, doc, time.Now(), &count); err != nil || count != maxFixes {
		t.Fatalf("at fix limit: count=%d err=%v", count, err)
	}
	if err := compact(data, doc, time.Now(), &count); err == nil {
		t.Fatal("accepted more than the total fix limit")
	}
	long := strings.Repeat("a", 1024)
	doc.Vulnerability = doc.Vulnerability[:1]
	v := &doc.Vulnerability[0]
	v.CVE, v.Title.Value, v.Threats[0].Description.Value = long, long, long
	v.CVSSScoreSets[0].Vector = long
	v.Remediations[0].Description.Value, v.Remediations[0].URL = long, long
	doc.ProductTree.FullProductName[0].Value = "Windows " + long
	data, count = map[string]*record{}, 0
	if err := compact(data, doc, time.Now(), &count); err != nil {
		t.Fatal(err)
	}
	r := data[long[:maxStringBytes]]
	if r == nil || len(r.fixes) != 1 {
		t.Fatalf("compacted record = %+v", r)
	}
	f := r.fixes[0]
	for field, value := range map[string]string{
		"id": r.id, "title": r.title, "severity": r.severity,
		"vector": f.score.vector, "product": f.product, "kb": f.kb, "url": f.url,
	} {
		if len(value) != maxStringBytes {
			t.Errorf("%s retained %d bytes", field, len(value))
		}
	}
}

func TestParseBuild(t *testing.T) {
	for _, s := range []string{"", "10.0.1", "10.0.1.2.3", "10.0.-1.2", "10.0.+1.2", "10.0.1.", "10.0.1. 2", "10.0.1.18446744073709551616"} {
		if _, ok := parseBuild(s); ok {
			t.Errorf("accepted %q", s)
		}
	}
	b, ok := parseBuild("10.0.26100.2314")
	if !ok || b != (build{10, 0, 26100, 2314}) || b.String() != "10.0.26100.2314" {
		t.Fatalf("parsed build = %v, %v", b, ok)
	}
}

func TestRefreshWaitsForWindowsAndCachesDocuments(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/cvrf/v3.0/updates":
			w.Write([]byte(`{"value":[{"ID":"2026-Nov","InitialReleaseDate":"2026-11-11T08:00:00Z","CurrentReleaseDate":"2026-11-12T08:00:00Z"}]}`))
		case "/cvrf/v3.0/cvrf/2026-Nov":
			w.Write([]byte(`{"ProductTree":{"FullProductName":[]},"Vulnerability":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	mi, err := New("msrc", json.RawMessage(`{"url":"`+srv.URL+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	m := mi.(*Matcher)
	m.background = false
	if err := m.Refresh(context.Background()); err != nil || hits.Load() != 0 {
		t.Fatalf("refresh before any Windows device: err=%v requests=%d", err, hits.Load())
	}
	if _, err := m.Match(context.Background(), []proto.Component{{PURL: "pkg:generic/microsoft/windows@10.0.26100.1?type=client"}}); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("first load requests = %d, want 2", hits.Load())
	}
	if err := m.Refresh(context.Background()); err != nil || hits.Load() != 3 {
		t.Fatalf("refresh of an unchanged document: err=%v requests=%d, want 3 (list only)", err, hits.Load())
	}
}

func TestBackgroundFirstLoad(t *testing.T) {
	a := fakeMSRC(t)
	mi, err := New("msrc", json.RawMessage(`{"url":"`+a.srv.URL+`","months":2}`))
	if err != nil {
		t.Fatal(err)
	}
	m := mi.(*Matcher)
	ready := make(chan struct{})
	m.OnReady(func() { close(ready) })
	c := []proto.Component{windows("10.0.26100.1", "client", "24H2")}
	if _, err := m.Match(context.Background(), c); !errors.Is(err, ErrNotReady) {
		t.Fatalf("first match = %v, want ErrNotReady", err)
	}
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("OnReady not called")
	}
	if hits, err := m.Match(context.Background(), c); err != nil || len(hits) == 0 {
		t.Fatalf("after ready: %d hits, %v", len(hits), err)
	}
}
