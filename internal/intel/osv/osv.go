// Package osv is a vulnerability matcher that uses the OSV database
// (https://osv.dev). It maps distribution packages to OSV ecosystems,
// asks OSV which vulnerabilities affect the installed versions, and
// caches the answers.
//
// The OSV API receives package names, versions and the distribution
// release. It receives nothing else (no host names, no addresses).
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

func init() {
	intel.Matchers.RegisterWithSchema("osv", New, registry.Schema{Fields: []registry.Field{
		{Key: "url", Label: "API base URL", Type: "url", Default: "https://api.osv.dev"},
		{Key: "cache_ttl", Label: "Cache lifetime", Type: "duration", Default: "24h"},
		{Key: "concurrency", Label: "Parallel requests", Type: "int", Default: 8, Help: "1 to 32."},
	}})
}

type settings struct {
	URL         string `json:"url"`         // default https://api.osv.dev
	CacheTTL    string `json:"cache_ttl"`   // default 24h
	Concurrency int    `json:"concurrency"` // parallel detail requests, default 8
}

// Query is one OSV package query.
type Query struct {
	Ecosystem string
	Name      string
	Version   string
}

type idRef struct {
	ID       string    `json:"id"`
	Modified time.Time `json:"modified"`
}

type queryEntry struct {
	ids []idRef
	at  time.Time
}

type vulnEntry struct {
	rec      *record // nil: OSV does not know the ID
	at       time.Time
	notFound bool
}

// Matcher is the OSV matcher.
type Matcher struct {
	name string
	base string
	ttl  time.Duration
	conc int
	hc   *http.Client
	now  func() time.Time

	mu      sync.Mutex
	queries map[Query]queryEntry
	vulns   map[string]vulnEntry
}

// New builds the matcher from its settings.
func New(name string, raw json.RawMessage) (intel.Matcher, error) {
	s := settings{URL: "https://api.osv.dev", CacheTTL: "24h", Concurrency: 8}
	if err := registry.Decode(raw, &s); err != nil {
		return nil, err
	}
	if err := tlspin.CheckURL(s.URL, false); err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}
	ttl, err := time.ParseDuration(s.CacheTTL)
	if err != nil || ttl <= 0 {
		return nil, fmt.Errorf("osv: bad cache_ttl %q", s.CacheTTL)
	}
	if s.Concurrency < 1 || s.Concurrency > 32 {
		s.Concurrency = 8
	}
	return &Matcher{
		name:    name,
		base:    strings.TrimRight(s.URL, "/"),
		ttl:     ttl,
		conc:    s.Concurrency,
		hc:      &http.Client{Transport: tlspin.Transport(), Timeout: 60 * time.Second, CheckRedirect: tlspin.NoRedirects},
		now:     time.Now,
		queries: map[Query]queryEntry{},
		vulns:   map[string]vulnEntry{},
	}, nil
}

// Name returns the instance name.
func (m *Matcher) Name() string { return m.name }

var debianCodenames = map[string]string{
	"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14",
}

func major(v string) string {
	v, _, _ = strings.Cut(v, ".")
	for _, r := range v {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return v
}

// QueryFor maps a component to an OSV query. ok is false for package types
// or distributions that OSV does not cover (or that this matcher does not map yet).
func QueryFor(c proto.Component) (Query, bool) {
	p, err := intel.ParsePURL(c.PURL)
	if err != nil || p.Version == "" {
		return Query{}, false
	}
	distro := p.Qualifiers["distro"]
	q := Query{Name: p.Name, Version: p.Version}
	switch p.Type {
	case "pypi":
		q.Ecosystem = "PyPI"
	case "golang":
		q.Ecosystem = "Go"
		if p.Namespace != "" {
			q.Name = p.Namespace + "/" + p.Name
		}
	case "deb":
		// Debian and Ubuntu advisories name the source package.
		if un, uv := p.Upstream(); un != "" {
			q.Name = un
			if uv != "" {
				q.Version = uv
			}
		}
		switch p.Namespace {
		case "debian":
			rel := strings.TrimPrefix(distro, "debian-")
			if n, ok := debianCodenames[rel]; ok {
				rel = n
			}
			if major(rel) == "" {
				return Query{}, false
			}
			q.Ecosystem = "Debian:" + major(rel)
		case "ubuntu":
			rel := strings.TrimPrefix(distro, "ubuntu-")
			yy, mm, ok := strings.Cut(rel, ".")
			if !ok || major(yy) == "" || major(mm) == "" {
				return Query{}, false
			}
			q.Ecosystem = "Ubuntu:" + rel
			if mm == "04" && (yy[len(yy)-1]-'0')%2 == 0 {
				q.Ecosystem += ":LTS"
			}
		default:
			return Query{}, false
		}
	case "apk":
		if p.Namespace != "alpine" {
			return Query{}, false
		}
		if un, _ := p.Upstream(); un != "" {
			q.Name = un
		}
		rel := strings.TrimPrefix(distro, "alpine-")
		parts := strings.Split(rel, ".")
		if len(parts) < 2 || major(parts[0]) == "" || major(parts[1]) == "" {
			return Query{}, false
		}
		q.Ecosystem = "Alpine:v" + parts[0] + "." + parts[1]
	case "rpm":
		rel := distro[strings.LastIndex(distro, "-")+1:]
		if major(rel) == "" {
			return Query{}, false
		}
		switch p.Namespace {
		case "rocky":
			q.Ecosystem = "Rocky Linux:" + major(rel)
		case "almalinux":
			q.Ecosystem = "AlmaLinux:" + major(rel)
		default:
			return Query{}, false
		}
		// Version from the PURL (never the free-form component field), with
		// the epoch qualifier, as OSV compares with rpm rules.
		if ep := p.Qualifiers["epoch"]; ep != "" && ep != "0" {
			if major(ep) == "" {
				return Query{}, false
			}
			q.Version = ep + ":" + p.Version
		}
	default:
		return Query{}, false
	}
	return q, true
}

// Match returns the vulnerabilities that affect the components.
// It returns an error if any lookup failed, so that a caller never treats
// an incomplete answer as "fixed".
func (m *Matcher) Match(ctx context.Context, comps []proto.Component) ([]intel.Hit, error) {
	type item struct {
		c proto.Component
		q Query
	}
	var items []item
	uniq := map[Query]bool{}
	for _, c := range comps {
		if q, ok := QueryFor(c); ok {
			items = append(items, item{c, q})
			uniq[q] = true
		}
	}
	if len(items) == 0 {
		return nil, nil
	}
	if len(uniq) > maxMatchQueries {
		return nil, fmt.Errorf("osv: %d distinct packages, more than %d per device", len(uniq), maxMatchQueries)
	}
	ids, err := m.lookup(ctx, uniq)
	if err != nil {
		return nil, err
	}
	if err := m.fetchAll(ctx, ids); err != nil {
		return nil, err
	}
	var hits []intel.Hit
	for _, it := range items {
		for _, ref := range ids[it.q] {
			rec := m.record(ref.ID)
			if rec == nil || rec.Withdrawn != nil {
				continue
			}
			hits = append(hits, intel.Hit{
				Component:  it.c,
				Vuln:       m.toVuln(rec),
				Fixed:      rec.fixedFor(it.q),
				Confidence: proto.High,
			})
		}
	}
	return hits, nil
}

// --- OSV API ---

type batchQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type batchResp struct {
	Results []struct {
		Vulns         []idRef `json:"vulns"`
		NextPageToken string  `json:"next_page_token"`
	} `json:"results"`
}

func (m *Matcher) post(ctx context.Context, path string, in, out any) error {
	b, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netnoodle")
	res, err := m.hc.Do(req)
	if err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("osv %s: %s: %s", path, res.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(out)
}

var errNotFound = errors.New("not found")

func (m *Matcher) get(ctx context.Context, id string) (*record, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.base+"/v1/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "netnoodle")
	res, err := m.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv vuln %s: %s", id, res.Status)
	}
	var r record
	if err := json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(&r); err != nil {
		return nil, fmt.Errorf("osv vuln %s: %w", id, err)
	}
	r.compact()
	return &r, nil
}

// lookup returns the vulnerability IDs per query, from the cache or from
// the querybatch endpoint.
func (m *Matcher) lookup(ctx context.Context, uniq map[Query]bool) (map[Query][]idRef, error) {
	out := map[Query][]idRef{}
	var todo []Query
	now := m.now()
	m.mu.Lock()
	m.pruneLocked(now)
	for q := range uniq {
		if e, ok := m.queries[q]; ok && now.Sub(e.at) < m.ttl {
			out[q] = e.ids
		} else {
			todo = append(todo, q)
		}
	}
	m.mu.Unlock()

	const chunk = 1000
	for len(todo) > 0 {
		n := min(chunk, len(todo))
		part := todo[:n]
		todo = todo[n:]
		res, err := m.batch(ctx, part, nil)
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		for i, q := range part {
			out[q] = res[i]
			m.queries[q] = queryEntry{ids: res[i], at: now}
		}
		m.pruneLocked(now)
		m.mu.Unlock()
	}
	return out, nil
}

// Paging limits of one querybatch (security review 2026-11-20: a custom
// OSV server could send endless page tokens). Results above the limits are
// cut, not dropped, so the found IDs are still used.
const (
	maxPages       = 20
	maxIDsPerQuery = 2000
)

// batch runs querybatch calls and follows page tokens, iteratively and
// bounded.
func (m *Matcher) batch(ctx context.Context, qs []Query, _ []string) ([][]idRef, error) {
	out := make([][]idRef, len(qs))
	idx := make([]int, len(qs))
	for i := range idx {
		idx[i] = i
	}
	cur := qs
	var tokens []string
	seen := map[string]bool{}
	for page := 0; len(cur) > 0; page++ {
		if page >= maxPages {
			slog.Warn("osv: result pages cut", "pages", maxPages, "queries", len(cur))
			break
		}
		req := struct {
			Queries []batchQuery `json:"queries"`
		}{}
		for i, q := range cur {
			var bq batchQuery
			bq.Package.Name, bq.Package.Ecosystem, bq.Version = q.Name, q.Ecosystem, q.Version
			if tokens != nil {
				bq.PageToken = tokens[i]
			}
			req.Queries = append(req.Queries, bq)
		}
		var resp batchResp
		if err := m.post(ctx, "/v1/querybatch", req, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != len(cur) {
			return nil, fmt.Errorf("osv: %d results for %d queries", len(resp.Results), len(cur))
		}
		var next []Query
		var nextTok []string
		var nextIdx []int
		for i, r := range resp.Results {
			k := idx[i]
			room := maxIDsPerQuery - len(out[k])
			if len(r.Vulns) > room {
				r.Vulns = r.Vulns[:max(room, 0)]
				r.NextPageToken = ""
				slog.Warn("osv: result IDs cut", "package", cur[i].Name, "max", maxIDsPerQuery)
			}
			out[k] = append(out[k], r.Vulns...)
			if r.NextPageToken == "" || seen[r.NextPageToken] || len(r.NextPageToken) > 4096 {
				continue
			}
			seen[r.NextPageToken] = true
			next = append(next, cur[i])
			nextTok = append(nextTok, r.NextPageToken)
			nextIdx = append(nextIdx, k)
		}
		cur, tokens, idx = next, nextTok, nextIdx
	}
	return out, nil
}

// Cache limits. Entries expire after the TTL; above the limits the oldest
// part of the cache is dropped, so a peer that reports many fake packages
// cannot grow the server's memory without end.
const (
	maxCachedQueries = 200000
	maxCachedVulns   = 100000
	// maxMatchQueries bounds the work of one device match. Real hosts have
	// a few thousand packages.
	maxMatchQueries = 50000
)

func (m *Matcher) pruneLocked(now time.Time) {
	if len(m.queries) > maxCachedQueries/2 {
		for q, e := range m.queries {
			if now.Sub(e.at) >= m.ttl {
				delete(m.queries, q)
			}
		}
	}
	if len(m.vulns) > maxCachedVulns/2 {
		for id, e := range m.vulns {
			if now.Sub(e.at) >= m.ttl {
				delete(m.vulns, id)
			}
		}
	}
	if len(m.queries) > maxCachedQueries {
		m.queries = map[Query]queryEntry{}
	}
	if len(m.vulns) > maxCachedVulns {
		m.vulns = map[string]vulnEntry{}
	}
}

func (m *Matcher) record(id string) *record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.vulns[id].rec
}

// needs reports whether the ID must be (re)fetched.
func (m *Matcher) needs(id string, modified time.Time, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.vulns[id]
	if !ok || now.Sub(e.at) >= m.ttl {
		return true
	}
	return e.rec != nil && !modified.IsZero() && e.rec.Modified.Before(modified)
}

// fetchAll loads the details of all IDs, and the CVE records needed for
// scores that the distribution records do not have.
func (m *Matcher) fetchAll(ctx context.Context, ids map[Query][]idRef) error {
	now := m.now()
	var todo []string
	seen := map[string]bool{}
	for _, refs := range ids {
		for _, r := range refs {
			if !seen[r.ID] && m.needs(r.ID, r.Modified, now) {
				todo = append(todo, r.ID)
			}
			seen[r.ID] = true
		}
	}
	if err := m.fetch(ctx, todo, now); err != nil {
		return err
	}
	// Second round: CVE records for records without a CVSS vector.
	var cves []string
	for id := range seen {
		rec := m.record(id)
		if rec == nil || rec.cvss() != "" {
			continue
		}
		for _, c := range rec.cveIDs() {
			if c != id && !seen[c] && m.needs(c, time.Time{}, now) {
				cves = append(cves, c)
				seen[c] = true
			}
		}
	}
	return m.fetch(ctx, cves, now)
}

func (m *Matcher) fetch(ctx context.Context, ids []string, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	jobs := make(chan string)
	errs := make(chan error, len(ids))
	var wg sync.WaitGroup
	for i := 0; i < m.conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				rec, err := m.get(ctx, id)
				if err != nil && !errors.Is(err, errNotFound) {
					errs <- err
					continue
				}
				m.mu.Lock()
				m.vulns[id] = vulnEntry{rec: rec, at: now, notFound: rec == nil}
				if len(m.vulns) > maxCachedVulns {
					m.pruneLocked(now)
				}
				m.mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		select {
		case jobs <- id:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	close(errs)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err, ok := <-errs; ok {
		return err
	}
	return nil
}

// --- OSV record ---

type sev struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type record struct {
	ID        string     `json:"id"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Aliases   []string   `json:"aliases"`
	Upstream  []string   `json:"upstream"`
	Published time.Time  `json:"published"`
	Modified  time.Time  `json:"modified"`
	Withdrawn *time.Time `json:"withdrawn"`
	Severity  []sev      `json:"severity"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Severity         []sev          `json:"severity"`
		DatabaseSpecific map[string]any `json:"database_specific"`
		EcosystemSpec    map[string]any `json:"ecosystem_specific"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// compact drops data that the matcher does not use, to keep the cache small.
func (r *record) compact() {
	if r.Summary == "" {
		line, _, _ := strings.Cut(strings.TrimSpace(r.Details), "\n")
		r.Summary = line
	}
	if len(r.Summary) > 300 {
		r.Summary = r.Summary[:300] + "…"
	}
	r.Details = ""
	if len(r.References) > 10 {
		r.References = r.References[:10]
	}
}

// cvss returns the best CVSS vector of the record ("" if none).
func (r *record) cvss() string {
	all := append([]sev(nil), r.Severity...)
	for _, a := range r.Affected {
		all = append(all, a.Severity...)
	}
	for _, want := range []string{"CVSS_V3", "CVSS_V2"} {
		for _, s := range all {
			if s.Type == want {
				if _, ok := intel.Score(s.Score); ok {
					return s.Score
				}
			}
		}
	}
	return ""
}

// label returns a severity word from the record, if any.
func (r *record) label() string {
	for _, a := range r.Affected {
		for _, s := range a.Severity {
			if s.Type == "Ubuntu" {
				return s.Score
			}
		}
		if v, ok := a.EcosystemSpec["severity"].(string); ok {
			return v
		}
		if v, ok := a.DatabaseSpecific["severity"].(string); ok {
			return v
		}
	}
	if v, ok := r.DatabaseSpecific["severity"].(string); ok {
		return v
	}
	return ""
}

func (r *record) cveIDs() []string {
	var out []string
	for _, id := range append(append([]string{r.ID}, r.Aliases...), r.Upstream...) {
		if strings.HasPrefix(id, "CVE-") {
			out = append(out, id)
		}
	}
	return out
}

// fixedFor returns the first fixed version for the queried package.
func (r *record) fixedFor(q Query) string {
	for _, a := range r.Affected {
		if a.Package.Ecosystem != q.Ecosystem || a.Package.Name != q.Name {
			continue
		}
		for _, rg := range a.Ranges {
			for _, ev := range rg.Events {
				if f := ev["fixed"]; f != "" {
					return f
				}
			}
		}
	}
	return ""
}

func (m *Matcher) toVuln(r *record) intel.Vuln {
	v := intel.Vuln{
		ID:        r.ID,
		Summary:   r.Summary,
		Published: r.Published,
		Modified:  r.Modified,
	}
	seen := map[string]bool{r.ID: true}
	for _, a := range append(append([]string(nil), r.Aliases...), r.Upstream...) {
		if !seen[a] {
			seen[a] = true
			v.Aliases = append(v.Aliases, a)
		}
	}
	for _, ref := range r.References {
		v.Refs = append(v.Refs, ref.URL)
	}
	// Score: the record's own CVSS, then the CVE record's, then a severity word.
	if vec := r.cvss(); vec != "" {
		v.Score, _ = intel.Score(vec)
		v.Vector = vec
		v.SetFact("score.source", r.ID)
		return v
	}
	for _, c := range r.cveIDs() {
		if cr := m.record(c); cr != nil {
			if vec := cr.cvss(); vec != "" {
				v.Score, _ = intel.Score(vec)
				v.Vector = vec
				v.SetFact("score.source", c)
				if v.Summary == "" {
					v.Summary = cr.Summary
				}
				return v
			}
		}
	}
	if w := r.label(); w != "" {
		if s, ok := intel.LabelScore(w); ok {
			v.Score = s
			v.SetFact("score.source", "label:"+strings.ToLower(w))
		}
	}
	return v
}

// Test fetches once using an empty batch. No inventory is sent or saved.
func (m *Matcher) Test(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.base+"/v1/querybatch", strings.NewReader(`{"queries":[]}`))
	if err != nil {
		return errors.New("osv test request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := m.hc.Do(req)
	if err != nil {
		return errors.New("osv test fetch failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 || res.StatusCode/100 != 2 || !json.Valid(body) {
		return errors.New("osv test response failed")
	}
	return nil
}
