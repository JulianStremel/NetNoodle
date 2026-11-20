// Package msrc matches Windows builds against Microsoft's CVRF security updates.
package msrc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

const (
	defaultURL     = "https://api.msrc.microsoft.com"
	maxDocument    = 64 << 20
	maxUpdates     = 4 << 20
	maxFixes       = 500000
	maxStringBytes = 512
	// maxComponents is the number of distinct Windows builds matched per
	// call. A host has one Windows; more are reports of a broken or hostile
	// agent (security review 2026-11-20).
	maxComponents = 8
	// maxHits stops a match that would produce more findings than any
	// real Windows build can have.
	maxHits = 20000
)

// ErrTooManyHits is returned when one match exceeds maxHits.
var ErrTooManyHits = errors.New("msrc: too many hits for one device")

func init() {
	intel.Matchers.RegisterWithSchema("msrc", New, registry.Schema{Fields: []registry.Field{
		{Key: "url", Label: "API base URL", Type: "url", Default: defaultURL},
		{Key: "months", Label: "Months of updates", Type: "int", Default: 24, Help: "1 to 120."},
	}})
}

// Settings configures the API base URL and the number of monthly documents.
type Settings struct {
	URL    string `json:"url"`    // defaults to https://api.msrc.microsoft.com
	Months int    `json:"months"` // defaults to 24; maximum 120
}

type build [4]uint64

func parseBuild(s string) (build, bool) {
	var b build
	parts := strings.Split(s, ".")
	if len(parts) != len(b) {
		return b, false
	}
	for i, part := range parts {
		if part == "" {
			return build{}, false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return build{}, false
			}
		}
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return build{}, false
		}
		b[i] = n
	}
	return b, true
}

// String returns the four-part Windows build number.
func (b build) String() string { return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]) }

func (b build) after(other build) bool {
	for i := range b {
		if b[i] != other[i] {
			return b[i] > other[i]
		}
	}
	return false
}

type score struct {
	base   float64
	vector string
	valid  bool
}

func (s *score) include(other score) {
	if other.valid && (!s.valid || other.base > s.base || (other.base == s.base && s.vector == "")) {
		*s = other
	}
}

type fix struct {
	product, kb, url string
	build            build
	score            score // maximum score explicitly scoped to this product
}

type record struct {
	id, title, severity string
	published           time.Time // earliest initial release among the selected documents
	exploited           bool
	score               score // fallback when no matching product has a score
	fixes               []fix
}

type loadCall struct {
	done chan struct{}
	err  error
}

// Matcher holds an immutable snapshot of the selected monthly CVRF documents.
type Matcher struct {
	name   string
	base   string
	months int
	hc     *http.Client

	mu      sync.Mutex
	data    []record // nil until loaded; a successful empty snapshot is non-nil
	loading *loadCall
	docs    map[string]cachedDoc // compacted documents by ID; only the load goroutine uses it
	// background: the first load runs in the background and Match returns
	// ErrNotReady until it completes (production). Tests load inline.
	background bool
	onReady    func()
}

// ErrNotReady is returned by Match while the first download runs.
var ErrNotReady = errors.New("msrc: security update data is still loading; devices are matched again when it is ready")

// OnReady sets a function that is called after a background load succeeds.
func (m *Matcher) OnReady(fn func()) {
	m.mu.Lock()
	m.onReady = fn
	m.mu.Unlock()
}

// startLoad starts the first load in the background, once.
func (m *Matcher) startLoad() {
	m.mu.Lock()
	busy := m.loading != nil
	m.mu.Unlock()
	if busy {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		if err := m.load(ctx, false); err != nil {
			return
		}
		m.mu.Lock()
		fn := m.onReady
		m.mu.Unlock()
		if fn != nil {
			fn()
		}
	}()
}

// cachedDoc is one compacted monthly document. It is downloaded again only
// when its CurrentReleaseDate changes.
type cachedDoc struct {
	current time.Time
	recs    map[string]*record
	fixes   int
}

// New builds an MSRC matcher from strictly decoded settings.
func New(name string, raw json.RawMessage) (intel.Matcher, error) {
	var s Settings
	if err := registry.Decode(raw, &s); err != nil {
		return nil, err
	}
	if s.URL == "" {
		s.URL = defaultURL
	}
	if err := tlspin.CheckURL(s.URL, false); err != nil {
		return nil, fmt.Errorf("msrc: %w", err)
	}
	if s.Months == 0 {
		s.Months = 24
	}
	if s.Months < 1 || s.Months > 120 {
		return nil, fmt.Errorf("msrc: months must be between 1 and 120")
	}
	return &Matcher{
		name: name, base: strings.TrimRight(s.URL, "/"), months: s.Months,
		hc:         &http.Client{Timeout: 120 * time.Second, CheckRedirect: tlspin.HTTPSRedirects},
		background: true,
	}, nil
}

// Name returns the configured instance name.
func (m *Matcher) Name() string { return m.name }

// Refresh reloads the selected documents, retaining the old snapshot on error.
// Concurrent refreshes and initial matches share the in-progress load.
// Before the first Windows component is matched, Refresh does nothing, so
// installations without Windows devices download nothing. Unchanged
// documents are not downloaded again.
func (m *Matcher) Refresh(ctx context.Context) error {
	m.mu.Lock()
	loaded := m.data != nil
	m.mu.Unlock()
	if !loaded {
		return nil
	}
	return m.load(ctx, true)
}

func (m *Matcher) load(ctx context.Context, refresh bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if !refresh && m.data != nil {
		m.mu.Unlock()
		return nil
	}
	if call := m.loading; call != nil {
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-call.done:
			return call.err
		}
	}
	call := &loadCall{done: make(chan struct{})}
	m.loading = call
	m.mu.Unlock()

	data, err := m.download(ctx)
	if err == nil {
		err = ctx.Err()
	}
	m.mu.Lock()
	if err == nil {
		m.data = data
	}
	call.err = err
	close(call.done)
	m.loading = nil
	m.mu.Unlock()
	return err
}

type component struct {
	c       proto.Component
	build   build
	kind    string
	release string
}

func windowsComponent(c proto.Component) (component, bool) {
	p, err := intel.ParsePURL(c.PURL)
	if err != nil || p.Type != "generic" || p.Namespace != "microsoft" || p.Name != "windows" {
		return component{}, false
	}
	b, ok := parseBuild(p.Version)
	kind := p.Qualifiers["type"]
	if !ok || (kind != "client" && kind != "server") {
		return component{}, false
	}
	return component{c: c, build: b, kind: kind, release: p.Qualifiers["release"]}, true
}

func (f fix) applies(c component) bool {
	if f.build[2] != c.build[2] || !strings.HasPrefix(f.product, "Windows") {
		return false
	}
	if strings.Contains(f.product, "Server") != (c.kind == "server") {
		return false
	}
	if c.release != "" {
		_, rest, found := strings.Cut(strings.ToLower(f.product), "version ")
		if fields := strings.Fields(rest); found && len(fields) > 0 && !strings.EqualFold(fields[0], c.release) {
			return false
		}
	}
	return true
}

// Match returns high-confidence hits for Windows components, loading lazily once.
// After loading, matches read the current snapshot without network requests.
func (m *Matcher) Match(ctx context.Context, comps []proto.Component) ([]intel.Hit, error) {
	var items []component
	seen := map[string]bool{}
	for _, c := range comps {
		item, ok := windowsComponent(c)
		if !ok {
			continue
		}
		key := item.build.String() + "|" + item.kind + "|" + strings.ToLower(item.release)
		if seen[key] {
			continue
		}
		if len(items) == maxComponents {
			break
		}
		seen[key] = true
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil, nil
	}
	m.mu.Lock()
	data := m.data
	m.mu.Unlock()
	if data == nil && m.background {
		m.startLoad()
		return nil, ErrNotReady
	}
	if err := m.load(ctx, false); err != nil {
		return nil, err
	}
	m.mu.Lock()
	data = m.data
	m.mu.Unlock()
	var hits []intel.Hit
	for _, c := range items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, rec := range data {
			var selected *fix
			var productScore score
			for i := range rec.fixes {
				f := &rec.fixes[i]
				if !f.applies(c) {
					continue
				}
				productScore.include(f.score)
				if selected == nil || f.build.after(selected.build) {
					selected = f
				}
			}
			if selected == nil || c.build[3] >= selected.build[3] {
				continue
			}
			s := productScore
			if !s.valid {
				s = rec.score
			}
			if !s.valid {
				s.base, _ = intel.LabelScore(rec.severity)
			}
			exploited := "no"
			if rec.exploited {
				exploited = "yes"
			}
			v := intel.Vuln{
				ID: rec.id, Summary: rec.title, Score: s.base, Vector: s.vector, Published: rec.published,
				Refs: []string{"https://msrc.microsoft.com/update-guide/vulnerability/" + rec.id},
				Facts: map[string]string{
					"msrc.kb": selected.kb, "msrc.severity": rec.severity,
					"msrc.exploited": exploited, "msrc.product": selected.product,
				},
			}
			if selected.url != "" {
				v.Refs = append(v.Refs, selected.url)
			}
			hits = append(hits, intel.Hit{Component: c.c, Vuln: v, Fixed: selected.build.String(), Confidence: proto.High})
			if len(hits) > maxHits {
				return nil, ErrTooManyHits
			}
		}
	}
	return hits, nil
}

type update struct {
	ID                 string
	InitialReleaseDate time.Time
	CurrentReleaseDate time.Time
}

type textValue struct {
	Value string
}

type document struct {
	ProductTree struct {
		FullProductName []struct {
			ProductID string
			Value     string
		}
	}
	Vulnerability []struct {
		CVE     string
		Title   textValue
		Threats []struct {
			Type        int
			Description textValue
		}
		CVSSScoreSets []struct {
			BaseScore json.Number
			Vector    string
			ProductID []string
		}
		Remediations []struct {
			Type        int
			Description textValue
			FixedBuild  string
			ProductID   []string
			URL         string
		}
	}
}

func (m *Matcher) get(ctx context.Context, path string, limit int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.base+path, nil)
	if err != nil {
		return fmt.Errorf("msrc request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "netnoodle")
	res, err := m.hc.Do(req)
	if err != nil {
		return fmt.Errorf("msrc download %s: %w", path, err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("msrc download %s: %s", path, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return fmt.Errorf("msrc read %s: %w", path, err)
	}
	if int64(len(body)) > limit {
		return fmt.Errorf("msrc %s exceeds %d bytes", path, limit)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("msrc parse %s: %w", path, err)
	}
	return nil
}

func (m *Matcher) download(ctx context.Context) ([]record, error) {
	var updates struct {
		Value []update
	}
	if err := m.get(ctx, "/cvrf/v3.0/updates", maxUpdates, &updates); err != nil {
		return nil, err
	}
	if updates.Value == nil {
		return nil, fmt.Errorf("msrc: updates list has no value array")
	}
	sort.SliceStable(updates.Value, func(i, j int) bool {
		return updates.Value[i].InitialReleaseDate.After(updates.Value[j].InitialReleaseDate)
	})
	seen := map[string]bool{}
	docs := map[string]cachedDoc{}
	var order []string // newest first; the newest document gives the title
	loaded, fixes := 0, 0
	for _, u := range updates.Value {
		if _, err := time.Parse("2006-Jan", u.ID); err != nil || seen[u.ID] {
			continue // Only monthly documents, once each; never follow CvrfUrl.
		}
		if u.InitialReleaseDate.IsZero() {
			return nil, fmt.Errorf("msrc: update %q has no initial release date", u.ID)
		}
		seen[u.ID] = true
		cd, ok := m.docs[u.ID]
		if !ok || u.CurrentReleaseDate.IsZero() || !cd.current.Equal(u.CurrentReleaseDate) {
			var doc document
			if err := m.get(ctx, "/cvrf/v3.0/cvrf/"+url.PathEscape(u.ID), maxDocument, &doc); err != nil {
				return nil, err
			}
			if doc.Vulnerability == nil {
				return nil, fmt.Errorf("msrc: document %q has no vulnerability array", u.ID)
			}
			cd = cachedDoc{current: u.CurrentReleaseDate, recs: map[string]*record{}}
			if err := compact(cd.recs, doc, u.InitialReleaseDate, &cd.fixes); err != nil {
				return nil, err
			}
		}
		if fixes += cd.fixes; fixes > maxFixes {
			return nil, fmt.Errorf("msrc: more than %d fix entries", maxFixes)
		}
		docs[u.ID] = cd
		order = append(order, u.ID)
		loaded++
		if loaded == m.months {
			break
		}
	}
	m.docs = docs // only the single load goroutine reaches this point
	data := map[string]*record{}
	for _, docID := range order {
		for id, r := range docs[docID].recs {
			merge(data, id, r)
		}
	}
	// Stable CVE ordering makes results reproducible across refreshes.
	ids := make([]string, 0, len(data))
	for id := range data {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]record, 0, len(ids))
	for _, id := range ids {
		out = append(out, *data[id])
	}
	return out, nil
}

// merge adds a copy of r to data; cached records are not changed.
func merge(data map[string]*record, id string, r *record) {
	d := data[id]
	if d == nil {
		c := *r
		c.fixes = append([]fix(nil), r.fixes...)
		data[id] = &c
		return
	}
	if d.title == "" {
		d.title = r.title
	}
	if r.published.Before(d.published) {
		d.published = r.published
	}
	n, _ := intel.LabelScore(r.severity)
	old, _ := intel.LabelScore(d.severity)
	if d.severity == "" || n > old {
		d.severity = r.severity
	}
	d.exploited = d.exploited || r.exploited
	d.score.include(r.score)
	d.fixes = append(d.fixes, r.fixes...)
}

// bounded also copies short prefixes so discarded API strings can be collected.
func bounded(s string) string { return strings.Clone(s[:min(len(s), maxStringBytes)]) }

func compact(data map[string]*record, doc document, published time.Time, count *int) error {
	products := map[string]string{}
	for _, p := range doc.ProductTree.FullProductName {
		if strings.HasPrefix(p.Value, "Windows") {
			products[p.ProductID] = bounded(p.Value)
		}
	}
	for _, v := range doc.Vulnerability {
		id := bounded(v.CVE)
		if id == "" {
			continue
		}
		var fallback score
		productScores := map[string]score{}
		for _, cs := range v.CVSSScoreSets {
			s := apiScore(cs.BaseScore, cs.Vector)
			fallback.include(s)
			for _, pid := range cs.ProductID {
				if _, ok := products[pid]; ok {
					ps := productScores[pid]
					ps.include(s)
					productScores[pid] = ps
				}
			}
		}
		var fixes []fix
		for _, r := range v.Remediations {
			b, ok := parseBuild(r.FixedBuild)
			if r.Type != 2 || !ok {
				continue
			}
			kb := strings.TrimSpace(r.Description.Value)
			if kb != "" {
				if strings.HasPrefix(strings.ToUpper(kb), "KB") {
					kb = kb[2:]
				}
				kb = bounded("KB" + strings.TrimSpace(kb))
			}
			for _, pid := range r.ProductID {
				product, ok := products[pid]
				if !ok {
					continue
				}
				if *count >= maxFixes {
					return fmt.Errorf("msrc: more than %d fix entries", maxFixes)
				}
				*count += 1
				fixes = append(fixes, fix{product: product, build: b, kb: kb, url: bounded(r.URL), score: productScores[pid]})
			}
		}
		if len(fixes) == 0 {
			continue
		}
		rec := data[id]
		if rec == nil {
			rec = &record{id: id, published: published}
			data[id] = rec
		}
		if rec.title == "" {
			rec.title = bounded(v.Title.Value)
		}
		if published.Before(rec.published) {
			rec.published = published
		}
		for _, threat := range v.Threats {
			switch threat.Type {
			case 3:
				severity := bounded(threat.Description.Value)
				n, _ := intel.LabelScore(severity)
				old, _ := intel.LabelScore(rec.severity)
				if rec.severity == "" || n > old {
					rec.severity = severity
				}
			case 1:
				for _, field := range strings.Split(threat.Description.Value, ";") {
					key, val, _ := strings.Cut(field, ":")
					if strings.EqualFold(strings.TrimSpace(key), "Exploited") && strings.EqualFold(strings.TrimSpace(val), "Yes") {
						rec.exploited = true
					}
				}
			}
		}
		rec.score.include(fallback)
		rec.fixes = append(rec.fixes, fixes...)
	}
	return nil
}

func apiScore(n json.Number, vector string) score {
	b, err := n.Float64()
	if err != nil || b < 0 || b > 10 {
		return score{}
	}
	return score{base: b, vector: bounded(vector), valid: true}
}

// Test forces one fresh fetch on this disposable matcher, without saving findings.
func (m *Matcher) Test(ctx context.Context) error { return m.load(ctx, true) }
