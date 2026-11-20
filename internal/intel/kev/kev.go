// Package kev enriches vulnerabilities from CISA's Known Exploited Vulnerabilities catalog.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

// maxEntries bounds the catalog (about 1,500 entries in 2026).
const maxEntries = 100000

const defaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
const maxBodySize = 16 << 20 // the catalog is about 1.5 MB (security review 2026-11-20)

func init() {
	intel.Enrichers.RegisterWithSchema("kev", New, registry.Schema{Fields: []registry.Field{{Key: "url", Label: "Catalog URL", Type: "url", Default: defaultURL}}})
}

// Settings configures the catalog endpoint.
type Settings struct {
	URL string `json:"url"`
}

type entry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

type enricher struct {
	name string
	url  string
	c    *http.Client
	mu   sync.RWMutex
	data map[string]entry
}

// New builds a KEV enricher. An empty URL selects CISA's public catalog.
func New(name string, raw json.RawMessage) (intel.Enricher, error) {
	var s Settings
	if err := registry.Decode(raw, &s); err != nil {
		return nil, err
	}
	if s.URL == "" {
		s.URL = defaultURL
	}
	if err := tlspin.CheckURL(s.URL, false); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	return &enricher{name: name, url: s.URL, c: &http.Client{Timeout: 60 * time.Second, CheckRedirect: tlspin.HTTPSRedirects}}, nil
}

func (e *enricher) Name() string { return e.name }

func (e *enricher) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.url, nil)
	if err != nil {
		return fmt.Errorf("kev request: %w", err)
	}
	req.Header.Set("User-Agent", "netnoodle")
	res, err := e.c.Do(req)
	if err != nil {
		return fmt.Errorf("kev download: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("kev download returned %s", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBodySize+1))
	if err != nil {
		return fmt.Errorf("kev read: %w", err)
	}
	if len(body) > maxBodySize {
		return fmt.Errorf("kev catalog exceeds %d bytes", maxBodySize)
	}
	var catalog struct {
		CatalogVersion  string  `json:"catalogVersion"`
		Vulnerabilities []entry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return fmt.Errorf("kev parse: %w", err)
	}
	if len(catalog.Vulnerabilities) == 0 {
		return fmt.Errorf("kev catalog has no entries")
	}
	if len(catalog.Vulnerabilities) > maxEntries {
		return fmt.Errorf("kev catalog has more than %d entries", maxEntries)
	}
	data := make(map[string]entry, len(catalog.Vulnerabilities))
	for _, item := range catalog.Vulnerabilities {
		if item.CVEID == "" {
			return fmt.Errorf("kev entry has no cveID")
		}
		if old, exists := data[item.CVEID]; !exists || item.DateAdded < old.DateAdded {
			data[item.CVEID] = item
		}
	}
	e.mu.Lock()
	e.data = data
	e.mu.Unlock()
	return nil
}

func (e *enricher) Enrich(v *intel.Vuln) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var selected entry
	found := false
	for _, cve := range v.CVEs() {
		item, ok := e.data[cve]
		// Catalog dates use ISO 8601 YYYY-MM-DD, so lexical order is chronological.
		if ok && (!found || item.DateAdded < selected.DateAdded) {
			selected, found = item, true
		}
	}
	if found {
		v.KEV = true
		v.SetFact("kev.added", selected.DateAdded)
		v.SetFact("kev.due", selected.DueDate)
		v.SetFact("kev.ransomware", selected.KnownRansomwareCampaignUse)
		v.SetFact("kev.name", selected.VulnerabilityName)
	}
}
