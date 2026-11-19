// Package intel defines the threat-intelligence plug-ins.
//
//   - A Matcher maps installed components to known vulnerabilities (OSV, ...).
//   - An Enricher adds facts to a vulnerability (CISA KEV, FIRST EPSS, ...).
//
// Both may keep caches; Refresh is called on a schedule.
package intel

import (
	"context"
	"time"

	"netnoodle/internal/proto"
	"netnoodle/internal/registry"
)

// Vuln is one vulnerability in the server's normalized form.
type Vuln struct {
	ID        string            `json:"id"` // primary id, e.g. DEBIAN-CVE-..., GHSA-..., CVE-...
	Aliases   []string          `json:"aliases,omitempty"`
	Summary   string            `json:"summary,omitempty"`
	Score     float64           `json:"score,omitempty"`  // CVSS base score 0-10, 0 = unknown
	Vector    string            `json:"vector,omitempty"` // CVSS vector the score came from
	Published time.Time         `json:"published,omitempty"`
	Modified  time.Time         `json:"modified,omitempty"`
	KEV       bool              `json:"kev,omitempty"`      // listed as known exploited
	EPSS      float64           `json:"epss,omitempty"`     // exploit probability 0-1
	EPSSPct   float64           `json:"epss_pct,omitempty"` // EPSS percentile 0-1
	Refs      []string          `json:"refs,omitempty"`
	Facts     map[string]string `json:"facts,omitempty"` // free-form facts from matchers and enrichers
}

// CVEs returns the CVE IDs of the vulnerability (its ID and aliases).
func (v *Vuln) CVEs() []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if len(id) > 4 && id[:4] == "CVE-" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// SetFact sets a free-form fact.
func (v *Vuln) SetFact(k, val string) {
	if v.Facts == nil {
		v.Facts = map[string]string{}
	}
	v.Facts[k] = val
}

// Hit links one component to one vulnerability.
type Hit struct {
	Component  proto.Component
	Vuln       Vuln
	Fixed      string // first fixed version for this component; "" if no fix is known
	Confidence proto.Confidence
}

// Matcher finds vulnerabilities for components.
type Matcher interface {
	Name() string
	Match(ctx context.Context, comps []proto.Component) ([]Hit, error)
}

// Enricher adds facts to vulnerabilities in place.
type Enricher interface {
	Name() string
	// Refresh loads or updates the enricher's data. It is called at start
	// and then on a schedule. On error the old data stays in use.
	Refresh(ctx context.Context) error
	// Enrich sets facts on v. It must not do network calls.
	Enrich(v *Vuln)
}

var (
	Matchers  = registry.New[Matcher]("matcher")
	Enrichers = registry.New[Enricher]("enricher")
)
