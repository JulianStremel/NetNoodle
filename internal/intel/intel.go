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
	ID        string            `json:"id"` // primary id, e.g. GHSA-..., CVE-..., DSA-...
	Aliases   []string          `json:"aliases,omitempty"`
	Summary   string            `json:"summary,omitempty"`
	Severity  float64           `json:"severity,omitempty"` // CVSS base score 0-10, 0 = unknown
	Vector    string            `json:"vector,omitempty"`
	Published time.Time         `json:"published,omitempty"`
	Modified  time.Time         `json:"modified,omitempty"`
	KEV       bool              `json:"kev,omitempty"`  // known exploited
	EPSS      float64           `json:"epss,omitempty"` // 0-1
	Fixed     []string          `json:"fixed,omitempty"`
	Refs      []string          `json:"refs,omitempty"`
	Facts     map[string]string `json:"facts,omitempty"` // free-form facts from enrichers
}

// Hit links one component to one vulnerability.
type Hit struct {
	Component proto.Component
	Vuln      Vuln
	Source    string // matcher name
}

// Matcher finds vulnerabilities for components.
type Matcher interface {
	Name() string
	Match(ctx context.Context, comps []proto.Component) ([]Hit, error)
}

// Enricher adds facts to vulnerabilities in place.
type Enricher interface {
	Name() string
	Refresh(ctx context.Context) error
	Enrich(ctx context.Context, v *Vuln) error
}

var (
	Matchers  = registry.New[Matcher]("matcher")
	Enrichers = registry.New[Enricher]("enricher")
)
