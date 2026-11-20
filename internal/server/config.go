package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide/rules"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

// Config is the nn-server configuration file (JSON).
type Config struct {
	Update UpdateConfig `json:"update"`
	// Listen is the HTTPS listen address. Default ":7443".
	Listen string `json:"listen"`
	// DataDir holds the database, TLS key and signing keys. Default "./data".
	DataDir string `json:"data_dir"`
	// Store selects the persistence backend. Default: sqlite, netnoodle.db.
	Store registry.Spec `json:"store"`
	// SessionTTL is the lifetime of a web UI session. Default 12h.
	SessionTTL Duration `json:"session_ttl"`

	// ObservationRetention is how long raw observations are kept. Default 7 days.
	ObservationRetention Duration `json:"observation_retention"`

	// Plug-in instances. Each entry is {type, name, settings}.
	// Sources also take an "interval" (default 10m).
	Sources   []SourceSpec    `json:"sources,omitempty"`
	Notifiers []registry.Spec `json:"notifiers,omitempty"`
	// MQTT enables discovery and event publishing when present; absent is disabled.
	MQTT json.RawMessage `json:"mqtt,omitempty"`

	// Decisions default to rules and the four built-in safety guards.
	// An explicit empty list disables the corresponding plug-ins.
	Deciders []registry.Spec `json:"deciders"`
	Guards   []registry.Spec `json:"guards"`
	// Threat intelligence defaults to osv, msrc, kev and epss.
	Matchers  []registry.Spec `json:"matchers"`
	Enrichers []registry.Spec `json:"enrichers"`
	// IntelRefresh is the time between feed refreshes and full re-matches. Default 24h.
	IntelRefresh Duration `json:"intel_refresh"`
}

// Default plug-in specs apply when the config has no corresponding key.
var (
	DefaultDeciders  = []registry.Spec{{Type: "rules", Name: "rules", Settings: rules.DefaultRules}}
	DefaultGuards    = []registry.Spec{{Type: "protected"}, {Type: "scope"}, {Type: "rate"}, {Type: "killswitch"}}
	MandatoryGuards  = []string{"protected", "scope", "killswitch"}
	DefaultMatchers  = []registry.Spec{{Type: "osv", Name: "osv"}, {Type: "msrc", Name: "msrc"}}
	DefaultEnrichers = []registry.Spec{{Type: "kev", Name: "kev"}, {Type: "epss", Name: "epss"}}
)

// Duration is a time.Duration that reads "90s" / "12h" in JSON.
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// DefaultConfig returns a config with all defaults set.
func DefaultConfig() Config {
	return Config{
		Listen:     ":7443",
		DataDir:    "data",
		Store:      registry.Spec{Type: "sqlite"},
		SessionTTL: Duration{12 * time.Hour},
		Update:     DefaultUpdateConfig(),

		ObservationRetention: Duration{7 * 24 * time.Hour},
	}
}

func (c *Config) applyIntelDefaults() {
	if c.Deciders == nil {
		c.Deciders = DefaultDeciders
	}
	if c.Guards == nil {
		c.Guards = DefaultGuards
	}
	// The protected, scope and kill switch guards cannot be removed by
	// configuration (security review 2026-11-20); only settings of them.
	for _, kind := range MandatoryGuards {
		if !slices.ContainsFunc(c.Guards, func(g registry.Spec) bool { return g.Type == kind }) {
			c.Guards = append(c.Guards, registry.Spec{Type: kind})
		}
	}
	if c.Matchers == nil {
		c.Matchers = DefaultMatchers
	}
	if c.Enrichers == nil {
		c.Enrichers = DefaultEnrichers
	}
	if c.IntelRefresh.Duration <= 0 {
		c.IntelRefresh.Duration = 24 * time.Hour
	}
	if c.IntelRefresh.Duration < time.Hour {
		c.IntelRefresh.Duration = time.Hour
	}
}

// LoadConfig reads path. A missing file gives the defaults.
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	if path == "" {
		c.applyIntelDefaults()
		return c, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		c.applyIntelDefaults()
		return c, nil
	}
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("config %s: %w", path, err)
	}
	if c.ObservationRetention.Duration <= 0 {
		c.ObservationRetention.Duration = 7 * 24 * time.Hour
	}
	if c.SessionTTL.Duration <= 0 {
		c.SessionTTL.Duration = 12 * time.Hour
	}
	c.applyIntelDefaults()
	if err := c.Update.Validate(); err != nil {
		return c, fmt.Errorf("update: %w", err)
	}
	return c, nil
}
