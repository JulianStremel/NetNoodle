package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"netnoodle/internal/registry"
)

// Config is the nn-server configuration file (JSON).
type Config struct {
	// Listen is the HTTPS listen address. Default ":7443".
	Listen string `json:"listen"`
	// DataDir holds the database, TLS key and signing keys. Default "./data".
	DataDir string `json:"data_dir"`
	// SessionTTL is the lifetime of a web UI session. Default 12h.
	SessionTTL Duration `json:"session_ttl"`

	// Plug-in instances. Each entry is {type, name, settings}.
	Sources   []registry.Spec `json:"sources,omitempty"`
	Notifiers []registry.Spec `json:"notifiers,omitempty"`
}

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
		SessionTTL: Duration{12 * time.Hour},
	}
}

// LoadConfig reads path. A missing file gives the defaults.
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
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
	if c.SessionTTL.Duration <= 0 {
		c.SessionTTL.Duration = 12 * time.Hour
	}
	return c, nil
}
