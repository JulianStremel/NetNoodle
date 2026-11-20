package updater

import (
	"fmt"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Cosign struct {
	Path     string `json:"path"`
	Key      string `json:"key,omitempty"`
	Identity string `json:"certificate_identity_regexp,omitempty"`
	Issuer   string `json:"certificate_oidc_issuer,omitempty"`
}
type Config struct {
	Mode               string `json:"mode"`
	ComposeFile        string `json:"compose_file"`
	ComposeProject     string `json:"compose_project"`
	Service            string `json:"service"`
	ImageRepo          string `json:"image_repo"`
	Channel            string `json:"channel"`
	RequireSignature   bool   `json:"require_signature"`
	Cosign             Cosign `json:"cosign"`
	SharedDir          string `json:"shared_dir"`
	HealthURL          string `json:"health_url"`
	HealthFingerprint  string `json:"health_fingerprint"`
	HealthTimeout      string `json:"health_timeout"`
	KeepDays           int    `json:"keep_days"`
	BinaryPath         string `json:"binary_path"`
	ReleaseURLTemplate string `json:"release_url_template"`
	ServiceUnit        string `json:"service_unit"`
}

func DefaultConfig() Config {
	return Config{Mode: "compose", Service: "server", Channel: "stable", RequireSignature: true, SharedDir: "/var/lib/netnoodle/updater", HealthTimeout: "120s", KeepDays: 7, Cosign: Cosign{Path: "cosign"}}
}
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	b, e := os.ReadFile(path)
	if e == nil {
		e = Decode(b, &c)
	}
	if e == nil {
		e = c.Validate()
	}
	return c, e
}
func (c Config) Validate() error {
	if c.Mode != "compose" && c.Mode != "binary" {
		return fmt.Errorf("invalid mode")
	}
	if c.Channel != "stable" && c.Channel != "latest" {
		return fmt.Errorf("invalid channel")
	}
	if (!filepath.IsAbs(c.SharedDir) && !strings.HasPrefix(c.SharedDir, "/")) || c.KeepDays < 1 || c.KeepDays > 365 {
		return fmt.Errorf("invalid shared_dir or keep_days")
	}
	d, e := time.ParseDuration(c.HealthTimeout)
	if e != nil || d <= 0 || d > time.Hour {
		return fmt.Errorf("invalid health_timeout")
	}
	u, e := url.Parse(c.HealthURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("health_url must be HTTPS")
	}
	if _, e = tlspin.Parse(c.HealthFingerprint); e != nil {
		return e
	}
	if c.RequireSignature && (c.Cosign.Path == "" || (c.Cosign.Key == "" && (c.Cosign.Identity == "" || c.Cosign.Issuer == ""))) {
		return fmt.Errorf("signature verification requires cosign key or identity and issuer")
	}
	if c.Cosign.Key != "" && (c.Cosign.Identity != "" || c.Cosign.Issuer != "") {
		return fmt.Errorf("cosign must use either key or certificate identity and issuer")
	}
	if c.Mode == "compose" {
		if (!filepath.IsAbs(c.ComposeFile) && !strings.HasPrefix(c.ComposeFile, "/")) || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`).MatchString(c.Service) || !regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`).MatchString(c.ComposeProject) {
			return fmt.Errorf("invalid compose file, project or service")
		}
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*$`).MatchString(c.ImageRepo) || strings.Contains(c.ImageRepo, "..") || strings.Contains(c.ImageRepo, "@") {
			return fmt.Errorf("invalid image_repo")
		}
	} else {
		if !filepath.IsAbs(c.BinaryPath) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]*\.service$`).MatchString(c.ServiceUnit) {
			return fmt.Errorf("invalid binary_path or service_unit")
		}
		u, e := url.Parse(strings.ReplaceAll(c.ReleaseURLTemplate, "{version}", "stable"))
		if e != nil || u.Scheme != "https" || u.Host == "" || !strings.Contains(c.ReleaseURLTemplate, "{version}") {
			return fmt.Errorf("invalid release_url_template")
		}
	}
	return nil
}
