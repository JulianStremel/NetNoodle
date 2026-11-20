// Package tlspin builds TLS client settings for servers with self-signed
// certificates: pin the SHA-256 fingerprint of the leaf certificate, or
// (only if the operator asks) skip verification.
package tlspin

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Parse decodes a hex fingerprint; colons and case are ignored.
func Parse(fp string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(fp)), ":", ""))
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("fingerprint must be 64 hex characters (SHA-256)")
	}
	return b, nil
}

// Config returns a TLS config.
//   - fingerprint set: accept only that leaf certificate.
//   - insecure true: accept any certificate (operator's explicit choice).
//   - neither: normal verification with the system roots.
func Config(fingerprint string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case fingerprint != "":
		want, err := Parse(fingerprint)
		if err != nil {
			return nil, err
		}
		cfg.InsecureSkipVerify = true // replaced by the pin check
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytes.Equal(got[:], want) {
				return fmt.Errorf("server certificate fingerprint %x does not match the pinned one", got)
			}
			return nil
		}
	case insecure:
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

// Client returns an HTTP client with the TLS config from Config.
func Client(fingerprint string, insecure bool, timeout time.Duration) (*http.Client, error) {
	cfg, err := Config(fingerprint, insecure)
	if err != nil {
		return nil, err
	}
	tr := Transport()
	tr.TLSClientConfig = cfg
	tr.MaxIdleConns = 4
	tr.IdleConnTimeout = time.Minute
	// A pinned peer never needs a redirect. Following one could leave the
	// pinned host or send credentials elsewhere.
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: NoRedirects}, nil
}

// NoRedirects is an http.Client CheckRedirect that never follows redirects.
func NoRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// HTTPSRedirects follows at most 3 redirects, and only to https URLs.
// Use it for public feeds that move their files (no credentials).
func HTTPSRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to non-https URL %s refused", req.URL.Redacted())
	}
	return nil
}
