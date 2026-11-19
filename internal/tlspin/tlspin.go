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
	tr := &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment, MaxIdleConns: 4, IdleConnTimeout: time.Minute}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}
