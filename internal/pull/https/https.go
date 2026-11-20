// Package https is the HTTPS pull transport: mutual TLS to `nn-agent serve`.
// The server presents its pull client certificate; the agent certificate
// is pinned after pairing. See docs/design/pull-mode.md.
package https

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/pull"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

// Limits of one pull.
const (
	MaxReport   = 64 << 20
	maxPairBody = 4 << 10
	pullTimeout = 2 * time.Minute
	pairTimeout = 20 * time.Second
)

// Transport pulls over HTTPS with a client certificate.
type Transport struct {
	cert     tls.Certificate
	serverFP string // fingerprint of cert, as the agent pins it
}

// New returns a transport that presents cert. fp is its fingerprint.
func New(cert tls.Certificate, fp string) *Transport {
	return &Transport{cert: cert, serverFP: strings.ToLower(fp)}
}

// client builds a one-shot HTTP client. verify checks the agent
// certificate; seen receives its fingerprint.
func (t *Transport) client(timeout time.Duration, verify func(fp string) error) *http.Client {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{t.cert},
		InsecureSkipVerify: true, // replaced by VerifyConnection (pin or pairing proof)
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("agent sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			return verify(hex.EncodeToString(sum[:]))
		},
	}
	tr := &http.Transport{
		TLSClientConfig:        cfg,
		Proxy:                  nil, // connect directly; the address is the agent
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: tlspin.NoRedirects}
}

func (t *Transport) get(ctx context.Context, c *http.Client, target pull.Target, path string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+target.Address+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nn-server")
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("answer larger than %d bytes", limit)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent answered %s", res.Status)
	}
	return body, nil
}

// Pair asks the agent for its pairing proof and returns its fingerprint.
func (t *Transport) Pair(ctx context.Context, target pull.Target, code string) (string, error) {
	var seen string
	c := t.client(pairTimeout, func(fp string) error { seen = fp; return nil })
	body, err := t.get(ctx, c, target, "/v1/pair", maxPairBody)
	if err != nil {
		return "", err
	}
	var r struct {
		Version string `json:"version"`
		Proof   string `json:"proof"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Version != "v1" {
		return "", errors.New("invalid pairing answer")
	}
	if seen == "" || !pull.CheckProof(r.Proof, code, seen, t.serverFP) {
		return "", errors.New("pairing proof does not match: wrong code, or another host answered")
	}
	return seen, nil
}

// Pull returns one report of a paired agent.
func (t *Transport) Pull(ctx context.Context, target pull.Target) ([]byte, error) {
	want := strings.ToLower(target.Pin)
	if len(want) != 64 {
		return nil, errors.New("agent is not paired")
	}
	c := t.client(pullTimeout, func(fp string) error {
		if fp != want {
			return fmt.Errorf("agent certificate fingerprint %s does not match the pinned one", fp)
		}
		return nil
	})
	body, err := t.get(ctx, c, target, "/v1/report", MaxReport)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(body), nil
}
