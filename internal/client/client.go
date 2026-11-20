// Package client is the Go side of the peer protocol, used by nn-scan,
// nn-actor and any other Go peer. It pins the server certificate by its
// SHA-256 fingerprint, enrolls with a join token, and sends observations.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
	"github.com/JulianStremel/netnoodle/internal/version"
)

// Credentials is what a peer stores after enrollment.
type Credentials struct {
	Server      string `json:"server"`      // e.g. https://10.0.0.2:7443
	Fingerprint string `json:"fingerprint"` // hex SHA-256 of the server certificate
	Name        string `json:"name"`
	Role        string `json:"role"`
	Token       string `json:"token"`
	OrderKey    string `json:"order_key,omitempty"`
}

// Client talks to nn-server.
type Client struct {
	creds Credentials
	http  *http.Client
}

// New returns a client for stored credentials.
func New(c Credentials) (*Client, error) {
	if c.Fingerprint == "" {
		return nil, errors.New("server fingerprint is required")
	}
	if !strings.HasPrefix(strings.ToLower(c.Server), "https://") {
		return nil, errors.New("server URL must start with https://")
	}
	hc, err := tlspin.Client(c.Fingerprint, false, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	c.Server = strings.TrimRight(c.Server, "/")
	return &Client{creds: c, http: hc}, nil
}

// Name returns the peer name.
func (c *Client) Name() string { return c.creds.Name }

// Enroll exchanges a join token for credentials.
func Enroll(ctx context.Context, server, fingerprint, joinToken, name string) (Credentials, error) {
	c, err := New(Credentials{Server: server, Fingerprint: fingerprint})
	if err != nil {
		return Credentials{}, err
	}
	var resp struct {
		Name     string `json:"name"`
		Role     string `json:"role"`
		Token    string `json:"token"`
		OrderKey string `json:"order_key"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/enroll", map[string]string{"join_token": joinToken, "name": name}, &resp); err != nil {
		return Credentials{}, err
	}
	return Credentials{Server: c.creds.Server, Fingerprint: fingerprint, Name: resp.Name, Role: resp.Role, Token: resp.Token, OrderKey: resp.OrderKey}, nil
}

// SaveCredentials writes credentials to a file only the owner can read:
// a new private file (0600 before any byte is written) that replaces the
// old one atomically. A symlink at path is replaced, not followed, and a
// directory that other users can write is refused (security review
// 2026-11-20).
func SaveCredentials(path string, c Credentials) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if i, err := os.Stat(dir); err != nil {
			return err
		} else if i.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s: directory is writable by other users", dir)
		}
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return orders.WriteFileDurable(path, b)
}

// LoadCredentials reads a credentials file.
func LoadCredentials(path string) (Credentials, error) {
	var c Credentials
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	if err == nil && (c.Server == "" || c.Token == "" || c.Fingerprint == "") {
		err = errors.New("credentials file is incomplete; enroll again")
	}
	return c, err
}

// PostObservation sends an observation.
func (c *Client) PostObservation(ctx context.Context, obs proto.Observation) error {
	obs.Version = proto.Version
	obs.Source = c.creds.Name
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now().UTC()
	}
	return c.do(ctx, http.MethodPost, "/v1/observations", obs, nil)
}

// Do sends a JSON request with the peer token and decodes the reply into out.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	return c.do(ctx, method, path, in, out)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.creds.Server+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.creds.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.creds.Token)
		req.Header.Set("X-Netnoodle-Version", version.Version)
		req.Header.Set("X-Netnoodle-Protocol", version.Protocol)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if res.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = res.Status
		}
		return fmt.Errorf("%s %s: %d %s", method, path, res.StatusCode, e.Error)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
