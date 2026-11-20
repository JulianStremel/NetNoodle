// Package unifiactor blocks and unblocks UniFi clients using the classic API.
package unifiactor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

const maxResponseBody = 4 << 20
const deviceCacheTTL = 5 * time.Minute

// Settings configure the console, credentials, TLS trust and local protection.
// APIKeyFile is read once at construction; mode 0600 is recommended.
type Settings struct {
	URL             string   `json:"url"`
	APIKey          string   `json:"api_key"`
	APIKeyFile      string   `json:"api_key_file"`
	Fingerprint     string   `json:"fingerprint"`
	Insecure        bool     `json:"insecure_skip_verify"`
	Site            string   `json:"site"`
	ClassicPath     string   `json:"classic_path"`
	ProtectMACsFile string   `json:"protect_macs_file"`
	NeverBlock      []string `json:"never_block"`
	// AllowEmptyNeverBlock permits a configuration without protected MACs.
	AllowEmptyNeverBlock bool `json:"allow_empty_never_block"`
}

// Backend implements the isolate and unisolate actions for MAC targets.
type Backend struct {
	name       string
	base       string
	key        string
	client     *http.Client
	neverBlock map[string]bool
	mu         sync.Mutex
	devices    map[string]bool
	devicesAt  time.Time
	journal    *actor.Journal
}

func init() { actor.Registry.Register("unifi", New) }

// New strictly decodes settings and reads credentials without contacting UniFi.
func New(name string, raw json.RawMessage) (actor.Backend, error) {
	s := Settings{Site: "default", ClassicPath: "/proxy/network/api"}
	if !json.Valid(raw) || registry.Decode(raw, &s) != nil {
		// Decode errors can contain arbitrary input, including a secret.
		return nil, errors.New("unifi: invalid settings (malformed JSON or unknown fields)")
	}
	if (s.APIKey == "") == (s.APIKeyFile == "") {
		return nil, errors.New("unifi: exactly one of api_key and api_key_file is required")
	}
	if s.APIKeyFile != "" {
		key, err := os.ReadFile(s.APIKeyFile)
		if err != nil {
			return nil, errors.New("unifi: cannot read api_key_file")
		}
		s.APIKey = strings.TrimSpace(string(key))
	}
	if strings.TrimSpace(s.APIKey) == "" || strings.ContainsAny(s.APIKey, "\r\n") {
		return nil, errors.New("unifi: api_key must be nonempty and contain no newlines")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("unifi: url must be an HTTPS console or controller origin")
	}
	if s.Site == "" || s.Site == "." || s.Site == ".." || strings.ContainsAny(s.Site, "/\\?#") {
		return nil, errors.New("unifi: site must be a single nonempty path segment")
	}
	s.ClassicPath = strings.TrimRight(s.ClassicPath, "/")
	if !strings.HasPrefix(s.ClassicPath, "/") || path.Clean(s.ClassicPath) != s.ClassicPath || strings.ContainsAny(s.ClassicPath, "\\?#%") {
		return nil, errors.New("unifi: classic_path must be an absolute API path")
	}
	if s.ProtectMACsFile != "" {
		data, e := os.ReadFile(s.ProtectMACsFile)
		if e != nil {
			return nil, errors.New("unifi: cannot read protect_macs_file")
		}
		s.NeverBlock = append(s.NeverBlock, strings.Fields(string(data))...)
	}
	// Local MACs below are added automatically, but in a container they are
	// only the container's MACs (security review 2026-11-20).
	if len(s.NeverBlock) == 0 && !s.AllowEmptyNeverBlock {
		return nil, errors.New("unifi: never_block (or protect_macs_file) must protect the gateway, the controller and the server; explicitly set allow_empty_never_block to override")
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		return nil, errors.New("unifi: cannot enumerate local interfaces")
	}
	for _, iface := range interfaces {
		if len(iface.HardwareAddr) == 6 {
			mac := iface.HardwareAddr.String()
			s.NeverBlock = append(s.NeverBlock, mac)
			slog.Info("UniFi actor protecting local MAC", "interface", iface.Name, "mac", mac)
		}
	}
	protected := make(map[string]bool, len(s.NeverBlock))
	for _, value := range s.NeverBlock {
		mac, err := normalizeMAC(value)
		if err != nil {
			return nil, errors.New("unifi: invalid MAC in never_block")
		}
		protected[mac] = true
	}
	c, err := tlspin.Client(s.Fingerprint, s.Insecure, 20*time.Second)
	if err != nil {
		return nil, errors.New("unifi: invalid TLS fingerprint")
	}
	if s.Insecure {
		slog.Warn("UniFi actor insecure_skip_verify enabled; configure a TLS fingerprint or trusted certificate")
	}
	return &Backend{name: name, base: strings.TrimRight(s.URL, "/") + s.ClassicPath + "/s/" + url.PathEscape(s.Site), key: s.APIKey, client: c, neverBlock: protected, journal: &actor.Journal{}}, nil
}

func (b *Backend) SetJournal(j *actor.Journal) { b.journal = j }

func (b *Backend) Name() string { return b.name }

func (b *Backend) Capabilities() []proto.Capability {
	return []proto.Capability{
		{Action: "isolate", TargetIDKinds: []string{"mac"}, Reversible: true, RevertAction: "unisolate"},
		{Action: "unisolate", TargetIDKinds: []string{"mac"}},
	}
}

func normalizeMAC(value string) (string, error) {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return "", errors.New("unifi: invalid 48-bit MAC address")
	}
	return mac.String(), nil
}

// Execute protects infrastructure before changing a single client's block state.
func (b *Backend) Execute(ctx context.Context, o proto.Order) (message string, err error) {
	sent := false
	defer func() {
		if err != nil && sent {
			err = fmt.Errorf("%w: %w", actor.ErrPossiblyApplied, err)
		}
	}()
	if len(o.Targets) != 1 || o.Targets[0].Kind != "mac" {
		return "", errors.New("unifi: exactly one target of kind mac is required")
	}
	mac, err := normalizeMAC(o.Targets[0].Value)
	if err != nil {
		return "", err
	}
	cmd, state, blocked := "block-sta", "blocked", true
	switch o.Action {
	case "isolate":
	case "unisolate":
		cmd, state, blocked = "unblock-sta", "unblocked", false
	default:
		return "", errors.New("unifi: unsupported action")
	}
	// Only blocking is restricted. Unblocking must always work, so an
	// operator can recover a device that was blocked by mistake.
	if blocked {
		if b.neverBlock[mac] {
			return "", errors.New("unifi: target is protected by never_block")
		}
		if err := b.checkInfrastructure(ctx, mac); err != nil {
			return "", err
		}
	}
	if blocked {
		prior, e := b.blockedState(ctx, mac)
		if e != nil {
			return "", e
		}
		if e = b.journal.Put(o.ID, actor.JournalEntry{Backend: b.name, Target: mac, Action: o.Action, Expires: actor.OrderExpiry(o.TTL, o.NotAfter), Prior: prior}); e != nil {
			return "", e
		}
		if prior {
			return "already blocked; left as is", nil
		}
	} else if o.RevertOf != "" {
		// A revert acts only on what its order did. Without a journal entry
		// the order never changed anything (security review 2026-11-20).
		prior, ok := b.journal.Get(o.RevertOf, b.name, mac, "isolate")
		if !ok {
			return actor.NoJournal, nil
		}
		if prior.Prior {
			return "block was pre-existing; left blocked", nil
		}
	}
	payload, _ := json.Marshal(struct {
		Cmd string `json:"cmd"`
		MAC string `json:"mac"`
	}{cmd, mac})
	sent = true
	body, _, err := b.request(ctx, http.MethodPost, "/cmd/stamgr", payload)
	if err != nil {
		return "", err
	}
	var result response
	if err := json.Unmarshal(body, &result); err != nil {
		return "", errors.New("unifi: invalid command response JSON")
	}
	if err := result.checkRC(true); err != nil {
		return "", err
	}
	body, status, err := b.request(ctx, http.MethodGet, "/stat/user/"+mac, nil)
	if err != nil {
		return "", err
	}
	unknown := state + " (not verified: client unknown to stat/user)"
	if status == http.StatusNotFound || len(bytes.TrimSpace(body)) == 0 {
		return unknown, nil
	}
	var users struct {
		response
		Data []struct {
			Blocked *bool `json:"blocked"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &users); err != nil {
		return "", errors.New("unifi: invalid verification response JSON")
	}
	if err := users.checkRC(false); err != nil {
		return "", err
	}
	if len(users.Data) == 0 {
		return unknown, nil
	}
	if users.Data[0].Blocked == nil || *users.Data[0].Blocked != blocked {
		return "", errors.New("unifi: verification failed: client blocked state does not match order")
	}
	return state + " " + mac + "; verified", nil
}

type response struct {
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg"`
	} `json:"meta"`
}

func (r response) checkRC(required bool) error {
	if r.Meta.RC != "ok" && (required || r.Meta.RC != "") {
		// rc is upstream-controlled too: only the documented error code is safe.
		if r.Meta.RC == "error" {
			return errors.New("unifi: API rc error")
		}
		return errors.New("unifi: API rc invalid or missing")
	}
	return nil
}

func (b *Backend) checkInfrastructure(ctx context.Context, mac string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.devices == nil || time.Since(b.devicesAt) >= deviceCacheTTL {
		body, _, err := b.request(ctx, http.MethodGet, "/stat/device", nil)
		if err != nil {
			return fmt.Errorf("unifi: cannot check infrastructure: %w", err)
		}
		var result struct {
			response
			Data []struct {
				MAC string `json:"mac"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &result) != nil || result.Data == nil {
			return errors.New("unifi: invalid infrastructure device list")
		}
		if err := result.checkRC(false); err != nil {
			return err
		}
		devices := make(map[string]bool, len(result.Data))
		for _, device := range result.Data {
			value, err := normalizeMAC(device.MAC)
			if err != nil {
				return errors.New("unifi: invalid infrastructure device MAC")
			}
			devices[value] = true
		}
		b.devices, b.devicesAt = devices, time.Now()
	}
	if b.devices[mac] {
		return errors.New("unifi: refusing to change an adopted network device")
	}
	return nil
}

func (b *Backend) request(ctx context.Context, method, endpoint string, payload []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.base+endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-API-KEY", b.key)
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := b.client.Do(req)
	if err != nil {
		return nil, 0, errors.New("unifi: API transport failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBody+1))
	if err != nil {
		return nil, res.StatusCode, errors.New("unifi: API response read failed")
	}
	if len(body) > maxResponseBody {
		return nil, res.StatusCode, errors.New("unifi: response exceeds 4 MiB")
	}
	if res.StatusCode == http.StatusNotFound && method == http.MethodGet && strings.HasPrefix(endpoint, "/stat/user/") {
		return nil, res.StatusCode, nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, res.StatusCode, fmt.Errorf("unifi: API HTTP %d", res.StatusCode)
	}
	return body, res.StatusCode, nil
}

// Unknown clients may still be blocked by MAC. Malformed or failed reads must
// stop isolation before the mutation, since prior state cannot be preserved.
func (b *Backend) blockedState(ctx context.Context, mac string) (bool, error) {
	body, status, err := b.request(ctx, http.MethodGet, "/stat/user/"+mac, nil)
	if err != nil {
		return false, err
	}
	if status == 404 || len(bytes.TrimSpace(body)) == 0 {
		return false, nil
	}
	var users struct {
		response
		Data []struct {
			Blocked *bool `json:"blocked"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &users) != nil {
		return false, errors.New("unifi: invalid prior-state response JSON")
	}
	if err = users.checkRC(false); err != nil {
		return false, err
	}
	if len(users.Data) == 0 {
		return false, nil
	}
	if len(users.Data) != 1 || users.Data[0].Blocked == nil {
		return false, errors.New("unifi: invalid prior blocked state")
	}
	return *users.Data[0].Blocked, nil
}
