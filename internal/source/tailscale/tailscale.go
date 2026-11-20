// Package tailscale imports nodes and enabled subnet routes from the read-only
// Tailscale API. Poll intervals are handled by the common source runtime.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/source"
)

func init() { source.Registry.Register("tailscale", New) }

type Settings struct {
	Tailnet     string   `json:"tailnet"`
	APIKey      string   `json:"api_key"`
	APIKeyFile  string   `json:"api_key_file"`
	URL         string   `json:"url"`
	IncludeTags []string `json:"include_tags"`
}

type Source struct {
	name string
	s    Settings
	c    *http.Client
}

const (
	maxDevices    = 10000
	maxRoutes     = 64
	maxFieldBytes = 256
	maxBody       = 16 << 20
)

func New(name string, raw json.RawMessage) (source.Source, error) {
	s := Settings{Tailnet: "-", URL: "https://api.tailscale.com"}
	// Do not echo decoder errors: a misspelled field could contain the key.
	if !json.Valid(raw) {
		return nil, errors.New("tailscale: invalid settings")
	}
	if err := registry.Decode(raw, &s); err != nil {
		return nil, errors.New("tailscale: invalid settings")
	}
	if (s.APIKey == "") == (s.APIKeyFile == "") {
		return nil, errors.New("tailscale: exactly one of api_key and api_key_file is required")
	}
	if s.APIKeyFile != "" {
		b, err := os.ReadFile(s.APIKeyFile)
		if err != nil {
			return nil, errors.New("tailscale: cannot read api_key_file")
		}
		s.APIKey = strings.TrimSpace(string(b))
	}
	if strings.TrimSpace(s.APIKey) == "" || strings.ContainsAny(s.APIKey, "\r\n") {
		return nil, errors.New("tailscale: invalid API key")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("tailscale: url must be https://host with optional base path")
	}
	if s.Tailnet == "" || len(s.Tailnet) > maxFieldBytes || s.Tailnet == "." || s.Tailnet == ".." || strings.ContainsAny(s.Tailnet, "/\\\r\n") {
		return nil, errors.New("tailscale: invalid tailnet")
	}
	for _, tag := range s.IncludeTags {
		if tag == "" || len(tag) > maxFieldBytes {
			return nil, errors.New("tailscale: invalid include_tags")
		}
	}
	c := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Source{name: name, s: s, c: c}, nil
}

func (s *Source) Name() string { return s.name }

type device struct {
	NodeID            string   `json:"nodeId"`
	Hostname          string   `json:"hostname"`
	Name              string   `json:"name"`
	Addresses         []string `json:"addresses"`
	OS                string   `json:"os"`
	ClientVersion     string   `json:"clientVersion"`
	UpdateAvailable   bool     `json:"updateAvailable"`
	Tags              []string `json:"tags"`
	LastSeen          string   `json:"lastSeen"`
	EnabledRoutes     []string `json:"enabledRoutes"`
	KeyExpiryDisabled bool     `json:"keyExpiryDisabled"`
	Authorized        bool     `json:"authorized"`
	BlocksIncoming    bool     `json:"blocksIncoming"`
}

func short(s string) string {
	if len(s) > maxFieldBytes {
		return strings.ToValidUTF8(s[:maxFieldBytes], "")
	}
	return s
}

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func clientVersion(raw string) string {
	v, _, _ := strings.Cut(raw, "-")
	if len(v) > maxFieldBytes || !semver.MatchString(v) {
		return ""
	}
	return "v" + v
}

func (s *Source) entity(d device) (proto.Entity, error) {
	if d.NodeID == "" || len(d.NodeID) > maxFieldBytes {
		return proto.Entity{}, errors.New("tailscale: invalid node ID")
	}
	if len(d.EnabledRoutes) > maxRoutes {
		return proto.Entity{}, errors.New("tailscale: more than 64 routes per device")
	}
	name := short(d.Hostname)
	if name == "" {
		name, _, _ = strings.Cut(short(d.Name), ".")
	}
	ids := []proto.Identifier{{Kind: "tailscale.node", Value: d.NodeID, Strength: proto.Strong}}
	if name != "" {
		ids = append(ids, proto.Identifier{Kind: "hostname", Value: name, Strength: proto.Weak})
	}
	ips := []string{}
	for _, raw := range d.Addresses {
		if len(raw) > maxFieldBytes {
			continue
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		ips = append(ips, ip.String())
		ids = append(ids, proto.Identifier{Kind: "ip", Value: ip.String(), Strength: proto.Weak})
	}
	routes := []string{}
	seenRoutes := map[string]bool{}
	exit := false
	for _, raw := range d.EnabledRoutes {
		if len(raw) > maxFieldBytes {
			return proto.Entity{}, errors.New("tailscale: invalid enabled route")
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return proto.Entity{}, errors.New("tailscale: invalid enabled route")
		}
		if p.Bits() == 0 {
			exit = true
			continue
		}
		route := p.Masked().String()
		if !seenRoutes[route] {
			seenRoutes[route] = true
			routes = append(routes, route)
		}
	}
	// Reject an oversized field rather than truncating a CIDR, which could
	// silently change the network or omit reachability evidence.
	routeField := strings.Join(routes, ",")
	if len(routeField) > maxFieldBytes {
		return proto.Entity{}, errors.New("tailscale: enabled routes exceed 256 bytes")
	}
	attrs := map[string]string{
		"tailscale.os":                  short(d.OS),
		"tailscale.client_version":      short(d.ClientVersion),
		"tailscale.update_available":    strconv.FormatBool(d.UpdateAvailable),
		"tailscale.tags":                short(strings.Join(d.Tags, ",")),
		"tailscale.last_seen":           short(d.LastSeen),
		"tailscale.routes":              routeField,
		"tailscale.exit_node":           strconv.FormatBool(exit),
		"tailscale.key_expiry_disabled": strconv.FormatBool(d.KeyExpiryDisabled),
		"tailscale.authorized":          strconv.FormatBool(d.Authorized),
		"tailscale.blocks_incoming":     strconv.FormatBool(d.BlocksIncoming),
	}
	e := proto.Entity{Kind: proto.KindHost, Name: name, Identifiers: ids, Attributes: attrs,
		Interfaces: []proto.Interface{{Name: "tailscale0", Kind: "vpn", VPN: "tailscale", IPs: ips}}}
	if v := clientVersion(d.ClientVersion); v != "" {
		e.Components = []proto.Component{{PURL: "pkg:golang/tailscale.com@" + v, Name: "tailscale.com", Version: v, Confidence: proto.High}}
	}
	return e, nil
}

func (s *Source) Poll(ctx context.Context, emit func(proto.Observation) error) error {
	endpoint := strings.TrimRight(s.s.URL, "/") + "/api/v2/tailnet/" + url.PathEscape(s.s.Tailnet) + "/devices?fields=all"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("tailscale: cannot build request")
	}
	req.Header.Set("Authorization", "Bearer "+s.s.APIKey)
	req.Header.Set("Accept", "application/json")
	// Never echo URLs, headers, response bodies or transport errors.
	res, err := s.c.Do(req)
	if err != nil {
		return errors.New("tailscale: request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("tailscale: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return errors.New("tailscale: cannot read response")
	}
	if len(body) > maxBody {
		return errors.New("tailscale: response exceeds 16 MiB")
	}
	var env struct {
		Devices []device `json:"devices"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return errors.New("tailscale: invalid response")
	}
	if len(env.Devices) > maxDevices {
		return errors.New("tailscale: more than 10000 devices")
	}
	obs := proto.Observation{Version: proto.Version, Source: s.name, ObservedAt: time.Now().UTC(), Entities: []proto.Entity{}}
	for _, d := range env.Devices {
		selected := len(s.s.IncludeTags) == 0
		for _, tag := range s.s.IncludeTags {
			selected = selected || slices.Contains(d.Tags, tag)
		}
		if !selected {
			continue
		}
		e, err := s.entity(d)
		if err != nil {
			return err
		}
		obs.Entities = append(obs.Entities, e)
	}
	return emit(obs)
}
