// Package unifi is a read-only source for the UniFi Network Integration
// API (API key in the X-API-KEY header). It reports UniFi network devices
// and their firmware, and all clients the controller knows.
//
// Settings:
//
//	{
//	  "url": "https://192.168.1.1",          // console or controller
//	  "api_key": "...",                      // create in Network > Settings > Control Plane > Integrations
//	  "api_path": "/proxy/network/integration/v1",   // default; self-hosted controllers may differ
//	  "fingerprint": "<sha256 hex>",         // pin the self-signed certificate (recommended)
//	  "insecure_skip_verify": false,
//	  "sites": ["Default"]                   // names or ids; empty = all
//	}
package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/source"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

func init() {
	source.Registry.Register("unifi", New)
}

// Settings configure the source.
type Settings struct {
	URL        string   `json:"url"`
	APIKey     string   `json:"api_key"`
	APIKeyFile string   `json:"api_key_file,omitempty"`
	APIPath    string   `json:"api_path,omitempty"`
	FP         string   `json:"fingerprint,omitempty"`
	Insecure   bool     `json:"insecure_skip_verify,omitempty"`
	Sites      []string `json:"sites,omitempty"`
}

// Source is the UniFi source.
type Source struct {
	name string
	s    Settings
	base string
	c    *http.Client
}

// New builds the source from settings.
func New(name string, raw json.RawMessage) (source.Source, error) {
	var s Settings
	if err := registry.Decode(raw, &s); err != nil {
		return nil, err
	}
	if s.APIKey == "" && s.APIKeyFile != "" {
		b, err := os.ReadFile(s.APIKeyFile)
		if err != nil {
			return nil, err
		}
		s.APIKey = strings.TrimSpace(string(b))
	}
	if s.URL == "" || s.APIKey == "" {
		return nil, errors.New("url and api_key (or api_key_file) are required")
	}
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("bad url %q", s.URL)
	}
	if s.APIPath == "" {
		s.APIPath = "/proxy/network/integration/v1"
	}
	c, err := tlspin.Client(s.FP, s.Insecure, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return &Source{name: name, s: s, base: strings.TrimRight(s.URL, "/") + "/" + strings.Trim(s.APIPath, "/"), c: c}, nil
}

func (u *Source) Name() string { return u.name }

type page[T any] struct {
	Offset     int `json:"offset"`
	Limit      int `json:"limit"`
	Count      int `json:"count"`
	TotalCount int `json:"totalCount"`
	Data       []T `json:"data"`
}

type site struct {
	ID                string `json:"id"`
	InternalReference string `json:"internalReference"`
	Name              string `json:"name"`
}

type device struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Model           string `json:"model"`
	MACAddress      string `json:"macAddress"`
	IPAddress       string `json:"ipAddress"`
	State           string `json:"state"`
	FirmwareVersion string `json:"firmwareVersion"`
}

type client struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Name           string `json:"name"`
	ConnectedAt    string `json:"connectedAt"`
	IPAddress      string `json:"ipAddress"`
	MACAddress     string `json:"macAddress"`
	UplinkDeviceID string `json:"uplinkDeviceId"`
}

const pageSize = 200
const maxPages = 500

func (u *Source) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", u.s.APIKey)
	req.Header.Set("Accept", "application/json")
	res, err := u.c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, res.Status)
	}
	return json.Unmarshal(body, out)
}

func all[T any](ctx context.Context, u *Source, path string) ([]T, error) {
	var out []T
	for i, off := 0, 0; i < maxPages; i++ {
		var p page[T]
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		if err := u.get(ctx, fmt.Sprintf("%s%soffset=%d&limit=%d", path, sep, off, pageSize), &p); err != nil {
			return nil, err
		}
		out = append(out, p.Data...)
		off += len(p.Data)
		if len(p.Data) == 0 || off >= p.TotalCount {
			return out, nil
		}
	}
	return out, fmt.Errorf("%s: more than %d pages", path, maxPages)
}

// Poll reads all selected sites and emits one observation per site.
func (u *Source) Poll(ctx context.Context, emit func(proto.Observation) error) error {
	sites, err := all[site](ctx, u, "/sites")
	if err != nil {
		return err
	}
	sites, err = selectSites(sites, u.s.Sites)
	if err != nil {
		return err
	}
	for _, st := range sites {
		devs, err := all[device](ctx, u, "/sites/"+url.PathEscape(st.ID)+"/devices")
		if err != nil {
			return err
		}
		clients, err := all[client](ctx, u, "/sites/"+url.PathEscape(st.ID)+"/clients")
		if err != nil {
			return err
		}
		obs := proto.Observation{ObservedAt: time.Now().UTC(), Entities: Entities(st.Name, devs, clients)}
		if err := emit(obs); err != nil {
			return err
		}
	}
	return nil
}

func selectSites(all []site, want []string) ([]site, error) {
	if len(want) == 0 {
		return all, nil
	}
	var out []site
	for _, w := range want {
		found := false
		for _, s := range all {
			if strings.EqualFold(s.Name, w) || s.ID == w || s.InternalReference == w {
				out = append(out, s)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("site %q not found", w)
		}
	}
	return out, nil
}

// Entities converts UniFi devices and clients to entities. Exported for tests.
func Entities(siteName string, devs []device, clients []client) []proto.Entity {
	var out []proto.Entity
	for _, d := range devs {
		e := proto.Entity{
			Kind: proto.KindNetworkDevice,
			Name: d.Name,
			Identifiers: []proto.Identifier{
				{Kind: "unifi.device", Value: d.ID, Strength: proto.Strong},
			},
			Attributes: map[string]string{
				"vendor":      "Ubiquiti",
				"model":       d.Model,
				"unifi.site":  siteName,
				"unifi.state": d.State,
			},
		}
		if d.MACAddress != "" {
			e.Interfaces = []proto.Interface{{MAC: d.MACAddress, IPs: nonEmpty(d.IPAddress)}}
		} else if d.IPAddress != "" {
			e.Identifiers = append(e.Identifiers, proto.Identifier{Kind: "ip", Value: d.IPAddress, Strength: proto.Weak})
		}
		if d.FirmwareVersion != "" {
			e.Attributes["firmware"] = d.FirmwareVersion
			model := strings.ToLower(strings.ReplaceAll(d.Model, " ", "-"))
			if model == "" {
				model = "unifi-device"
			}
			e.Components = []proto.Component{{
				PURL:    "pkg:generic/ubiquiti/" + url.PathEscape(model) + "@" + url.PathEscape(d.FirmwareVersion),
				Name:    "UniFi firmware " + d.Model,
				Version: d.FirmwareVersion,
			}}
		}
		out = append(out, e)
	}
	for _, c := range clients {
		e := proto.Entity{
			Kind: proto.KindUnknown,
			Name: c.Name,
			Identifiers: []proto.Identifier{
				{Kind: "unifi.client", Value: c.ID, Strength: proto.Strong},
			},
			Attributes: map[string]string{
				"unifi.site":        siteName,
				"unifi.connection":  strings.ToLower(c.Type),
				"unifi.uplink":      c.UplinkDeviceID,
				"unifi.connectedat": c.ConnectedAt,
			},
		}
		if c.MACAddress != "" {
			e.Interfaces = []proto.Interface{{MAC: c.MACAddress, IPs: nonEmpty(c.IPAddress)}}
		} else if c.IPAddress != "" {
			e.Identifiers = append(e.Identifiers, proto.Identifier{Kind: "ip", Value: c.IPAddress, Strength: proto.Weak})
		}
		out = append(out, e)
	}
	return out
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
