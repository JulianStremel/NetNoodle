// Package homeassistant imports devices and versions using Home Assistant's
// authenticated, read-only WebSocket commands.
package homeassistant

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/source"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const (
	maxDevices     = 20000
	maxField       = 256
	maxConnections = 64
	maxDeviceMACs  = 4
)

func init() { source.Registry.Register("homeassistant", New) }

type Settings struct {
	URL             string `json:"url"`
	TokenFile       string `json:"token_file"`
	Fingerprint     string `json:"fingerprint"`
	Insecure        bool   `json:"insecure_skip_verify"`
	AllowHTTP       bool   `json:"allow_http"`
	IncludeTrackers bool   `json:"include_trackers"`
}

type Source struct {
	name, endpoint, host, token string
	s                           Settings
	client                      *http.Client
}

func New(name string, raw json.RawMessage) (source.Source, error) {
	s := Settings{IncludeTrackers: true}
	if !json.Valid(raw) || registry.Decode(raw, &s) != nil {
		return nil, errors.New("homeassistant: invalid settings")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("homeassistant: url must be an https origin")
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme != "https" {
		// Plain http only on the same computer. Names under .local are
		// resolved by unauthenticated mDNS, so any device on the LAN could
		// answer and receive the (administrator) token.
		if u.Scheme != "http" || !s.AllowHTTP || !(host == "127.0.0.1" || host == "::1") {
			return nil, errors.New("homeassistant: http requires allow_http and a loopback host; use https with fingerprint for a LAN host")
		}
	}
	if name == "" || len(name) > maxField || s.TokenFile == "" {
		return nil, errors.New("homeassistant: source name and token_file are required")
	}
	b, err := os.ReadFile(s.TokenFile)
	if err != nil {
		return nil, errors.New("homeassistant: cannot read token_file")
	}
	token := strings.TrimSpace(string(b))
	if token == "" || len(token) > 64<<10 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("homeassistant: invalid token_file")
	}
	c, err := tlspin.Client(s.Fingerprint, s.Insecure, time.Minute)
	if err != nil {
		return nil, errors.New("homeassistant: invalid TLS settings")
	}
	u.Path = "/api/websocket"
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	return &Source{name: name, endpoint: u.String(), host: host, token: token, s: s, client: c}, nil
}

func (s *Source) Name() string { return s.name }

type message struct {
	ID      int             `json:"id"`
	Type    string          `json:"type"`
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
}

type device struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	NameByUser   string     `json:"name_by_user"`
	Manufacturer string     `json:"manufacturer"`
	Model        string     `json:"model"`
	SW           string     `json:"sw_version"`
	HW           string     `json:"hw_version"`
	Area         string     `json:"area_id"`
	EntryType    string     `json:"entry_type"`
	Connections  [][]string `json:"connections"`
}

type registryEntity struct {
	EntityID string `json:"entity_id"`
	DeviceID string `json:"device_id"`
}

type state struct {
	EntityID   string          `json:"entity_id"`
	Attributes json.RawMessage `json:"attributes"`
}

type trackerAttributes struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	HostName string `json:"host_name"`
}

type config struct {
	Version      string `json:"version"`
	LocationName string `json:"location_name"`
	InternalURL  string `json:"internal_url"`
}

// All transport and remote errors deliberately omit remote payloads: even an
// auth error or WebSocket close reason can reflect the access token.
func (s *Source) Poll(ctx context.Context, emit func(proto.Observation) error) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	c, _, err := websocket.Dial(ctx, s.endpoint, &websocket.DialOptions{HTTPClient: s.client})
	if err != nil {
		return errors.New("homeassistant: WebSocket connection failed")
	}
	defer c.CloseNow()
	c.SetReadLimit(32 << 20)
	var m message
	if wsjson.Read(ctx, c, &m) != nil || m.Type != "auth_required" {
		return errors.New("homeassistant: invalid auth handshake")
	}
	if wsjson.Write(ctx, c, map[string]string{"type": "auth", "access_token": s.token}) != nil {
		return errors.New("homeassistant: auth write failed")
	}
	if wsjson.Read(ctx, c, &m) != nil || m.Type != "auth_ok" {
		return errors.New("homeassistant: authentication failed")
	}
	id := 0
	call := func(typ string, extra map[string]any, out any) error {
		id++
		req := map[string]any{"id": id, "type": typ}
		for k, v := range extra {
			req[k] = v
		}
		if wsjson.Write(ctx, c, req) != nil {
			return errors.New("homeassistant: command write failed")
		}
		var reply message
		if wsjson.Read(ctx, c, &reply) != nil {
			return errors.New("homeassistant: command read failed")
		}
		if reply.Type != "result" || reply.ID != id || !reply.Success {
			return errors.New("homeassistant: command rejected")
		}
		if json.Unmarshal(reply.Result, out) != nil {
			return errors.New("homeassistant: invalid command result")
		}
		return nil
	}
	var devices []device
	if err := call("config/device_registry/list", nil, &devices); err != nil {
		return err
	}
	if len(devices) > maxDevices {
		return errors.New("homeassistant: more than 20000 devices")
	}
	var trackers map[string][]trackerAttributes
	if s.s.IncludeTrackers {
		var entities []registryEntity
		if err := call("config/entity_registry/list", nil, &entities); err != nil {
			return err
		}
		var states []state
		if err := call("get_states", nil, &states); err != nil {
			return err
		}
		mapping := map[string]string{}
		for _, e := range entities {
			if strings.HasPrefix(e.EntityID, "device_tracker.") {
				mapping[e.EntityID] = e.DeviceID
			}
		}
		trackers = map[string][]trackerAttributes{}
		for _, st := range states {
			if dev := mapping[st.EntityID]; dev != "" && len(trackers[dev]) < maxConnections {
				var attributes trackerAttributes
				if json.Unmarshal(st.Attributes, &attributes) == nil {
					trackers[dev] = append(trackers[dev], attributes)
				}
			}
		}
	}
	var cfg config
	if err := call("get_config", nil, &cfg); err != nil {
		return err
	}
	host := proto.Entity{Kind: proto.KindHost, Name: short(cfg.LocationName), Identifiers: []proto.Identifier{{Kind: "homeassistant.instance", Value: s.name, Strength: proto.Strong}}}
	if host.Name == "" {
		host.Name = "homeassistant"
	}
	addIP(&host, s.host)
	if u, err := url.Parse(cfg.InternalURL); err == nil {
		addIP(&host, u.Hostname())
	}
	// Supervisor is optional (Core/Container installations do not have it).
	supervisor := func(endpoint string, out any) bool {
		var body json.RawMessage
		if call("supervisor/api", map[string]any{"endpoint": endpoint, "method": "get"}, &body) != nil {
			return false
		}
		// Supervisor responses are normally {result: "ok", data: {...}}.
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(body, &envelope) == nil && len(envelope.Data) > 0 {
			body = envelope.Data
		}
		return json.Unmarshal(body, out) == nil
	}
	var core, osinfo struct {
		Version string `json:"version"`
	}
	if supervisor("/core/info", &core) && cfg.Version == "" {
		cfg.Version = core.Version
	}
	component(&host, "pkg:pypi/homeassistant", "Home Assistant", cfg.Version, proto.High)
	if supervisor("/os/info", &osinfo) {
		component(&host, "pkg:generic/home-assistant/haos", "Home Assistant OS", osinfo.Version, proto.High)
	}
	var addons struct {
		Addons []struct {
			Slug    string `json:"slug"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"addons"`
	}
	if supervisor("/addons", &addons) {
		for i, a := range addons.Addons {
			if i == maxDevices {
				break
			}
			if a.Slug != "" {
				component(&host, "pkg:generic/home-assistant-addon/"+part(a.Slug), short(a.Name), a.Version, proto.High)
			}
		}
	}
	out := []proto.Entity{host}
	for _, d := range devices {
		if d.ID == "" || len(s.name+"/"+d.ID) > maxField {
			return errors.New("homeassistant: invalid device ID")
		}
		if len(d.Connections) > maxConnections {
			return errors.New("homeassistant: more than 64 connections per device")
		}
		name := d.NameByUser
		if name == "" {
			name = d.Name
		}
		e := proto.Entity{Kind: proto.KindNetworkDevice, Name: short(name), Identifiers: []proto.Identifier{{Kind: "homeassistant.device", Value: s.name + "/" + d.ID, Strength: proto.Strong}}, Attributes: map[string]string{
			"ha.manufacturer": short(d.Manufacturer), "ha.model": short(d.Model), "ha.sw_version": short(d.SW), "ha.hw_version": short(d.HW), "ha.area": short(d.Area),
		}}
		// Connections are what the device itself reports. A device with
		// many MAC addresses (or a device that lies) must not connect many
		// devices: above maxDeviceMACs, its MACs are not used as identifiers.
		macs := 0
		for _, conn := range d.Connections {
			if len(conn) == 2 && conn[0] == "mac" {
				macs++
			}
		}
		for _, conn := range d.Connections {
			if len(conn) == 2 && conn[0] == "mac" && macs <= maxDeviceMACs {
				addMAC(&e, conn[1])
			}
		}
		for _, st := range trackers[d.ID] {
			addIP(&e, st.IP)
			addMAC(&e, st.MAC)
			if st.HostName != "" {
				identifier(&e, "hostname", short(st.HostName), proto.Weak)
			}
		}
		if d.Manufacturer != "" && d.Model != "" && d.SW != "" {
			component(&e, "pkg:generic/"+part(d.Manufacturer)+"/"+part(d.Model), short(d.Model), d.SW, proto.Low)
		}
		if d.EntryType == "service" {
			out[0].Children = append(out[0].Children, e)
		} else {
			out = append(out, e)
		}
	}
	observation := func(entities []proto.Entity) error {
		return emit(proto.Observation{Version: proto.Version, Source: s.name, ObservedAt: time.Now().UTC(), Entities: entities})
	}
	// The registry cap excludes the HA host. At the exact boundary there
	// are 20001 entities, while ingest accepts 20000 per observation.
	if len(devices) == maxDevices {
		if len(out) > 1 {
			if err := observation(out[:len(out)-1]); err != nil {
				return err
			}
			return observation(out[len(out)-1:])
		}
		rest := out[0]
		rest.Children = rest.Children[maxDevices-1:]
		out[0].Children = out[0].Children[:maxDevices-1]
		if err := observation(out); err != nil {
			return err
		}
		return observation([]proto.Entity{rest})
	}
	return observation(out)
}

func short(s string) string {
	if len(s) > maxField {
		return strings.ToValidUTF8(s[:maxField], "")
	}
	return s
}
func part(s string) string {
	return url.PathEscape(strings.ReplaceAll(strings.ToLower(short(s)), " ", "-"))
}
func component(e *proto.Entity, purl, name, version string, confidence proto.Confidence) {
	version = short(version)
	purl += "@" + url.PathEscape(version)
	if version != "" && len(purl) <= maxField {
		e.Components = append(e.Components, proto.Component{PURL: purl, Name: short(name), Version: version, Confidence: confidence})
	}
}
func identifier(e *proto.Entity, kind, value string, strength proto.Strength) {
	for _, id := range e.Identifiers {
		if id.Kind == kind && id.Value == value {
			return
		}
	}
	e.Identifiers = append(e.Identifiers, proto.Identifier{Kind: kind, Value: value, Strength: strength})
}
func addIP(e *proto.Entity, raw string) {
	if ip, err := netip.ParseAddr(raw); err == nil {
		identifier(e, "ip", ip.Unmap().String(), proto.Weak)
	}
}
func addMAC(e *proto.Entity, raw string) {
	if len(raw) <= maxField {
		if mac, err := net.ParseMAC(raw); err == nil {
			identifier(e, "mac", mac.String(), proto.Strong)
		}
	}
}
