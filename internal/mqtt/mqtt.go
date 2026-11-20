// Package mqtt publishes Home Assistant discovery, inventory snapshots and
// notification events over one broker connection. The server owns its lifetime.
package mqtt

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
	paho "github.com/eclipse/paho.mqtt.golang"
)

type Settings struct {
	Broker          string `json:"broker"`
	AllowPlain      bool   `json:"allow_plain"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	PasswordFile    string `json:"password_file"`
	ClientID        string `json:"client_id"`
	TopicPrefix     string `json:"topic_prefix"`
	DiscoveryPrefix string `json:"discovery_prefix"`
	Interval        string `json:"interval"`
	DeviceTag       string `json:"device_tag"`
	// Events are the event types published to <prefix>/event. Default:
	// defaultEvents. Other events (proposal details, claims, ...) stay
	// inside netnoodle.
	Events []string `json:"events"`
	// EventDetails also publishes the detail text of an event. Off by
	// default: details can name identifiers of devices that are not
	// tagged for Home Assistant.
	EventDetails bool `json:"event_details"`
	// Fingerprint pins the broker certificate (SHA-256 hex), for a broker
	// with a self-signed certificate.
	Fingerprint string `json:"fingerprint"`
}

var defaultEvents = []string{"device.new", "finding.new", "proposal.pending", "order.done", "order.failed", "order.uncertain", "order.expired", "order.revert-blocked"}

// republishEvery re-sends the retained discovery configs every N snapshots,
// so a config that another broker client changed is repaired.
const republishEvery = 10

// Snapshot contains only the data exported to Home Assistant. Collecting it is
// done in the publisher worker, never on an ingest or matching goroutine.
type Snapshot struct {
	OpenFindings, Critical, KEV, Exposed                    int
	Devices, New24h, ReachInternet, ReachTunnel, ReachLocal int
	PendingApprovals                                        int
	KEVReachable, KillSwitch                                bool
	DeviceRisks                                             []Device
}

type Device struct {
	ID   string
	Name string
	Tags []string
	Risk float64
	Top  any
}

type Provider func(context.Context) (Snapshot, error)

const queueSize = 256
const debounce = 5 * time.Second

type Publisher struct {
	name                       string
	s                          Settings
	broker, password, identity string
	interval                   time.Duration
	provider                   Provider
	wake                       chan struct{}
	events                     chan notify.Event
	mu                         sync.Mutex // serialize drop-oldest producers
	// Only the Run goroutine accesses configs, bases and cycles.
	configs     map[string]string
	bases       map[string]string // config topic → state/attributes base topic
	cycles      int
	allowEvents map[string]bool
	tls         *tls.Config
}

// New validates settings and reads the password file once at startup. Errors
// never include settings, credentials, broker replies or file contents.
func New(raw json.RawMessage, provider Provider) (*Publisher, error) {
	s := Settings{ClientID: "netnoodle", TopicPrefix: "netnoodle", DiscoveryPrefix: "homeassistant", Interval: "60s", DeviceTag: "ha"}
	if !json.Valid(raw) || registry.Decode(raw, &s) != nil {
		return nil, errors.New("mqtt: invalid settings")
	}
	u, err := url.Parse(s.Broker)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "mqtt" && u.Scheme != "mqtts") {
		return nil, errors.New("mqtt: broker must be mqtts://host:port")
	}
	if u.Scheme == "mqtt" && !s.AllowPlain {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.Unmap().IsLoopback() {
			return nil, errors.New("mqtt: plaintext requires loopback or allow_plain")
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("mqtt: invalid broker port")
		}
	}
	if u.Scheme == "mqtts" {
		u.Scheme = "ssl"
		if port == "" {
			port = "8883"
		}
	} else {
		u.Scheme = "tcp"
		if port == "" {
			port = "1883"
		}
	}
	u.Host = net.JoinHostPort(u.Hostname(), port)
	u.Path = ""
	every, err := time.ParseDuration(s.Interval)
	if err != nil || every <= 0 {
		return nil, errors.New("mqtt: interval must be a positive duration")
	}
	if every < debounce {
		every = debounce
	}
	if s.ClientID == "" || len(s.ClientID) > 256 || strings.ContainsAny(s.ClientID, "\x00\r\n") || s.DeviceTag == "" || len(s.DeviceTag) > 256 || !validPrefix(s.TopicPrefix) || !validPrefix(s.DiscoveryPrefix) {
		return nil, errors.New("mqtt: invalid client_id, device_tag or topic prefix")
	}
	password := s.Password
	if s.PasswordFile != "" {
		b, err := os.ReadFile(s.PasswordFile)
		if err != nil {
			return nil, errors.New("mqtt: cannot read password_file")
		}
		password = strings.TrimSpace(string(b))
		if password == "" {
			return nil, errors.New("mqtt: empty password_file")
		}
	}
	if provider == nil {
		return nil, errors.New("mqtt: data provider required")
	}
	if s.Events == nil {
		s.Events = defaultEvents
	}
	allowed := map[string]bool{}
	for _, e := range s.Events {
		allowed[e] = true
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.Fingerprint != "" {
		if tlsCfg, err = tlspin.Config(s.Fingerprint, false); err != nil {
			return nil, errors.New("mqtt: fingerprint must be 64 hex characters")
		}
	}
	return &Publisher{s: s, broker: u.String(), password: password, identity: "netnoodle_" + digest(s.TopicPrefix+"/"+s.ClientID), interval: every, provider: provider, wake: make(chan struct{}, 1), events: make(chan notify.Event, queueSize), configs: map[string]string{}, bases: map[string]string{}, allowEvents: allowed, tls: tlsCfg}, nil
}

func validPrefix(s string) bool {
	return s != "" && len(s) <= 256 && strings.Trim(s, "/") == s && !strings.ContainsAny(s, "+#\x00\r\n") && !strings.Contains(s, "//")
}

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:8]) }

// Trigger coalesces snapshot requests; callers never wait for the broker.
func (p *Publisher) Trigger() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Notify copies the event's scalar fields into a bounded drop-oldest queue.
// Fields are intentionally excluded from the public event payload.
func (p *Publisher) Notify(_ context.Context, e notify.Event) error {
	if e.Type != "integration.test" && !p.allowEvents[e.Type] {
		return nil
	}
	e.Fields = nil
	if !p.s.EventDetails {
		// Titles contain device names and vulnerability IDs of devices
		// that are not tagged for MQTT: without event_details only a
		// generic title is published (security review 2026-11-20).
		e.Detail = ""
		e.Title = genericTitle(e.Type)
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	p.mu.Lock()
	select {
	case p.events <- e:
	default:
		select {
		case <-p.events:
		default:
		}
		p.events <- e
	}
	p.mu.Unlock()
	p.Trigger()
	return nil
}

func (p *Publisher) Name() string {
	if p.name != "" {
		return p.name
	}
	return "mqtt"
}

func waitToken(ctx context.Context, t paho.Token) bool {
	select {
	case <-ctx.Done():
		return false
	case <-t.Done():
		return t.Error() == nil
	}
}

func (p *Publisher) publish(ctx context.Context, c paho.Client, topic string, retained bool, payload any) bool {
	b, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	return p.send(ctx, c, topic, retained, b)
}

func (p *Publisher) send(ctx context.Context, c paho.Client, topic string, retained bool, payload []byte) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return waitToken(ctx, c.Publish(topic, 1, retained, payload))
}

// Run reconnects with exponential backoff (1s to 30s). Only this worker talks
// to the broker; a slow or absent broker cannot block notification producers.
func (p *Publisher) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		opts := paho.NewClientOptions().AddBroker(p.broker).SetClientID(p.s.ClientID).
			SetUsername(p.s.Username).SetPassword(p.password).SetAutoReconnect(false).
			SetConnectRetry(false).SetConnectTimeout(5*time.Second).SetWriteTimeout(5*time.Second).
			SetKeepAlive(15*time.Second).SetPingTimeout(5*time.Second).
			SetDialer(&net.Dialer{Timeout: 5 * time.Second, Control: tlspin.SafeControl}).SetTLSConfig(p.tls).
			SetWill(p.s.TopicPrefix+"/availability", "offline", 1, true)
		c := paho.NewClient(opts)
		connectCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		tok := c.Connect()
		connected := waitToken(connectCtx, tok)
		cancel()
		if !connected && ctx.Err() == nil {
			// Generic reason only: broker replies are not logged.
			reason := "timeout"
			if err := tok.Error(); err != nil {
				reason = "connection refused or TLS/authentication failed"
			}
			slog.Warn("mqtt: cannot connect to broker", "reason", reason, "retry_in", backoff)
		}
		if connected {
			backoff = time.Second
			p.connected(ctx, c)
		}
		c.Disconnect(0)
		if ctx.Err() != nil {
			return
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (p *Publisher) connected(ctx context.Context, c paho.Client) {
	defer func() {
		if ctx.Err() != nil && c.IsConnectionOpen() {
			offline, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			p.send(offline, c, p.s.TopicPrefix+"/availability", true, []byte("offline"))
		}
	}()
	if !p.send(ctx, c, p.s.TopicPrefix+"/availability", true, []byte("online")) {
		return
	}
	// Rediscover after every reconnect, even when a broker lost its retained data.
	for topic := range p.configs {
		p.configs[topic] = ""
	}
	due := time.NewTimer(0)
	defer due.Stop()
	check := time.NewTicker(time.Second)
	defer check.Stop()
	last := time.Time{}
	pending := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			if !c.IsConnectionOpen() {
				return
			}
		case e := <-p.events:
			payload := struct {
				Type     string    `json:"type"`
				Severity string    `json:"severity"`
				Title    string    `json:"title"`
				Detail   string    `json:"detail"`
				Link     string    `json:"link"`
				At       time.Time `json:"at"`
			}{e.Type, e.Severity, e.Title, e.Detail, e.Link, e.At}
			if !p.publish(ctx, c, p.s.TopicPrefix+"/event", false, payload) {
				return
			}
		case <-p.wake:
			if !pending {
				due.Reset(max(time.Until(last.Add(debounce)), 0))
				pending = true
			}
		case <-due.C:
			pending = false
			sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			snapshot, err := p.provider(sctx)
			cancel()
			if err == nil && !p.snapshot(ctx, c, snapshot) {
				return
			}
			last = time.Now()
			due.Reset(p.interval)
		}
	}
}

type reading struct {
	key, kind, name string
	state           any
	attributes      any
	device          map[string]any
	problem         bool
}

func (p *Publisher) snapshot(ctx context.Context, c paho.Client, s Snapshot) bool {
	device := map[string]any{"identifiers": []string{p.identity}, "name": "netnoodle", "manufacturer": "netnoodle"}
	onoff := func(b bool) string {
		if b {
			return "ON"
		}
		return "OFF"
	}
	readings := []reading{
		{"open_findings", "sensor", "Open findings", s.OpenFindings, map[string]int{"critical": s.Critical, "kev": s.KEV, "exposed": s.Exposed}, device, false},
		{"devices", "sensor", "Devices", s.Devices, map[string]int{"new_24h": s.New24h, "internet": s.ReachInternet, "tunnel": s.ReachTunnel, "local": s.ReachLocal}, device, false},
		{"kev_reachable", "binary_sensor", "KEV reachable", onoff(s.KEVReachable), nil, device, true},
		{"pending_approvals", "sensor", "Pending approvals", s.PendingApprovals, nil, device, false},
		{"kill_switch", "binary_sensor", "Kill switch", onoff(s.KillSwitch), nil, device, false},
	}
	for _, d := range s.DeviceRisks {
		include := false
		for _, tag := range d.Tags {
			if tag == p.s.DeviceTag {
				include = true
				break
			}
		}
		if !include {
			continue
		}
		key := "risk_" + digest(d.ID)
		readings = append(readings, reading{key, "sensor", "Risk", max(0, min(10, d.Risk)), map[string]any{"top_findings": d.Top}, map[string]any{"identifiers": []string{p.identity + "_" + key}, "name": d.Name, "via_device": p.identity}, false})
	}
	active := map[string]bool{}
	for _, r := range readings {
		base := p.s.TopicPrefix + "/" + r.key
		topic := p.s.DiscoveryPrefix + "/" + r.kind + "/" + p.identity + "/" + r.key + "/config"
		cfg := map[string]any{"name": r.name, "unique_id": p.identity + "_" + r.key, "state_topic": base + "/state", "availability_topic": p.s.TopicPrefix + "/availability", "payload_available": "online", "payload_not_available": "offline", "device": r.device}
		if r.attributes != nil {
			cfg["json_attributes_topic"] = base + "/attributes"
		}
		if r.problem {
			cfg["device_class"] = "problem"
		}
		if r.kind == "binary_sensor" {
			cfg["payload_on"] = "ON"
			cfg["payload_off"] = "OFF"
		}
		b, err := json.Marshal(cfg)
		if err != nil {
			return false
		}
		active[topic] = true
		p.bases[topic] = base
		if p.configs[topic] != string(b) {
			if !p.send(ctx, c, topic, true, b) {
				return false
			}
			p.configs[topic] = string(b)
		}
		state := r.state
		if text, ok := state.(string); ok {
			if !p.send(ctx, c, base+"/state", true, []byte(text)) {
				return false
			}
		} else if !p.publish(ctx, c, base+"/state", true, state) {
			return false
		}
		if r.attributes != nil && !p.publish(ctx, c, base+"/attributes", true, r.attributes) {
			return false
		}
	}
	// Removing the opt-in tag removes its retained discovery config and
	// its retained state and attributes (they name findings).
	for topic := range p.configs {
		if !active[topic] {
			if !p.send(ctx, c, topic, true, nil) {
				return false
			}
			if base := p.bases[topic]; base != "" {
				if !p.send(ctx, c, base+"/state", true, nil) || !p.send(ctx, c, base+"/attributes", true, nil) {
					return false
				}
			}
			delete(p.configs, topic)
			delete(p.bases, topic)
		}
	}
	// Re-send the retained configs now and then, so a config that another
	// broker client overwrote is repaired.
	p.cycles++
	if p.cycles%republishEvery == 0 {
		for topic := range p.configs {
			p.configs[topic] = ""
		}
	}
	return true
}

// genericTitle is the event title without device or vulnerability names.
func genericTitle(eventType string) string {
	if t, ok := map[string]string{
		"device.new":           "New device",
		"device.claimed":       "Agent took over a device",
		"device.merge_refused": "Devices not merged",
		"finding.new":          "New vulnerability finding",
		"proposal.pending":     "Decision needs approval",
		"proposal.auto":        "Automatic action",
		"order.failed":         "Action failed",
		"order.done":           "Action done",
		"order.uncertain":      "Action result uncertain",
		"order.expired":        "Action expired",
		"order.revert-blocked": "Revert blocked",
		"update.available":     "Update available",
		"killswitch.changed":   "Kill switch changed",
	}[eventType]; ok {
		return t
	}
	return eventType
}

// BindProvider is called before Run starts, to attach the server inventory.
func (p *Publisher) BindProvider(provider Provider) { p.provider = provider }

func init() {
	notify.Registry.RegisterWithSchema("mqtt", func(name string, raw json.RawMessage) (notify.Notifier, error) {
		p, err := New(raw, func(context.Context) (Snapshot, error) { return Snapshot{}, nil })
		if err == nil {
			p.name = name
		}
		return p, err
	}, registry.Schema{Fields: []registry.Field{
		{Key: "broker", Label: "Broker", Type: "string", Required: true, Help: "mqtts://host:8883; mqtt:// only for loopback or with Allow plaintext."},
		{Key: "username", Label: "Username", Type: "string"},
		{Key: "password", Label: "Password", Type: "secret"},
		{Key: "allow_plain", Label: "Allow plaintext", Type: "bool", Default: false},
		{Key: "client_id", Label: "Client ID", Type: "string", Default: "netnoodle", Help: "Use a unique ID for each publisher."},
		{Key: "topic_prefix", Label: "Topic prefix", Type: "string", Default: "netnoodle"},
		{Key: "discovery_prefix", Label: "Discovery prefix", Type: "string", Default: "homeassistant"},
		{Key: "interval", Label: "Snapshot interval", Type: "duration", Default: "60s"},
		{Key: "device_tag", Label: "Device tag", Type: "string", Default: "ha"},
		{Key: "events", Label: "Event types", Type: "list", Default: defaultEvents},
		{Key: "event_details", Label: "Send event details", Type: "bool", Default: false},
		{Key: "fingerprint", Label: "Certificate fingerprint", Type: "fingerprint"},
	}})
}

// Test connects once and waits for acknowledgement of just this test event.
// It sends no discovery, inventory, availability or retained messages.
func (p *Publisher) Test(ctx context.Context, e notify.Event) error {
	opts := paho.NewClientOptions().AddBroker(p.broker).SetClientID(p.s.ClientID + "-test").
		SetUsername(p.s.Username).SetPassword(p.password).SetAutoReconnect(false).
		SetConnectRetry(false).SetConnectTimeout(5 * time.Second).SetWriteTimeout(5 * time.Second).SetDialer(&net.Dialer{Timeout: 5 * time.Second, Control: tlspin.SafeControl}).SetTLSConfig(p.tls)
	c := paho.NewClient(opts)
	defer c.Disconnect(0)
	if !waitToken(ctx, c.Connect()) {
		return errors.New("mqtt: test connection failed")
	}
	e.Fields = nil
	if !p.publish(ctx, c, p.s.TopicPrefix+"/event", false, e) {
		return errors.New("mqtt: test delivery failed")
	}
	return nil
}
