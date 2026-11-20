// Package pveactor isolates Proxmox guests and starts guest snapshots.
package pveactor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

const maxResponseBody = 4 << 20

var (
	netKey         = regexp.MustCompile(`^net[0-9]+$`)
	tokenID        = regexp.MustCompile(`^[^@!=\s]+@[^@!=\s]+![^@!=\s]+$`)
	upidPattern    = regexp.MustCompile(`^UPID:[A-Za-z0-9._-]+:[0-9A-F]{8}:[0-9A-F]{8}:[0-9A-F]{8}:[A-Za-z0-9_-]+:[0-9A-Za-z._@!-]*:[A-Za-z0-9._@!-]*:$`)
	passthroughKey = regexp.MustCompile(`^(hostpci|usb|dev)[0-9]+$`)
	snapshotID     = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// Settings configure the API token, TLS trust, source identity and protection.
// TokenSecretFile is read once at construction; mode 0600 is recommended.
type Settings struct {
	URL                    string `json:"url"`
	TokenID                string `json:"token_id"`
	TokenSecret            string `json:"token_secret"`
	TokenSecretFile        string `json:"token_secret_file"`
	Fingerprint            string `json:"fingerprint"`
	Insecure               bool   `json:"insecure_skip_verify"`
	Source                 string `json:"source"`
	NeverIsolate           []int  `json:"never_isolate"`
	AllowEmptyNeverIsolate bool   `json:"allow_empty_never_isolate"`
	MaxSnapshots           int    `json:"max_snapshots"`
}

// Backend implements isolate, unisolate and snapshot for proxmox.guest targets.
type Backend struct {
	name         string
	base         string
	source       string
	auth         string
	client       *http.Client
	neverIsolate map[int]bool
	maxSnapshots int
	journal      *actor.Journal
}

func init() { actor.Registry.Register("proxmox", New) }

// New strictly decodes settings and reads credentials without contacting PVE.
func New(name string, raw json.RawMessage) (actor.Backend, error) {
	s := Settings{MaxSnapshots: 3}
	if !json.Valid(raw) || registry.Decode(raw, &s) != nil {
		// Decoder errors can include secrets supplied as values or field names.
		return nil, errors.New("proxmox: invalid settings (malformed JSON or unknown fields)")
	}
	if (s.TokenSecret == "") == (s.TokenSecretFile == "") {
		return nil, errors.New("proxmox: exactly one of token_secret and token_secret_file is required")
	}
	if s.TokenSecretFile != "" {
		secret, err := os.ReadFile(s.TokenSecretFile)
		if err != nil {
			return nil, errors.New("proxmox: cannot read token_secret_file")
		}
		s.TokenSecret = strings.TrimSpace(string(secret))
	}
	if !headerValue(s.TokenSecret) {
		return nil, errors.New("proxmox: token_secret must be nonempty and contain no whitespace or control characters")
	}
	if !tokenID.MatchString(s.TokenID) || !headerValue(s.TokenID) {
		return nil, errors.New("proxmox: token_id must look like user@realm!name")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("proxmox: url must be an HTTPS PVE origin")
	}
	if !segment(s.Source) {
		return nil, errors.New("proxmox: source must be a single nonempty path segment")
	}
	if len(s.NeverIsolate) == 0 && !s.AllowEmptyNeverIsolate {
		return nil, errors.New("proxmox: never_isolate must protect management/router/VPN guests; explicitly set allow_empty_never_isolate to override")
	}
	if s.MaxSnapshots < 1 {
		return nil, errors.New("proxmox: max_snapshots must be positive")
	}
	protected := make(map[int]bool, len(s.NeverIsolate))
	for _, vmid := range s.NeverIsolate {
		if vmid < 100 || vmid > 999999999 {
			return nil, errors.New("proxmox: never_isolate VM IDs must be 100..999999999")
		}
		protected[vmid] = true
	}
	c, err := tlspin.Client(s.Fingerprint, s.Insecure, 30*time.Second)
	if err != nil {
		return nil, errors.New("proxmox: invalid TLS fingerprint")
	}
	if s.Insecure {
		slog.Warn("Proxmox actor insecure_skip_verify enabled; configure a TLS fingerprint or trusted certificate")
	}
	return &Backend{name: name, base: strings.TrimRight(s.URL, "/") + "/api2/json", source: s.Source,
		auth: "PVEAPIToken=" + s.TokenID + "=" + s.TokenSecret, client: c, neverIsolate: protected, maxSnapshots: s.MaxSnapshots, journal: &actor.Journal{}}, nil
}

func headerValue(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c == 127 {
			return false
		}
	}
	return true
}

func segment(s string) bool {
	return headerValue(s) && s != "." && s != ".." && !strings.ContainsAny(s, "/\\?#%")
}

func (b *Backend) SetJournal(j *actor.Journal) { b.journal = j }

func (b *Backend) Name() string { return b.name }

func (b *Backend) Capabilities() []proto.Capability {
	return []proto.Capability{
		{Action: "isolate", TargetIDKinds: []string{"proxmox.guest"}, TargetScope: []string{"proxmox.guest=" + b.source + "/*"}, Reversible: true, RevertAction: "unisolate"},
		{Action: "unisolate", TargetIDKinds: []string{"proxmox.guest"}, TargetScope: []string{"proxmox.guest=" + b.source + "/*"}},
		{Action: "snapshot", TargetIDKinds: []string{"proxmox.guest"}, TargetScope: []string{"proxmox.guest=" + b.source + "/*"}},
	}
}

// Execute checks the source and live cluster identity before resolving a guest.
func (b *Backend) Execute(ctx context.Context, o proto.Order) (message string, err error) {
	if len(o.Targets) != 1 || o.Targets[0].Kind != "proxmox.guest" {
		return "", errors.New("proxmox: exactly one target of kind proxmox.guest is required")
	}
	parts := strings.Split(o.Targets[0].Value, "/")
	if len(parts) != 3 || parts[0] != b.source || !segment(parts[1]) {
		return "", errors.New("proxmox: target must be <configured source>/<cluster>/<vmid>")
	}
	vmid, err := strconv.Atoi(parts[2])
	if err != nil || vmid < 100 || vmid > 999999999 || strconv.Itoa(vmid) != parts[2] {
		return "", errors.New("proxmox: target VM ID must be 100..999999999")
	}
	snapname := ""
	switch o.Action {
	case "isolate":
		if b.neverIsolate[vmid] {
			return "", errors.New("proxmox: target is protected by never_isolate")
		}
	case "unisolate": // Recovery is also allowed for protected guests.
	case "snapshot":
		prefix := o.ID
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		if !snapshotID.MatchString(prefix) {
			return "", errors.New("proxmox: order ID must start with snapshot name characters (letters, digits, '-' or '_')")
		}
		snapname = "nn-" + prefix
	default:
		return "", errors.New("proxmox: unsupported action")
	}
	base, err := b.guest(ctx, parts[1], vmid)
	if err != nil {
		return "", err
	}
	if o.Action == "snapshot" {
		var snapshots []struct {
			Name string `json:"name"`
		}
		if err := b.request(ctx, http.MethodGet, base+"/snapshot", nil, &snapshots); err != nil {
			return "", err
		}
		count := 0
		for _, snap := range snapshots {
			if strings.HasPrefix(snap.Name, "nn-") {
				count++
			}
		}
		if count >= b.maxSnapshots {
			return "", errors.New("proxmox: max_snapshots reached")
		}
		var upid string
		if err := b.request(ctx, http.MethodPost, base+"/snapshot", url.Values{
			"snapname": {snapname}, "description": {"netnoodle order " + o.ID},
		}, &upid); err != nil {
			return "", err
		}
		if !upidPattern.MatchString(upid) {
			return "task started", nil
		}
		return upid, nil
	}
	return b.network(ctx, base, o)
}

func (b *Backend) guest(ctx context.Context, cluster string, vmid int) (string, error) {
	var status []struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if err := b.request(ctx, http.MethodGet, "/cluster/status", nil, &status); err != nil {
		return "", err
	}
	// Match the source's fallback when no cluster name is reported.
	name := ""
	for _, item := range status {
		if item.Type == "cluster" {
			name = item.Name
		}
	}
	if name == "" {
		name = "standalone"
	}
	if name != cluster {
		return "", errors.New("proxmox: target cluster does not match API cluster name")
	}
	var resources []struct {
		VMID     int    `json:"vmid"`
		Node     string `json:"node"`
		Type     string `json:"type"`
		Template int    `json:"template"`
	}
	if err := b.request(ctx, http.MethodGet, "/cluster/resources?type=vm", nil, &resources); err != nil {
		return "", err
	}
	base := ""
	for _, r := range resources {
		if r.VMID != vmid {
			continue
		}
		if base != "" || !segment(r.Node) || (r.Type != "qemu" && r.Type != "lxc") {
			return "", errors.New("proxmox: invalid or ambiguous guest resource")
		}
		if r.Template != 0 {
			return "", errors.New("proxmox: refusing a template")
		}
		base = "/nodes/" + url.PathEscape(r.Node) + "/" + r.Type + "/" + strconv.Itoa(vmid)
	}
	if base == "" {
		return "", errors.New("proxmox: guest not found")
	}
	return base, nil
}

// linkDown changes only the link_down option, preserving all other bytes.
func linkDown(value string, isolated bool) (string, error) {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts)+1)
	found := false
	for _, part := range parts {
		key, v, _ := strings.Cut(part, "=")
		if key != "link_down" {
			result = append(result, part)
			continue
		}
		if found || (v != "0" && v != "1") {
			return "", errors.New("proxmox: invalid or duplicate link_down option")
		}
		found = true
		if isolated {
			result = append(result, "link_down=1")
		}
	}
	if isolated && !found {
		result = append(result, "link_down=1")
	}
	return strings.Join(result, ","), nil
}

// parseNIC compares options independently of PVE's output ordering. A bare
// leading model is represented by a private key; duplicate keys fail closed.
func parseNIC(value string) (map[string]string, error) {
	result := map[string]string{}
	for i, part := range strings.Split(value, ",") {
		key, v, ok := strings.Cut(part, "=")
		if !ok {
			if i != 0 || key == "" {
				return nil, errors.New("proxmox: invalid network config")
			}
			v = key
			key = "$model"
		}
		if _, exists := result[key]; exists || key == "" {
			return nil, errors.New("proxmox: duplicate network option")
		}
		result[key] = v
	}
	return result, nil
}
func sameNIC(a, b string) bool {
	x, e := parseNIC(a)
	if e != nil {
		return false
	}
	y, e := parseNIC(b)
	if e != nil {
		return false
	}
	// Missing link_down and explicit 0 both mean an enabled link.
	if x["link_down"] == "0" {
		delete(x, "link_down")
	}
	if y["link_down"] == "0" {
		delete(y, "link_down")
	}
	return maps.Equal(x, y)
}

func (b *Backend) network(ctx context.Context, base string, o proto.Order) (message string, err error) {
	sent := false
	defer func() {
		if err != nil && sent && !errors.Is(err, actor.ErrPossiblyApplied) {
			err = fmt.Errorf("%w: %w", actor.ErrPossiblyApplied, err)
		}
	}()
	isolated := o.Action == "isolate"
	var cfg map[string]json.RawMessage
	if err = b.request(ctx, http.MethodGet, base+"/config?current=1", nil, &cfg); err != nil {
		return "", err
	}
	if isolated {
		for key, raw := range cfg {
			qemu := strings.Contains(base, "/qemu/")
			var args string
			_ = json.Unmarshal(raw, &args)
			if (qemu && ((passthroughKey.MatchString(key) && !strings.HasPrefix(key, "dev")) || (key == "args" && strings.Contains(args, "netdev")))) || (!qemu && (strings.HasPrefix(key, "lxc.net.") || (passthroughKey.MatchString(key) && strings.HasPrefix(key, "dev")))) {
				return "", errors.New("cannot isolate fully: passthrough network device present")
			}
		}
	}
	var pending []struct {
		Key     string          `json:"key"`
		Pending json.RawMessage `json:"pending"`
		Delete  int             `json:"delete"`
	}
	if err = b.request(ctx, http.MethodGet, base+"/pending", nil, &pending); err != nil {
		return "", err
	}
	for _, p := range pending {
		if netKey.MatchString(p.Key) && ((len(p.Pending) > 0 && string(p.Pending) != "null") || p.Delete != 0) {
			return "", errors.New("proxmox: pending network change")
		}
	}
	var digest string
	if json.Unmarshal(cfg["digest"], &digest) != nil || digest == "" {
		return "", errors.New("proxmox: guest config missing digest")
	}
	prior, hasPrior := b.journal.Get(o.RevertOf, b.name, o.Targets[0].Value, "isolate")
	if o.Action != "isolate" && o.RevertOf != "" && !hasPrior {
		// The reverted order never changed anything; do not enable links
		// that were down before (security review 2026-11-20).
		return actor.NoJournal, nil
	}
	keys := []string{}
	changed := []string{}
	priorDown := []string{}
	want := map[string]string{}
	changes := url.Values{"digest": {digest}}
	for key, raw := range cfg {
		if !netKey.MatchString(key) {
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) != nil || value == "" {
			return "", errors.New("proxmox: invalid network interface config")
		}
		options, e := parseNIC(value)
		if e != nil {
			return "", e
		}
		if options["link_down"] == "1" {
			priorDown = append(priorDown, key)
		}
		next, e := linkDown(value, isolated)
		if e != nil {
			return "", e
		}
		if !isolated && hasPrior && !slices.Contains(prior.Changed, key) {
			next = value
		}
		keys = append(keys, key)
		want[key] = next
		if next != value {
			changes.Set(key, next)
			changed = append(changed, key)
		}
	}
	if len(keys) == 0 {
		return "", errors.New("proxmox: guest has no network interfaces")
	}
	slices.Sort(keys)
	if isolated {
		slices.Sort(changed)
		slices.Sort(priorDown)
		if err = b.journal.Put(o.ID, actor.JournalEntry{Backend: b.name, Target: o.Targets[0].Value, Action: o.Action, Expires: actor.OrderExpiry(o.TTL, o.NotAfter), Changed: changed, PriorDown: priorDown}); err != nil {
			return "", err
		}
	}
	if len(changes) > 1 {
		sent = true
		if err = b.request(ctx, http.MethodPut, base+"/config", changes, nil); err != nil {
			return "", err
		}
	}
	var verified map[string]json.RawMessage
	if err = b.request(ctx, http.MethodGet, base+"/config?current=1", nil, &verified); err != nil {
		return "", fmt.Errorf("proxmox: verification failed: %w", err)
	}
	for key, value := range want {
		var got string
		if json.Unmarshal(verified[key], &got) != nil || !sameNIC(got, value) {
			return "", fmt.Errorf("proxmox: verification failed for %s", key)
		}
	}
	for key := range verified {
		if netKey.MatchString(key) {
			if _, ok := want[key]; !ok {
				return "", errors.New("proxmox: verification failed: network interface added during update")
			}
		}
	}
	state := "isolated"
	if !isolated {
		state = "unisolated"
	}
	message = state + " " + strings.Join(keys, ", ") + "; verified"
	if !isolated && !hasPrior {
		message += "; no journal entry; all links enabled"
	}
	return message, nil
}

func (b *Backend) request(ctx context.Context, method, endpoint string, form url.Values, out any) (err error) {
	sent := false
	defer func() {
		if err != nil && sent && method != http.MethodGet {
			err = fmt.Errorf("%w: %w", actor.ErrPossiblyApplied, err)
		}
	}()
	var payload io.Reader
	if form != nil {
		payload = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base+endpoint, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", b.auth)
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	sent = true
	res, err := b.client.Do(req)
	if err != nil {
		return errors.New("proxmox: API transport failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBody+1))
	if err != nil {
		return errors.New("proxmox: API response read failed")
	}
	if len(body) > maxResponseBody {
		return errors.New("proxmox: response exceeds 4 MiB")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("proxmox: API HTTP %d", res.StatusCode)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &env) != nil || len(env.Data) == 0 {
		return errors.New("proxmox: invalid API response JSON")
	}
	if out == nil {
		return nil // PVE config PUT returns data:null.
	}
	if string(env.Data) == "null" || json.Unmarshal(env.Data, out) != nil {
		return errors.New("proxmox: invalid or missing API data")
	}
	return nil
}
