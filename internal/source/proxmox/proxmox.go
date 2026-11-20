// Package proxmox is an in-process source for Proxmox VE clusters. It reads
// cluster nodes, virtual machines and containers with a read-only API token
// (role PVEAuditor) and reports each node with its guests as children.
//
// Identity: a node is "proxmox.node=<source>/<cluster>/<node>", a guest is
// "proxmox.guest=<source>/<cluster>/<vmid>" (VM IDs are unique in a
// cluster, and a migrated guest keeps its identity). The configured source
// name is part of the value, so two clusters with the same name (for
// example the default) cannot collide. Guest MAC addresses come from the
// guest config; Proxmox MACs (BC:24:11:...) are globally unique, so guests
// merge with the same machine seen by an agent, a scan or UniFi.
package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/source"
	"github.com/JulianStremel/netnoodle/internal/tlspin"
)

func init() { source.Registry.Register("proxmox", New) }

// Settings configure the source.
type Settings struct {
	URL             string `json:"url"`               // https://pve1:8006
	TokenID         string `json:"token_id"`          // user@realm!name
	TokenSecret     string `json:"token_secret"`      // UUID
	TokenSecretFile string `json:"token_secret_file"` // alternative to token_secret
	FP              string `json:"fingerprint,omitempty"`
	Insecure        bool   `json:"insecure_skip_verify,omitempty"`
	// GuestAgent asks the QEMU guest agent for IP addresses and the OS
	// (needs the privilege VM.GuestAgent.Audit or VM.Monitor). Default true.
	GuestAgent *bool `json:"guest_agent,omitempty"`
	// IncludeTemplates also reports VM templates. Default false.
	IncludeTemplates bool `json:"include_templates,omitempty"`
}

// Source is the Proxmox source.
type Source struct {
	name  string
	s     Settings
	base  string
	auth  string
	c     *http.Client
	agent bool
}

// New builds the source from settings.
func New(name string, raw json.RawMessage) (source.Source, error) {
	var s Settings
	if err := registry.Decode(raw, &s); err != nil {
		return nil, err
	}
	if s.TokenSecret == "" && s.TokenSecretFile != "" {
		b, err := os.ReadFile(s.TokenSecretFile)
		if err != nil {
			return nil, err
		}
		s.TokenSecret = strings.TrimSpace(string(b))
	}
	if s.URL == "" || s.TokenID == "" || s.TokenSecret == "" {
		return nil, errors.New("url, token_id and token_secret (or token_secret_file) are required")
	}
	if !strings.Contains(s.TokenID, "!") || !strings.Contains(s.TokenID, "@") {
		return nil, fmt.Errorf("token_id %q must look like user@realm!name", s.TokenID)
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("url %q must be https://host:8006", s.URL)
	}
	c, err := tlspin.Client(s.FP, s.Insecure, 30*time.Second)
	if err != nil {
		return nil, err
	}
	agent := s.GuestAgent == nil || *s.GuestAgent
	return &Source{
		name:  name,
		s:     s,
		base:  strings.TrimRight(s.URL, "/") + "/api2/json",
		auth:  "PVEAPIToken=" + s.TokenID + "=" + s.TokenSecret,
		c:     c,
		agent: agent,
	}, nil
}

// Name returns the instance name.
func (p *Source) Name() string { return p.name }

// Limits against a broken or hostile API: the source keeps only short,
// bounded data per guest until the poll ends.
const (
	maxGuests     = 10000
	maxNodes      = 1000
	maxIfaces     = 32
	maxIPsPerNIC  = 64
	maxFieldBytes = 256
)

// short cuts a string from the API to maxFieldBytes.
func short(s string) string {
	if len(s) > maxFieldBytes {
		return strings.ToValidUTF8(s[:maxFieldBytes], "")
	}
	return s
}

// errStatus is an HTTP error from the API.
type errStatus struct {
	code int
	path string
}

func (e errStatus) Error() string { return fmt.Sprintf("proxmox %s: HTTP %d", e.path, e.code) }

func (p *Source) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", p.auth)
	req.Header.Set("Accept", "application/json")
	res, err := p.c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errStatus{res.StatusCode, path}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(&env); err != nil {
		return fmt.Errorf("proxmox %s: %w", path, err)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return fmt.Errorf("proxmox %s: no data", path)
	}
	return json.Unmarshal(env.Data, out)
}

type clusterItem struct {
	Type   string `json:"type"` // cluster | node
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Online int    `json:"online"`
}

type resource struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"` // qemu | lxc
	Node     string  `json:"node"`
	VMID     int     `json:"vmid"`
	Name     string  `json:"name"`
	Status   string  `json:"status"`
	Template int     `json:"template"`
	Tags     string  `json:"tags"`
	MaxMem   float64 `json:"maxmem"`
	MaxCPU   float64 `json:"maxcpu"`
}

type guestIface struct {
	Name string
	MAC  string
	IPs  []string
}

// parseNet reads a net<N> config value. QEMU: "virtio=BC:24:11:..,bridge=vmbr0".
// LXC: "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:..,ip=10.0.0.5/24".
func parseNet(key, val string) guestIface {
	gi := guestIface{Name: key}
	for _, part := range strings.Split(val, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch k {
		case "virtio", "e1000", "e1000e", "rtl8139", "vmxnet3", "hwaddr":
			gi.MAC = strings.ToLower(v)
		case "name":
			gi.Name = v
		case "ip", "ip6":
			if v != "dhcp" && v != "manual" && v != "auto" {
				ip, _, _ := strings.Cut(v, "/")
				gi.IPs = append(gi.IPs, ip)
			}
		}
	}
	return gi
}

// netKeys returns the interface entries of a guest config, sorted.
func netKeys(cfg map[string]any) []string {
	var keys []string
	for k := range cfg {
		if strings.HasPrefix(k, "net") {
			if _, err := strconv.Atoi(k[3:]); err == nil {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// Poll reads the cluster and emits one observation per node.
func (p *Source) Poll(ctx context.Context, emit func(proto.Observation) error) error {
	var status []clusterItem
	if err := p.get(ctx, "/cluster/status", &status); err != nil {
		return err
	}
	cluster := ""
	var nodes []clusterItem
	for _, it := range status {
		switch it.Type {
		case "cluster":
			cluster = it.Name
		case "node":
			nodes = append(nodes, it)
		}
	}
	if cluster == "" {
		cluster = "standalone"
	}
	cluster = p.name + "/" + short(cluster)
	if len(nodes) > maxNodes {
		return fmt.Errorf("proxmox: %d nodes, more than %d", len(nodes), maxNodes)
	}
	var res []resource
	if err := p.get(ctx, "/cluster/resources?type=vm", &res); err != nil {
		return err
	}
	if len(res) > maxGuests {
		return fmt.Errorf("proxmox: %d guests, more than %d", len(res), maxGuests)
	}

	guests := map[string][]proto.Entity{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, r := range res {
		if (r.Type != "qemu" && r.Type != "lxc") || (r.Template == 1 && !p.s.IncludeTemplates) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(r resource) {
			defer func() { <-sem; wg.Done() }()
			e := p.guest(ctx, cluster, r)
			mu.Lock()
			guests[r.Node] = append(guests[r.Node], e)
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	for _, n := range nodes {
		n.Name = short(n.Name)
		e := proto.Entity{
			Kind: proto.KindHost,
			Name: n.Name,
			Identifiers: []proto.Identifier{
				{Kind: "proxmox.node", Value: cluster + "/" + n.Name, Strength: proto.Strong},
				{Kind: "hostname", Value: n.Name, Strength: proto.Weak},
			},
			Attributes: map[string]string{
				"proxmox.cluster": cluster,
				"proxmox.online":  strconv.Itoa(n.Online),
			},
		}
		if n.IP != "" {
			e.Identifiers = append(e.Identifiers, proto.Identifier{Kind: "ip", Value: n.IP, Strength: proto.Weak})
		}
		if n.Online == 1 {
			var ver struct {
				Version string `json:"version"`
				Release string `json:"release"`
			}
			if err := p.get(ctx, "/nodes/"+url.PathEscape(n.Name)+"/version", &ver); err == nil && ver.Version != "" {
				ver.Version = short(ver.Version)
				e.Attributes["pve.version"] = ver.Version
				e.Components = append(e.Components, proto.Component{
					PURL: "pkg:generic/proxmox/pve-manager@" + url.PathEscape(ver.Version), Name: "pve-manager", Version: ver.Version, Confidence: proto.High,
				})
			}
		}
		gs := guests[n.Name]
		sort.Slice(gs, func(i, j int) bool { return gs[i].Identifiers[0].Value < gs[j].Identifiers[0].Value })
		e.Children = gs
		obs := proto.Observation{Version: proto.Version, Source: p.name, ObservedAt: time.Now().UTC(), Entities: []proto.Entity{e}}
		if err := emit(obs); err != nil {
			return err
		}
	}
	return nil
}

func (p *Source) guest(ctx context.Context, cluster string, r resource) proto.Entity {
	kind := proto.KindVM
	if r.Type == "lxc" {
		kind = proto.KindContainer
	}
	vmid := strconv.Itoa(r.VMID)
	r.Name, r.Tags, r.Status, r.Node = short(r.Name), short(r.Tags), short(r.Status), short(r.Node)
	e := proto.Entity{
		Kind: kind,
		Name: r.Name,
		Identifiers: []proto.Identifier{
			{Kind: "proxmox.guest", Value: cluster + "/" + vmid, Strength: proto.Strong},
		},
		Attributes: map[string]string{
			"proxmox.vmid":   vmid,
			"proxmox.type":   r.Type,
			"proxmox.node":   r.Node,
			"proxmox.status": r.Status,
		},
	}
	if r.Name != "" {
		e.Identifiers = append(e.Identifiers, proto.Identifier{Kind: "hostname", Value: r.Name, Strength: proto.Weak})
	}
	if r.Tags != "" {
		e.Attributes["proxmox.tags"] = r.Tags
	}
	if r.Template == 1 {
		e.Attributes["proxmox.template"] = "1"
	}
	base := "/nodes/" + url.PathEscape(r.Node) + "/" + r.Type + "/" + vmid
	var cfg map[string]any
	if err := p.get(ctx, base+"/config", &cfg); err != nil {
		e.Attributes["proxmox.error"] = err.Error()
		return e
	}
	if v, ok := cfg["ostype"].(string); ok {
		e.Attributes["proxmox.ostype"] = short(v)
	}
	byMAC := map[string]*proto.Interface{}
	keys := netKeys(cfg)
	if len(keys) > maxIfaces {
		keys = keys[:maxIfaces]
	}
	for _, k := range keys {
		v, _ := cfg[k].(string)
		gi := parseNet(k, short(v))
		e.Interfaces = append(e.Interfaces, proto.Interface{Name: gi.Name, MAC: gi.MAC, IPs: gi.IPs})
	}
	for i := range e.Interfaces {
		if e.Interfaces[i].MAC != "" {
			byMAC[e.Interfaces[i].MAC] = &e.Interfaces[i]
		}
	}
	// Live IP addresses: LXC from the host, QEMU from the guest agent.
	if r.Status == "running" {
		switch r.Type {
		case "lxc":
			var ifs []struct {
				Name   string `json:"name"`
				HWAddr string `json:"hwaddr"`
				Inet   string `json:"inet"`
				Inet6  string `json:"inet6"`
			}
			if err := p.get(ctx, base+"/interfaces", &ifs); err == nil {
				for _, f := range ifs {
					if in := byMAC[strings.ToLower(f.HWAddr)]; in != nil {
						for _, a := range []string{f.Inet, f.Inet6} {
							if ip, _, _ := strings.Cut(a, "/"); ip != "" {
								in.IPs = appendNew(in.IPs, ip)
							}
						}
					}
				}
			}
		case "qemu":
			if p.agent {
				p.guestAgent(ctx, base, byMAC, &e)
			}
		}
	}
	return e
}

func (p *Source) guestAgent(ctx context.Context, base string, byMAC map[string]*proto.Interface, e *proto.Entity) {
	var nets struct {
		Result []struct {
			Name   string `json:"name"`
			HWAddr string `json:"hardware-address"`
			IPs    []struct {
				Addr string `json:"ip-address"`
			} `json:"ip-addresses"`
		} `json:"result"`
	}
	if err := p.get(ctx, base+"/agent/network-get-interfaces", &nets); err != nil {
		return // no guest agent, or no permission
	}
	for _, n := range nets.Result {
		in := byMAC[strings.ToLower(n.HWAddr)]
		if in == nil {
			continue
		}
		for _, a := range n.IPs {
			in.IPs = appendNew(in.IPs, a.Addr)
		}
	}
	var osinfo struct {
		Result struct {
			PrettyName string `json:"pretty-name"`
			ID         string `json:"id"`
			VersionID  string `json:"version-id"`
		} `json:"result"`
	}
	if err := p.get(ctx, base+"/agent/get-osinfo", &osinfo); err == nil {
		if osinfo.Result.PrettyName != "" {
			e.Attributes["os.name"] = short(osinfo.Result.PrettyName)
		}
		if osinfo.Result.ID != "" {
			e.Attributes["os.id"] = short(osinfo.Result.ID)
		}
		if osinfo.Result.VersionID != "" {
			e.Attributes["os.version_id"] = short(osinfo.Result.VersionID)
		}
	}
}

func appendNew(list []string, v string) []string {
	if len(list) >= maxIPsPerNIC || len(v) > 64 {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
