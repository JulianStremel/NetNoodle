package server

import (
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

// The graph API gives the whole inventory in one document for the
// visualizations of the web UI: devices with risk, networks, relations.

// GraphService is one service of a device.
type GraphService struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Address string `json:"address,omitempty"`
	Process string `json:"process,omitempty"`
	Product string `json:"product,omitempty"`
	Reach   string `json:"reach"`
	Exposed bool   `json:"exposed"` // listens on a non-loopback address
	Vulns   int    `json:"vulns"`   // open findings in the owning package
	KEV     bool   `json:"kev"`     // one of them is known exploited
	Package string `json:"package,omitempty"`
}

// GraphVuln is one of the most urgent findings of a device.
type GraphVuln struct {
	ID      string  `json:"id"`
	Score   float64 `json:"score"`
	KEV     bool    `json:"kev"`
	EPSS    float64 `json:"epss"`
	Package string  `json:"package"`
	Version string  `json:"version"`
	Fixed   string  `json:"fixed,omitempty"`
	Exposed bool    `json:"exposed"`
	Summary string  `json:"summary,omitempty"`
}

// GraphNode is one device.
type GraphNode struct {
	Reach         string   `json:"reach"`
	ReachEvidence []string `json:"reach_evidence"`
	routed        bool
	Tags          []string       `json:"tags"`
	ID            int64          `json:"id"`
	Name          string         `json:"name"`
	Kind          string         `json:"kind"`
	Parent        int64          `json:"parent,omitempty"`
	Children      []int64        `json:"children"`
	IPs           []string       `json:"ips"`
	MACs          []string       `json:"macs"`
	Networks      []string       `json:"networks"`
	Sources       []string       `json:"sources"`
	Agent         bool           `json:"agent"` // reported by an agent (has package data)
	Components    int            `json:"components"`
	Services      []GraphService `json:"services"`
	Findings      int            `json:"findings"`
	KEV           int            `json:"kev"`
	MaxScore      float64        `json:"max_score"`
	MaxEPSS       float64        `json:"max_epss"`
	Exposed       int            `json:"exposed"` // open findings in packages with an exposed service
	// Risk is 0-10: the worst open finding (see findingWeight).
	Risk float64 `json:"risk"`
	// RelatedRisk is the highest risk of the host, its guests and the
	// other guests of the same host (they share the hypervisor).
	RelatedRisk float64     `json:"related_risk"`
	Related     []int64     `json:"related"`
	Top         []GraphVuln `json:"top"`
	LastSeen    time.Time   `json:"last_seen"`
}

// maxRelated limits the guests and the siblings listed per device (the
// riskiest first). RelatedRisk always covers all of them.
const maxRelated = 50

// GraphNetwork is an address range with its devices.
type GraphNetwork struct {
	ID      string  `json:"id"` // CIDR
	Devices []int64 `json:"devices"`
	Risk    float64 `json:"risk"` // highest device risk
}

// Graph is the response of GET /api/graph.
type Graph struct {
	Generated time.Time      `json:"generated"`
	Nodes     []GraphNode    `json:"nodes"`
	Networks  []GraphNetwork `json:"networks"`
	Stats     map[string]int `json:"stats"`
}

func isExposed(addr string) bool {
	return listenerReach(addr, deviceReach{level: reachLocal}) != ""
}

// networkOf returns the /24 (IPv4) or /64 (IPv6) of an address, or "".
// Loopback and link-local addresses have none.
func networkOf(s string) string {
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return ""
	}
	bits := 64
	if ip.Is4() || ip.Is4In6() {
		ip, bits = ip.Unmap(), 24
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// findingWeight rates one finding 0-10: 70 % of the CVSS score, plus 2
// if attackers use it (KEV), plus local/tunnel/internet exposure (1/1.5/2),
// plus the EPSS probability (0-1).
func findingWeight(score float64, kev bool, reach string, epss float64) float64 {
	w := score*0.7 + epss
	if kev {
		w += 2
	}
	switch reach {
	case reachLocal:
		w++
	case reachTunnel:
		w += 1.5
	case reachInternet:
		w += 2
	}
	return min(w, 10)
}

func buildGraph(devs []store.DeviceRow, fs []store.FindingRow, svcs []store.DeviceService, now time.Time) Graph {
	g := Graph{Generated: now, Nodes: make([]GraphNode, 0, len(devs)), Networks: []GraphNetwork{}, Stats: map[string]int{"reach.local": 0, "reach.tunnel": 0, "reach.internet": 0}}
	idx := map[int64]int{}
	routes := routedNetworks(devs)
	reaches := map[int64]deviceReach{}
	for _, d := range devs {
		r := classifyDevice(d, routes)
		reaches[d.ID] = r
		n := GraphNode{
			Reach: r.level, ReachEvidence: r.evidence, routed: r.routed,
			Tags: append([]string{}, d.Tags...), ID: d.ID, Name: d.Name, Kind: d.Kind, Parent: d.ParentID, Children: []int64{},
			IPs: []string{}, MACs: []string{}, Networks: []string{}, Sources: d.Sources,
			Components: d.Components, Services: []GraphService{}, Findings: d.Findings, KEV: d.KEV,
			MaxScore: d.MaxScore, Related: []int64{}, Top: []GraphVuln{}, LastSeen: d.LastSeen,
		}
		n.IPs = append(n.IPs, deviceIPs(d)...)
		nets := map[string]bool{}
		for _, ip := range n.IPs {
			if k := networkOf(ip); k != "" && !nets[k] {
				nets[k] = true
				n.Networks = append(n.Networks, k)
			}
		}
		for _, id := range d.Identifiers {
			switch id.Kind {
			case "mac":
				n.MACs = append(n.MACs, id.Value)
			case "agent":
				n.Agent = true
			}
		}
		idx[d.ID] = len(g.Nodes)
		g.Nodes = append(g.Nodes, n)
	}
	// Findings per device and package.
	type pkgKey struct {
		dev  int64
		purl string
	}
	pkgVulns := map[pkgKey]int{}
	pkgKEV := map[pkgKey]bool{}
	pkgReach := map[pkgKey]string{}
	for _, svc := range svcs {
		k := pkgKey{svc.DeviceID, svc.Component}
		if r := listenerReach(svc.Address, reaches[svc.DeviceID]); r != "" {
			pkgReach[k] = maxReach(pkgReach[k], r)
		}
	}
	for _, f := range fs {
		i, ok := idx[f.DeviceID]
		if !ok {
			continue
		}
		n := &g.Nodes[i]
		k := pkgKey{f.DeviceID, f.PURL}
		exposed := pkgReach[k] != ""
		if exposed {
			n.Exposed++
		}
		n.MaxEPSS = max(n.MaxEPSS, f.EPSS)
		n.Risk = max(n.Risk, findingWeight(f.Score, f.KEV, pkgReach[k], f.EPSS))
		pkgVulns[k]++
		pkgKEV[k] = pkgKEV[k] || f.KEV
		n.Top = append(n.Top, GraphVuln{ID: f.VulnID, Score: f.Score, KEV: f.KEV, EPSS: f.EPSS, Package: f.Package,
			Version: f.Version, Fixed: f.Fixed, Exposed: exposed, Summary: trimText(f.Summary, 160)})
	}
	for _, s := range svcs {
		i, ok := idx[s.DeviceID]
		if !ok {
			continue
		}
		k := pkgKey{s.DeviceID, s.Component}
		pkg := ""
		if s.Component != "" {
			pkg = s.Component
		}
		g.Nodes[i].Services = append(g.Nodes[i].Services, GraphService{
			Port: s.Port, Proto: s.Proto, Address: s.Address, Process: s.Process, Product: s.Product,
			Reach: listenerReach(s.Address, reaches[s.DeviceID]), Exposed: isExposed(s.Address), Vulns: pkgVulns[k], KEV: pkgKEV[k], Package: pkg,
		})
	}
	// Tree relations.
	for i := range g.Nodes {
		if p, ok := idx[g.Nodes[i].Parent]; ok && g.Nodes[i].Parent != 0 {
			g.Nodes[p].Children = append(g.Nodes[p].Children, g.Nodes[i].ID)
		} else {
			g.Nodes[i].Parent = 0
		}
	}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		sort.Slice(n.Top, func(a, b int) bool {
			x, y := n.Top[a], n.Top[b]
			if x.KEV != y.KEV {
				return x.KEV
			}
			if x.Exposed != y.Exposed {
				return x.Exposed
			}
			return x.Score > y.Score
		})
		if len(n.Top) > 5 {
			n.Top = n.Top[:5]
		}
	}
	// Related: parent, children and the riskiest siblings. Children are
	// sorted by risk once per host, so this stays linear in the number of
	// devices (a host can have thousands of guests).
	byRisk := func(ids []int64) []int64 {
		out := append([]int64(nil), ids...)
		sort.Slice(out, func(a, b int) bool {
			ra, rb := g.Nodes[idx[out[a]]].Risk, g.Nodes[idx[out[b]]].Risk
			if ra != rb {
				return ra > rb
			}
			return out[a] < out[b]
		})
		return out
	}
	sortedKids := map[int64][]int64{}
	for i := range g.Nodes {
		if len(g.Nodes[i].Children) > 0 {
			sortedKids[g.Nodes[i].ID] = byRisk(g.Nodes[i].Children)
		}
	}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		rel := map[int64]bool{}
		kids := sortedKids[n.ID]
		for j, c := range kids {
			if j == maxRelated {
				break
			}
			rel[c] = true
		}
		if len(kids) > 0 {
			n.RelatedRisk = g.Nodes[idx[kids[0]]].Risk
		}
		if n.Parent != 0 {
			rel[n.Parent] = true
			p := g.Nodes[idx[n.Parent]]
			n.RelatedRisk = max(n.RelatedRisk, p.Risk)
			sib := 0
			for _, s := range sortedKids[n.Parent] {
				if s == n.ID {
					continue
				}
				if sib == 0 {
					n.RelatedRisk = max(n.RelatedRisk, g.Nodes[idx[s]].Risk)
				}
				if sib == maxRelated {
					break
				}
				rel[s] = true
				sib++
			}
		}
		for id := range rel {
			n.Related = append(n.Related, id)
		}
		sort.Slice(n.Related, func(a, b int) bool { return n.Related[a] < n.Related[b] })
	}
	// Networks.
	byNet := map[string]*GraphNetwork{}
	for _, n := range g.Nodes {
		for _, k := range n.Networks {
			nw := byNet[k]
			if nw == nil {
				nw = &GraphNetwork{ID: k, Devices: []int64{}}
				byNet[k] = nw
			}
			nw.Devices = append(nw.Devices, n.ID)
			nw.Risk = max(nw.Risk, n.Risk)
		}
	}
	for _, nw := range byNet {
		g.Networks = append(g.Networks, *nw)
	}
	sort.Slice(g.Networks, func(a, b int) bool { return g.Networks[a].ID < g.Networks[b].ID })
	// Stats.
	for _, n := range g.Nodes {
		g.Stats["devices"]++
		g.Stats["reach."+n.Reach]++
		g.Stats["kind."+n.Kind]++
		if n.Findings > 0 {
			g.Stats["vulnerable"]++
		}
		if n.KEV > 0 {
			g.Stats["kev_devices"]++
		}
		if n.Exposed > 0 {
			g.Stats["exposed_devices"]++
		}
		g.Stats["findings"] += n.Findings
	}
	g.Stats["networks"] = len(g.Networks)
	return g
}

func trimText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devs, err := s.st.ListDevices(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	fs, err := s.st.ListFindings(ctx, store.FindingFilter{State: "open", Limit: 20000})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	svcs, err := s.st.ListAllServices(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, buildGraph(devs, fs, svcs, s.now()))
}

// RelatedDevice is a device that shares a hypervisor with another one.
type RelatedDevice struct {
	ID       int64   `json:"id"`
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	Relation string  `json:"relation"` // host | guest | sibling
	Risk     float64 `json:"risk"`
	Findings int     `json:"findings"`
	KEV      int     `json:"kev"`
	Agent    bool    `json:"agent"`
}

// handleRelated is GET /api/devices/{id}/related: the host, the guests and
// the other guests of the host. A problem on one of them can affect the
// others (shared hypervisor, D-050).
func (s *Server) handleRelated(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ctx := r.Context()
	devs, err := s.st.ListDevices(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	fs, err := s.st.ListFindings(ctx, store.FindingFilter{State: "open", Limit: 20000})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	svcs, err := s.st.ListAllServices(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	g := buildGraph(devs, fs, svcs, s.now())
	byID := map[int64]*GraphNode{}
	for i := range g.Nodes {
		byID[g.Nodes[i].ID] = &g.Nodes[i]
	}
	n, ok := byID[id]
	if !ok {
		writeErr(w, http.StatusNotFound, "no such device")
		return
	}
	out := []RelatedDevice{}
	for _, rid := range n.Related {
		o := byID[rid]
		rel := "sibling"
		switch {
		case rid == n.Parent:
			rel = "host"
		case o.Parent == n.ID:
			rel = "guest"
		}
		out = append(out, RelatedDevice{ID: o.ID, Name: o.Name, Kind: o.Kind, Relation: rel, Risk: o.Risk, Findings: o.Findings, KEV: o.KEV, Agent: o.Agent})
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Relation != out[b].Relation {
			return out[a].Relation < out[b].Relation
		}
		return out[a].Risk > out[b].Risk
	})
	writeJSON(w, http.StatusOK, map[string]any{"risk": n.Risk, "related_risk": n.RelatedRisk, "related": out})
}
