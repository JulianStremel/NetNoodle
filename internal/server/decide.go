package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/store"
)

type decideState struct {
	mu           sync.Mutex
	run          sync.Mutex
	contextMu    sync.Mutex
	nodes        map[int64]GraphNode
	nodesAt      time.Time
	deciders     []decide.Decider
	guards       []decide.Guard
	reevaluating bool
}

func newDecideState() *decideState { return &decideState{} }

// SetDecide installs configured plug-ins before the server starts.
func (s *Server) SetDecide(ds []decide.Decider, gs []decide.Guard) {
	s.decide.mu.Lock()
	defer s.decide.mu.Unlock()
	for _, g := range gs {
		if v, ok := g.(interface{ SetSettings(decide.Settings) }); ok {
			v.SetSettings(s.st)
		}
	}
	s.decide.deciders = ds
	s.decide.guards = gs
}

const maxEvaluationsPerDevice = 2000

// decisionContext reuses the graph's network and related-risk calculation.
func (s *Server) decisionContext(ctx context.Context) (map[int64]GraphNode, error) {
	s.decide.contextMu.Lock()
	defer s.decide.contextMu.Unlock()
	if s.decide.nodes != nil && s.now().Sub(s.decide.nodesAt) < 30*time.Second {
		return s.decide.nodes, nil
	}
	devs, e := s.st.ListDevices(ctx)
	if e != nil {
		return nil, e
	}
	fs, e := s.st.ListFindings(ctx, store.FindingFilter{State: "open", Limit: 20000})
	if e != nil {
		return nil, e
	}
	g := buildGraph(devs, fs, nil, s.now())
	out := map[int64]GraphNode{}
	for _, n := range g.Nodes {
		out[n.ID] = n
	}
	s.decide.nodes, s.decide.nodesAt = out, s.now()
	return out, nil
}

func (s *Server) invalidateDecisionContext() {
	s.decide.contextMu.Lock()
	s.decide.nodes = nil
	s.decide.contextMu.Unlock()
}
func (s *Server) evaluateFindings(ctx context.Context, fs []store.FindingRow, nodes map[int64]GraphNode, batch *proposalBatch) error {
	s.decide.mu.Lock()
	ds, gs := s.decide.deciders, s.decide.guards
	s.decide.mu.Unlock()
	if len(ds) == 0 {
		return nil
	}
	counts := map[int64]int{}
	details := map[int64]store.DeviceDetail{}
	for _, f := range fs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if counts[f.DeviceID] >= maxEvaluationsPerDevice {
			continue
		}
		counts[f.DeviceID]++
		d, ok := details[f.DeviceID]
		if !ok {
			var e error
			d, e = s.st.GetDevice(ctx, f.DeviceID)
			if e != nil {
				return e
			}
			details[f.DeviceID] = d
		}
		n := nodes[f.DeviceID]
		device := decide.Device{ID: d.ID, Name: d.Name, Kind: d.Kind, Tags: d.Tags, ParentID: d.ParentID, IPs: n.IPs}
		seenPorts := map[int]bool{}
		for _, svc := range d.Services {
			if svc.Component == f.PURL && isExposed(svc.Address) {
				device.Exposed = true
				if !seenPorts[svc.Port] {
					device.Ports = append(device.Ports, svc.Port)
					seenPorts[svc.Port] = true
				}
			}
		}
		if e := s.evaluateSituation(ctx, ds, gs, f, decide.Situation{Device: device, Component: f.PURL, Confidence: f.Confidence, Networks: n.Networks, RelatedRisk: n.RelatedRisk, Vuln: intel.Vuln{ID: f.VulnID, Aliases: f.Aliases, Summary: f.Summary, Score: f.Score, Vector: f.Vector, KEV: f.KEV, EPSS: f.EPSS, EPSSPct: f.EPSSPct, Facts: f.Facts}}, batch); e != nil {
			return e
		}
	}
	return nil
}

// Serialize only evaluation and persistence, one finding at a time. Matchers,
// graph construction and the rest of a re-evaluation run never hold this lock.
func (s *Server) evaluateSituation(ctx context.Context, ds []decide.Decider, gs []decide.Guard, f store.FindingRow, situation decide.Situation, batch *proposalBatch) error {
	s.decide.run.Lock()
	defer s.decide.run.Unlock()
	p, ok, e := decide.Evaluate(ctx, ds, gs, situation)
	if e != nil {
		s.log.Warn("evaluate proposal", "device", f.DeviceID, "vuln", f.VulnID, "err", e)
	}
	if !ok || p.Tier == decide.TierNone {
		return nil
	}
	// This invariant is independent of the configurable guards and runs last.
	if p.Tier == decide.TierAuto {
		v, err := s.st.GetSetting(ctx, "decide.killswitch")
		if err != nil {
			return err
		}
		if v == "on" {
			p.Tier = decide.TierApprove
			p.Reason = "kill switch"
		}
	}
	state := p.Tier.String()
	if p.Tier == decide.TierApprove {
		state = "pending"
	}
	saved, fresh, e := s.st.UpsertProposal(ctx, store.Proposal{DeviceID: f.DeviceID, VulnID: f.VulnID, PURL: f.PURL, Action: p.Action, Tier: p.Tier.String(), State: state, Reason: p.Reason, DecidedBy: p.DecidedBy, Params: p.Params, TTL: p.TTL, CreatedAt: s.now()})
	if e != nil {
		return e
	}
	if fresh && (saved.State == "pending" || saved.State == "notify") {
		batch.add(saved)
	}
	if saved.State == "auto" {
		s.kickPlanner()
	}
	return nil
}

// proposalBatch keeps at most 20 details per state, even across a full run.
type proposalBatch struct {
	counts  map[string]int
	samples map[string][]store.Proposal
}

func newProposalBatch() *proposalBatch {
	return &proposalBatch{counts: map[string]int{}, samples: map[string][]store.Proposal{}}
}
func (b *proposalBatch) add(p store.Proposal) {
	b.counts[p.State]++
	if len(b.samples[p.State]) < 20 {
		b.samples[p.State] = append(b.samples[p.State], p)
	}
}
func (s *Server) emitProposalBatch(ctx context.Context, b *proposalBatch) {
	for _, state := range []string{"pending", "notify"} {
		count := b.counts[state]
		if count == 0 {
			continue
		}
		severity := "info"
		if state == "pending" {
			severity = "warning"
		}
		emit := func(title, detail string) {
			s.emit(ctx, notify.Event{Type: "proposal." + state, Severity: severity, Title: title, Detail: detail, Link: "#/actions"}, "decide", "")
		}
		if count > 20 {
			emit(fmt.Sprintf("%d %s proposals recorded", count, state), "Review proposals on the Actions page.")
		} else {
			for _, p := range b.samples[state] {
				action := p.Action
				if action == "" {
					action = "notify"
				}
				emit(fmt.Sprintf("%s: %s on %s", p.VulnID, action, p.DeviceName), p.Reason)
			}
		}
	}
}

// resolveDeviceProposals uses the full open-vulnerability set without a read
// limit; bounded evaluation must never make an unexamined finding look resolved.
func (s *Server) resolveDeviceProposals(ctx context.Context, id int64) error {
	open, e := s.st.OpenVulnIDs(ctx, id)
	if e != nil {
		return e
	}
	return s.st.ResolveProposals(ctx, id, open)
}
func (s *Server) reevaluate(ctx context.Context) error {
	batch := newProposalBatch()
	defer s.emitProposalBatch(ctx, batch)
	nodes, e := s.decisionContext(ctx)
	if e != nil {
		return e
	}
	// Each device gets its own bound, so large devices cannot starve later ones.
	for id := range nodes {
		fs, e := s.st.ListFindings(ctx, store.FindingFilter{DeviceID: id, State: "open", Limit: maxEvaluationsPerDevice})
		if e != nil {
			return e
		}
		if e = s.evaluateFindings(ctx, fs, nodes, batch); e != nil {
			return e
		}
	}
	return nil
}
func (s *Server) startReevaluate() {
	go func() {
		defer func() { s.decide.mu.Lock(); s.decide.reevaluating = false; s.decide.mu.Unlock() }()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if e := s.reevaluate(ctx); e != nil {
			s.log.Warn("reevaluate proposals", "err", e)
		}
	}()
}
