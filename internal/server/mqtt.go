package server

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/mqtt"
	"github.com/JulianStremel/netnoodle/internal/store"
)

// StartMQTT is called once during startup, before ingest and matching start.
// It returns a shutdown function that publishes offline and joins the worker.
func (s *Server) StartMQTT(ctx context.Context) (func(), error) {
	if len(s.cfg.MQTT) == 0 || strings.TrimSpace(string(s.cfg.MQTT)) == "null" {
		return func() {}, nil
	}
	p, err := mqtt.New(s.cfg.MQTT, s.mqttSnapshot)
	if err != nil {
		return nil, err
	}
	s.mqtt = p
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()
	return func() { cancel(); <-done }, nil
}

func (s *Server) mqttSnapshot(ctx context.Context) (mqtt.Snapshot, error) {
	var out mqtt.Snapshot
	devs, err := s.st.ListDevices(ctx)
	if err != nil {
		return out, err
	}
	fs, err := s.st.ListFindings(ctx, store.FindingFilter{State: "open", Limit: 20000})
	if err != nil {
		return out, err
	}
	svcs, err := s.st.ListAllServices(ctx)
	if err != nil {
		return out, err
	}
	stats, err := s.st.FindingStats(ctx)
	if err != nil {
		return out, err
	}
	proposals, err := s.st.ProposalStats(ctx)
	if err != nil {
		return out, err
	}
	kill, err := s.st.GetSetting(ctx, "decide.killswitch")
	if err != nil {
		return out, err
	}
	now := s.now()
	g := buildGraph(devs, fs, svcs, now)
	out.OpenFindings = stats.Open
	out.Critical = stats.Critical
	out.KEV = stats.KEV
	out.Exposed = stats.Exposed
	out.Devices = len(devs)
	out.ReachInternet = g.Stats["reach.internet"]
	out.ReachTunnel = g.Stats["reach.tunnel"]
	out.ReachLocal = g.Stats["reach.local"]
	out.PendingApprovals = proposals["pending"]
	out.KillSwitch = kill == "on"
	for _, d := range devs {
		if !d.FirstSeen.IsZero() && !d.FirstSeen.Before(now.Add(-24*time.Hour)) && !d.FirstSeen.After(now) {
			out.New24h++
		}
	}
	for _, n := range g.Nodes {
		if n.KEV > 0 && (n.Reach == reachInternet || n.Reach == reachTunnel) {
			out.KEVReachable = true
		}
		out.DeviceRisks = append(out.DeviceRisks, mqtt.Device{ID: strconv.FormatInt(n.ID, 10), Name: n.Name, Tags: n.Tags, Risk: n.Risk, Top: n.Top})
	}
	return out, nil
}

func (s *Server) triggerMQTT() {
	if s.mqtt != nil {
		s.mqtt.Trigger()
	}
	for _, n := range s.notifierSnapshot() {
		if p, ok := n.(*mqtt.Publisher); ok {
			p.Trigger()
		}
	}
}
