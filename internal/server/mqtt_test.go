package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

type mqttStore struct {
	store.Store
	devs     []store.DeviceRow
	findings []store.FindingRow
	services []store.DeviceService
	fail     string
	kill     string
}

func (st *mqttStore) err(stage string) error {
	if st.fail == stage {
		return errors.New("snapshot unavailable")
	}
	return nil
}
func (st *mqttStore) ListDevices(context.Context) ([]store.DeviceRow, error) {
	return st.devs, st.err("devices")
}
func (st *mqttStore) ListFindings(_ context.Context, f store.FindingFilter) ([]store.FindingRow, error) {
	if f.State != "open" || f.Limit != 20000 {
		return nil, errors.New("wrong filter")
	}
	return st.findings, st.err("findings")
}
func (st *mqttStore) ListAllServices(context.Context) ([]store.DeviceService, error) {
	return st.services, st.err("services")
}
func (st *mqttStore) FindingStats(context.Context) (store.FindingStats, error) {
	return store.FindingStats{Open: 2, Critical: 1, KEV: 1, Exposed: 1}, st.err("stats")
}
func (st *mqttStore) ProposalStats(context.Context) (map[string]int, error) {
	return map[string]int{"pending": 3, "approved": 2}, st.err("proposals")
}
func (st *mqttStore) GetSetting(_ context.Context, key string) (string, error) {
	if key != "decide.killswitch" {
		return "", errors.New("wrong key")
	}
	return st.kill, st.err("kill")
}

func TestMQTTSnapshot(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	ip := func(s string) []proto.Identifier {
		return []proto.Identifier{{Kind: "ip", Value: s, Strength: proto.Weak}}
	}
	st := &mqttStore{kill: "on", devs: []store.DeviceRow{
		{ID: 1, Name: "Internet", Identifiers: ip("8.8.8.8"), FirstSeen: now.Add(-time.Hour), Tags: []string{"ha"}, KEV: 1, Findings: 1},
		{ID: 2, Name: "Tailnet", Identifiers: ip("100.64.1.2"), FirstSeen: now.Add(-2 * time.Hour)},
		{ID: 3, Name: "Local", Identifiers: ip("10.0.0.2"), FirstSeen: now.Add(-48 * time.Hour), Findings: 1},
	}, findings: []store.FindingRow{
		{Finding: store.Finding{DeviceID: 1, PURL: "pkg:pypi/homeassistant@2026.11.0", VulnID: "CVE-test"}, Score: 9.8, KEV: true},
		{Finding: store.Finding{DeviceID: 3, PURL: "pkg:generic/test@1", VulnID: "CVE-local"}, Score: 5},
	}, services: []store.DeviceService{{DeviceID: 1, Service: proto.Service{Address: "0.0.0.0", Port: 8123, Proto: "tcp", Component: "pkg:pypi/homeassistant@2026.11.0"}}}}
	s := &Server{st: st, now: func() time.Time { return now }}
	got, err := s.mqttSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.OpenFindings != 2 || got.Critical != 1 || got.KEV != 1 || got.Exposed != 1 || got.Devices != 3 || got.New24h != 2 || got.ReachInternet != 1 || got.ReachTunnel != 1 || got.ReachLocal != 1 || got.PendingApprovals != 3 || !got.KillSwitch || !got.KEVReachable {
		t.Fatalf("snapshot = %+v", got)
	}
	if len(got.DeviceRisks) != 3 || got.DeviceRisks[0].ID != "1" || got.DeviceRisks[0].Risk != 10 || len(got.DeviceRisks[0].Tags) != 1 {
		t.Fatalf("devices = %+v", got.DeviceRisks)
	}
	top, ok := got.DeviceRisks[0].Top.([]GraphVuln)
	if !ok || len(top) != 1 || top[0].ID != "CVE-test" {
		t.Fatalf("top = %+v", got.DeviceRisks[0].Top)
	}
	// KEV on a local-only device must not raise the reachable alarm.
	st.devs[0].KEV = 0
	st.devs[2].KEV = 1
	st.kill = "off"
	got, err = s.mqttSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.KillSwitch || got.KEVReachable {
		t.Fatalf("local-only snapshot = %+v", got)
	}
	st.devs[1].KEV = 1
	got, err = s.mqttSnapshot(context.Background())
	if err != nil || !got.KEVReachable {
		t.Fatalf("tailnet snapshot = %+v, %v", got, err)
	}
	for _, stage := range []string{"devices", "findings", "services", "stats", "proposals", "kill"} {
		st.fail = stage
		if _, err := s.mqttSnapshot(context.Background()); err == nil {
			t.Errorf("%s failure ignored", stage)
		}
	}
}

func TestMQTTConfigAndDefaultDisabled(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`null`)} {
		s := &Server{cfg: Config{MQTT: raw}}
		stop, err := s.StartMQTT(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		stop()
		if s.mqtt != nil {
			t.Fatal("MQTT enabled by default")
		}
	}
	file := filepath.Join(t.TempDir(), "netnoodle.json")
	if err := os.WriteFile(file, []byte(`{"mqtt":{"broker":"mqtts://broker.local:8883","interval":"60s"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(file)
	if err != nil || len(cfg.MQTT) == 0 {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
	s := &Server{cfg: Config{MQTT: json.RawMessage(`{"broker":"mqtt://remote.example"}`)}}
	if _, err := s.StartMQTT(context.Background()); err == nil {
		t.Fatal("invalid MQTT settings accepted")
	}
}
