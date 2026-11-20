package mqtt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/notify"
)

type publication struct {
	topic    string
	payload  []byte
	retained bool
}

// broker is a small MQTT 3.1.1 test broker: CONNECT, QoS1 PUBLISH, PING
// and DISCONNECT, including retained messages and last wills. No production
// broker dependency is needed to exercise the client over a real TCP socket.
type broker struct {
	t           *testing.T
	ln          net.Listener
	mu          sync.Mutex
	connections map[net.Conn]bool
	messages    []publication
	retained    map[string][]byte
	wills       []publication
	connects    int
	changed     chan struct{}
	acceptDone  chan struct{}
	wg          sync.WaitGroup
}

func startBroker(t *testing.T, addr string) *broker {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	b := &broker{t: t, ln: l, connections: map[net.Conn]bool{}, retained: map[string][]byte{}, changed: make(chan struct{}, 1), acceptDone: make(chan struct{})}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer close(b.acceptDone)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.connections[c] = true
			b.mu.Unlock()
			b.wg.Add(1)
			go b.serve(c)
		}
	}()
	t.Cleanup(b.close)
	return b
}

func (b *broker) close() {
	b.ln.Close()
	<-b.acceptDone
	b.mu.Lock()
	for c := range b.connections {
		c.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}

func (b *broker) record(p publication) {
	b.mu.Lock()
	b.messages = append(b.messages, p)
	if p.retained {
		if len(p.payload) == 0 {
			delete(b.retained, p.topic)
		} else {
			b.retained[p.topic] = p.payload
		}
	}
	b.mu.Unlock()
	select {
	case b.changed <- struct{}{}:
	default:
	}
}

func utf(r *bytes.Reader) string {
	var n uint16
	if binary.Read(r, binary.BigEndian, &n) != nil {
		return ""
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return ""
	}
	return string(b)
}

func packet(r *bufio.Reader) (byte, []byte, error) {
	h, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n, m := 0, 1
	for i := 0; i < 4; i++ {
		digit, err := r.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		n += int(digit&127) * m
		if digit&128 == 0 {
			data := make([]byte, n)
			_, err = io.ReadFull(r, data)
			return h, data, err
		}
		m *= 128
	}
	return 0, nil, fmt.Errorf("bad remaining length")
}

func (b *broker) serve(c net.Conn) {
	defer b.wg.Done()
	var will publication
	graceful := false
	defer func() {
		c.Close()
		b.mu.Lock()
		delete(b.connections, c)
		b.mu.Unlock()
		if !graceful && will.topic != "" {
			b.record(will)
		}
	}()
	r := bufio.NewReader(c)
	for {
		h, p, err := packet(r)
		if err != nil {
			return
		}
		switch h >> 4 {
		case 1:
			in := bytes.NewReader(p)
			if utf(in) != "MQTT" {
				b.t.Error("bad MQTT protocol")
				return
			}
			level, _ := in.ReadByte()
			flags, _ := in.ReadByte()
			in.Seek(2, io.SeekCurrent)
			if level != 4 || utf(in) != "netnoodle" {
				b.t.Error("bad MQTT client identity")
				return
			}
			if flags&4 != 0 {
				will = publication{utf(in), []byte(utf(in)), flags&32 != 0}
			}
			b.mu.Lock()
			b.wills = append(b.wills, will)
			b.connects++
			b.mu.Unlock()
			c.Write([]byte{0x20, 2, 0, 0})
		case 3:
			in := bytes.NewReader(p)
			topic := utf(in)
			qos := (h >> 1) & 3
			var id uint16
			if qos > 0 {
				binary.Read(in, binary.BigEndian, &id)
			}
			payload, _ := io.ReadAll(in)
			b.record(publication{topic, payload, h&1 != 0})
			if qos == 1 {
				c.Write([]byte{0x40, 2, byte(id >> 8), byte(id)})
			}
		case 12:
			c.Write([]byte{0xd0, 0})
		case 14:
			graceful = true
			return
		default:
			b.t.Errorf("unexpected MQTT packet %x", h)
			return
		}
	}
}

func (b *broker) await(t *testing.T, f func(*broker) bool) {
	t.Helper()
	timer := time.NewTimer(12 * time.Second)
	defer timer.Stop()
	for {
		b.mu.Lock()
		ok := f(b)
		b.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-b.changed:
		case <-timer.C:
			t.Fatal("timed out waiting for MQTT publication")
		}
	}
}

func count(b *broker, topic string) int {
	n := 0
	for _, m := range b.messages {
		if m.topic == topic {
			n++
		}
	}
	return n
}

func TestDiscoveryStatesEventsDebounceAndReconnect(t *testing.T) {
	b := startBroker(t, "127.0.0.1:0")
	addr := b.ln.Addr().String()
	var changed atomic.Bool
	var calls atomic.Int32
	provider := func(context.Context) (Snapshot, error) {
		calls.Add(1)
		tags := []string{"ha"}
		if changed.Load() {
			tags = nil
		}
		return Snapshot{OpenFindings: 4, Critical: 2, KEV: 1, Exposed: 3, Devices: 8, New24h: 2, ReachInternet: 1, ReachTunnel: 2, ReachLocal: 5, PendingApprovals: 3, KEVReachable: true, KillSwitch: changed.Load(), DeviceRisks: []Device{
			{ID: "12", Name: "Router", Tags: tags, Risk: 9.4, Top: []map[string]any{{"id": "CVE-test", "kev": true}}},
			{ID: "13", Name: "Private", Tags: []string{"other"}, Risk: 10},
		}}, nil
	}
	raw, _ := json.Marshal(map[string]any{"broker": "mqtt://" + addr, "interval": "1h"})
	p, err := New(raw, provider)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("publisher did not stop")
		}
	}()
	risk := "risk_" + digest("12")
	b.await(t, func(b *broker) bool {
		return string(b.retained["netnoodle/"+risk+"/state"]) == "9.4" && len(b.retained["netnoodle/"+risk+"/attributes"]) > 0
	})
	b.mu.Lock()
	seen := map[string]bool{}
	configs := 0
	for topic, data := range b.retained {
		if !strings.HasSuffix(topic, "/config") {
			continue
		}
		configs++
		var cfg map[string]any
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Error(err)
			continue
		}
		id, _ := cfg["unique_id"].(string)
		state, _ := cfg["state_topic"].(string)
		if id == "" || seen[id] || state == "" || cfg["availability_topic"] != "netnoodle/availability" || cfg["command_topic"] != nil {
			t.Errorf("invalid discovery %s: %s", topic, data)
		}
		seen[id] = true
		if strings.Contains(topic, "kev_reachable") && cfg["device_class"] != "problem" {
			t.Errorf("missing problem device class")
		}
	}
	if configs != 6 {
		t.Errorf("discovery configs = %d", configs)
	}
	for topic, want := range map[string]string{"open_findings": "4", "devices": "8", "kev_reachable": "ON", "pending_approvals": "3", "kill_switch": "OFF"} {
		if got := string(b.retained["netnoodle/"+topic+"/state"]); got != want {
			t.Errorf("%s = %s", topic, got)
		}
	}
	var attrs map[string]int
	json.Unmarshal(b.retained["netnoodle/open_findings/attributes"], &attrs)
	if attrs["critical"] != 2 || attrs["kev"] != 1 || attrs["exposed"] != 3 {
		t.Errorf("finding attributes = %v", attrs)
	}
	json.Unmarshal(b.retained["netnoodle/devices/attributes"], &attrs)
	if attrs["new_24h"] != 2 || attrs["internet"] != 1 || attrs["tunnel"] != 2 || attrs["local"] != 5 {
		t.Errorf("device attributes = %v", attrs)
	}
	var riskAttributes struct {
		Top []struct {
			ID string `json:"id"`
		} `json:"top_findings"`
	}
	if json.Unmarshal(b.retained["netnoodle/"+risk+"/attributes"], &riskAttributes) != nil || len(riskAttributes.Top) != 1 || riskAttributes.Top[0].ID != "CVE-test" {
		t.Errorf("risk attributes = %+v", riskAttributes)
	}
	if b.connects != 1 || len(b.wills) != 1 || b.wills[0].topic != "netnoodle/availability" || string(b.wills[0].payload) != "offline" || !b.wills[0].retained {
		t.Errorf("last will = %+v", b.wills)
	}
	b.mu.Unlock()
	if calls.Load() != 1 {
		t.Fatalf("initial snapshot calls = %d", calls.Load())
	}
	changed.Store(true)
	for i := 0; i < 50; i++ {
		p.Trigger()
	}
	e := notify.Event{Type: "finding.new", Severity: "critical", Title: "KEV found", Detail: "detail", Link: "#/findings", At: time.Now().UTC(), Fields: map[string]string{"private": "omitted"}}
	p.Notify(context.Background(), e)
	b.await(t, func(b *broker) bool { return count(b, "netnoodle/event") == 1 })
	b.mu.Lock()
	for _, m := range b.messages {
		if m.topic == "netnoodle/event" {
			var ev map[string]any
			if json.Unmarshal(m.payload, &ev) != nil || len(ev) != 6 || ev["type"] != e.Type || ev["severity"] != e.Severity || ev["title"] != e.Title || ev["detail"] != "" /* details are off by default */ || ev["link"] != e.Link || ev["at"] == nil || m.retained {
				t.Errorf("event = %s", m.payload)
			}
		}
	}
	b.mu.Unlock()
	if calls.Load() != 1 {
		t.Error("snapshot was not debounced")
	}
	b.await(t, func(b *broker) bool { return string(b.retained["netnoodle/kill_switch/state"]) == "ON" })
	b.await(t, func(b *broker) bool {
		for topic := range b.retained {
			// Untagging removes the config AND the retained state and
			// attributes (they name findings).
			if strings.HasSuffix(topic, "/"+risk+"/config") || topic == "netnoodle/"+risk+"/state" || topic == "netnoodle/"+risk+"/attributes" {
				return false
			}
		}
		return true
	})
	if calls.Load() != 2 {
		t.Errorf("burst snapshot calls = %d", calls.Load())
	}
	// Drop the TCP connection and listener; the broker records the client's LWT.
	b.close()
	b.mu.Lock()
	available := string(b.retained["netnoodle/availability"])
	b.mu.Unlock()
	if available != "offline" {
		t.Errorf("last will state = %s", available)
	}
	restarted := startBroker(t, addr)
	restarted.await(t, func(b *broker) bool { return string(b.retained["netnoodle/kill_switch/state"]) == "ON" })
	restarted.mu.Lock()
	configCount := 0
	for topic := range restarted.retained {
		if strings.HasSuffix(topic, "/config") {
			configCount++
		}
	}
	restarted.mu.Unlock()
	if configCount != 5 {
		t.Errorf("rediscovered configs = %d", configCount)
	}
	cancel()
	<-done
	restarted.await(t, func(b *broker) bool { return string(b.retained["netnoodle/availability"]) == "offline" })
}

func TestSettingsAndBoundedQueue(t *testing.T) {
	provider := func(context.Context) (Snapshot, error) { return Snapshot{}, nil }
	for _, tc := range []struct {
		raw string
		ok  bool
	}{
		{`{"broker":"mqtts://broker.local"}`, true},
		{`{"broker":"mqtt://127.0.0.1:1883"}`, true},
		{`{"broker":"mqtt://[::1]"}`, true},
		{`{"broker":"mqtt://broker.local","allow_plain":true}`, true},
		{`{"broker":"mqtt://broker.local"}`, false},
		{`{"broker":"mqtt://localhost"}`, false},
		{`{"broker":"https://broker.local"}`, false},
		{`{"broker":"mqtts://user:secret@host"}`, false},
		{`{"broker":"mqtts://host/path"}`, false},
		{`{"broker":"mqtts://host:70000"}`, false},
		{`{"broker":"mqtts://host","topic_prefix":"bad/#"}`, false},
		{`{"broker":"mqtts://host","interval":"bad-secret"}`, false},
		{`{"broker":"mqtts://host","interval":"0s"}`, false},
		{`{"broker":"mqtts://host","password_file":"missing"}`, false},
		{`{"broker":"mqtts://host","password":"secret"}`, false},
		{`{} {}`, false},
	} {
		_, err := New(json.RawMessage(tc.raw), provider)
		if (err == nil) != tc.ok || (err != nil && strings.Contains(err.Error(), "secret")) {
			t.Errorf("%s: %v", tc.raw, err)
		}
	}
	p, err := New(json.RawMessage(`{"broker":"mqtt://127.0.0.1"}`), provider)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < queueSize+10; i++ {
		p.Notify(context.Background(), notify.Event{Type: "device.new", Title: strconv.Itoa(i)})
	}
	if len(p.events) != queueSize || len(p.wake) != 1 {
		t.Fatalf("queue lengths = %d, %d", len(p.events), len(p.wake))
	}
	if first := <-p.events; first.Title != "10" {
		t.Errorf("oldest event = %s", first.Title)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				p.Notify(context.Background(), notify.Event{})
			}
		}()
	}
	wg.Wait()
	file := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(file, []byte("test-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"broker": "mqtts://broker.local", "password_file": file})
	p, err = New(raw, provider)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if p.password != "test-password" {
		t.Error("password not read and trimmed at startup")
	}
}

func TestPeriodicPublishingAndCustomTag(t *testing.T) {
	b := startBroker(t, "127.0.0.1:0")
	raw, _ := json.Marshal(map[string]any{"broker": "mqtt://" + b.ln.Addr().String(), "interval": "5s", "device_tag": "export"})
	p, err := New(raw, func(context.Context) (Snapshot, error) {
		return Snapshot{DeviceRisks: []Device{
			{ID: "included", Name: "Included", Tags: []string{"export"}, Risk: 15},
			{ID: "excluded", Name: "Excluded", Tags: []string{"ha"}, Risk: 5},
		}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()
	defer func() { cancel(); <-done }()
	b.await(t, func(b *broker) bool { return count(b, "netnoodle/open_findings/state") >= 2 })
	b.mu.Lock()
	defer b.mu.Unlock()
	if string(b.retained["netnoodle/risk_"+digest("included")+"/state"]) != "10" {
		t.Error("custom tag or risk clamp failed")
	}
	if _, ok := b.retained["netnoodle/risk_"+digest("excluded")+"/state"]; ok {
		t.Error("device without custom tag was published")
	}
}

func TestEventAllowlistAndDetails(t *testing.T) {
	provider := func(context.Context) (Snapshot, error) { return Snapshot{}, nil }
	p, err := New(json.RawMessage(`{"broker":"mqtt://127.0.0.1"}`), provider)
	if err != nil {
		t.Fatal(err)
	}
	p.Notify(context.Background(), notify.Event{Type: "device.claimed", Title: "claim", Detail: "agent x"})
	p.Notify(context.Background(), notify.Event{Type: "proposal.notify", Title: "n"})
	p.Notify(context.Background(), notify.Event{Type: "device.new", Title: "New device: cam", Detail: "mac=aa:bb:cc:00:00:01, ip=10.0.0.9"})
	if len(p.events) != 1 {
		t.Fatalf("events queued = %d, want only device.new", len(p.events))
	}
	if e := <-p.events; e.Detail != "" {
		t.Fatalf("detail published by default: %q", e.Detail)
	}
	p, _ = New(json.RawMessage(`{"broker":"mqtt://127.0.0.1","events":["device.claimed"],"event_details":true}`), provider)
	p.Notify(context.Background(), notify.Event{Type: "device.claimed", Title: "claim", Detail: "agent x"})
	if e := <-p.events; e.Detail != "agent x" {
		t.Fatalf("configured details missing: %+v", e)
	}
	if _, err := New(json.RawMessage(`{"broker":"mqtts://broker.lan","fingerprint":"zz"}`), provider); err == nil {
		t.Fatal("bad fingerprint accepted")
	}
}
