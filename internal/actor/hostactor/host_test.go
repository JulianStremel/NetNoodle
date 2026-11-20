package hostactor

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/proto"
)

const emptyChain = `{"nftables":[{"metainfo":{"json_schema_version":1}},{"chain":{"family":"inet","table":"netnoodle","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}}]}`

//go:embed testdata/chain.json
var fullChainFixture string

// Fixture follows nft -j list chain output, including handles and metadata.
func chainFixture(kinds ...int) string {
	entries := []string{`{"chain":{"family":"inet","table":"netnoodle","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}}`}
	kinds = append([]int{3}, kinds...)
	for i, kind := range kinds {
		expr := []byte(ruleExpressions[kind])
		entries = append(entries, fmt.Sprintf(`{"rule":{"family":"inet","table":"netnoodle","chain":"input","handle":%d,"expr":%s}}`, i+10, expr))
	}
	return `{"nftables":[` + strings.Join(entries, ",") + `]}`
}

func setFixture(protocol, elements string) string {
	return fmt.Sprintf(`{"nftables":[{"set":{"family":"inet","table":"netnoodle","name":"blocked_%s","type":"inet_service","flags":["timeout"],"elem":%s}}]}`, protocol, elements)
}

func elementFixture(number int, ttl int64) string {
	return fmt.Sprintf(`[{"elem":{"val":%d,"timeout":%d,"expires":%d}}]`, number, ttl, ttl-1)
}

type call struct {
	program string
	args    []string
	stdin   string
}

type fakeRunner struct {
	t     *testing.T
	calls []call
	chain string
	sets  map[string]string
	hook  func(call) ([]byte, []byte, error, bool)
}

func newFake(t *testing.T) *fakeRunner {
	return &fakeRunner{t: t, chain: chainFixture(0, 1, 2), sets: map[string]string{
		"blocked_tcp": setFixture("tcp", elementFixture(443, 3600)),
		"blocked_udp": setFixture("udp", elementFixture(53, 3600)),
	}}
}

func (f *fakeRunner) Run(ctx context.Context, program string, args []string, stdin string) ([]byte, []byte, error) {
	f.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > commandTimeout || time.Until(deadline) <= 0 {
		f.t.Fatal("command context must have a live deadline within 15s")
	}
	c := call{program, append([]string(nil), args...), stdin}
	f.calls = append(f.calls, c)
	if f.hook != nil {
		if out, stderr, err, handled := f.hook(c); handled {
			return out, stderr, err
		}
	}
	if len(args) == 6 && args[0] == "-j" {
		if stdin != "" || program != "/usr/sbin/nft" {
			f.t.Fatalf("unexpected nft invocation: %+v", c)
		}
		if args[2] == "chain" {
			return []byte(strings.ReplaceAll(f.chain, `"input"`, fmt.Sprintf(`"%s"`, args[5]))), nil, nil
		}
		return []byte(f.sets[args[5]]), nil, nil
	}
	if program != "/usr/sbin/nft" || !reflect.DeepEqual(args, []string{"-f", "-"}) || stdin == "" {
		f.t.Fatalf("unexpected command: %+v", c)
	}
	return nil, nil, nil
}

func build(t *testing.T, raw string, f *fakeRunner) *Backend {
	t.Helper()
	b, err := NewWithRunner("local-host", json.RawMessage(raw), f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func order(action string) proto.Order {
	return proto.Order{Action: action, Targets: []proto.Identifier{{Kind: "agent", Value: "web01"}}, Params: map[string]any{"ports": []string{"443/tcp"}}, TTL: 3600}
}

func TestBlockScriptAndArguments(t *testing.T) {
	f := newFake(t)
	f.chain = emptyChain
	b := build(t, `{"agent":"web01"}`, f)
	o := order("block-port")
	// JSON decoding produces []any, including a duplicate to deduplicate.
	o.Params["ports"] = []any{"443/tcp", "53/udp", "443/tcp"}
	msg, err := b.execute(context.Background(), o)
	if err != nil || msg != "ports blocked; verified" {
		t.Fatalf("message=%q error=%v", msg, err)
	}
	var scripts string
	for _, c := range f.calls {
		scripts += c.stdin
		if c.stdin != "" && (c.program != "/usr/sbin/nft" || !reflect.DeepEqual(c.args, []string{"-f", "-"})) {
			t.Fatalf("bad script invocation: %+v", c)
		}
	}
	for _, want := range []string{"hook input priority -10", "hook prerouting priority -150", "input iifname \"lo\" accept", "prerouting iifname \"lo\" accept", "input ct state established,related accept", "prerouting ct state established,related accept", "input tcp dport @blocked_tcp drop", "prerouting udp dport @blocked_udp drop", "443 timeout 3600s", "53 timeout 3600s"} {
		if !strings.Contains(scripts, want) {
			t.Errorf("missing %q in %s", want, scripts)
		}
	}
	if strings.Count(scripts, "add element inet netnoodle blocked_tcp") != 1 || strings.Count(scripts, "add element inet netnoodle blocked_udp") != 1 {
		t.Fatal("ports not deduplicated")
	}
}

func TestRulesOnlyAddedWhenMissing(t *testing.T) {
	for _, tc := range []struct {
		name, fixture, want string
	}{
		{"all present", chainFixture(0, 1, 2), ""},
		{"full JSON fixture", fullChainFixture, ""},
		{"missing udp", chainFixture(0, 1), "add rule inet netnoodle input udp dport @blocked_udp drop\n"},
		{"missing loopback", chainFixture(1, 2), "insert rule inet netnoodle input iifname \"lo\" accept\n"},
		{"duplicates", chainFixture(0, 1, 1, 2), "delete rule inet netnoodle input handle 13\n"},
		{"late loopback", chainFixture(1, 0, 2), "delete rule inet netnoodle input handle 12\ninsert rule inet netnoodle input iifname \"lo\" accept\n"},
		{"set in operator", strings.ReplaceAll(chainFixture(0, 1, 2), `"op":"==","left":{"payload"`, `"op":"in","left":{"payload"`), ""},
		{"counter", strings.Replace(chainFixture(0, 1, 2), `{"drop":null}`, `{"counter":{"packets":2,"bytes":100}},{"drop":null}`, 1), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.chain = tc.fixture
			b := build(t, `{"agent":"web01"}`, f)
			if err := b.ensureChainRules(context.Background(), "input"); err != nil {
				t.Fatal(err)
			}
			if len(f.calls) == 1 && tc.want == "" {
				return
			}
			if len(f.calls) != 2 || f.calls[1].stdin != tc.want {
				t.Fatalf("calls=%+v; want script=%q", f.calls, tc.want)
			}
		})
	}
	// A second order must discover existing rules rather than append them again.
	f := newFake(t)
	f.chain = emptyChain
	b := build(t, `{"agent":"web01"}`, f)
	if _, err := b.execute(context.Background(), order("block-port")); err != nil {
		t.Fatal(err)
	}
	f.chain, f.calls = chainFixture(0, 1, 2), nil
	if _, err := b.execute(context.Background(), order("block-port")); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 6 {
		t.Fatalf("second order added rules: %+v", f.calls)
	}
}

func TestTTL(t *testing.T) {
	for _, tc := range []struct {
		name, maxTTL string
		ttl, want    int64
	}{
		{"short order", "2h", 60, 60},
		{"clamped", "2h", 999999, 7200},
		{"zero", "2h", 0, 7200},
		{"overflow safe", "2h", 1<<63 - 1, 7200},
		{"fraction rounds down", "1500ms", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.sets["blocked_tcp"] = setFixture("tcp", elementFixture(443, tc.want))
			b := build(t, fmt.Sprintf(`{"agent":"web01","max_ttl":%q}`, tc.maxTTL), f)
			o := order("block-port")
			o.TTL = tc.ttl
			if _, err := b.execute(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(f.calls[len(f.calls)-2].stdin, fmt.Sprintf("timeout %ds", tc.want)) {
				t.Fatalf("wrong TTL: %+v", f.calls)
			}
		})
	}
}

func TestLocalRefusalsMakeNoCommands(t *testing.T) {
	orders := []proto.Order{order("reboot"), {Action: "block-port"}}
	for _, targets := range [][]proto.Identifier{
		{{Kind: "agent", Value: "other"}},
		{{Kind: "mac", Value: "web01"}},
		{{Kind: "agent", Value: "web01"}, {Kind: "agent", Value: "web01"}},
	} {
		o := order("block-port")
		o.Targets = targets
		orders = append(orders, o)
	}
	for _, ports := range []any{
		nil, "443/tcp", []any{443}, []any{"443/tcp", false}, []string{},
		[]string{"0/tcp"}, []string{"65536/tcp"}, []string{"-1/tcp"}, []string{"+22/tcp"}, []string{"022/tcp"},
		[]string{"443"}, []string{"443/TCP"}, []string{"443/sctp"}, []string{"443/tcp/udp"},
		[]string{"443/tcp; flush ruleset"}, []string{"443\n/tcp"},
		strings.Split(strings.Repeat("443/tcp,", 32)+"443/tcp", ","),
		[]string{"443/tcp", "22/tcp"}, []string{"22/udp"}, []string{"7444/tcp"},
	} {
		o := order("block-port")
		o.Params["ports"] = ports
		orders = append(orders, o)
	}
	o := order("block-port")
	o.TTL = -1
	orders = append(orders, o)
	for _, o := range orders {
		f := newFake(t)
		b := build(t, `{"agent":"web01"}`, f)
		if _, err := b.execute(context.Background(), o); err == nil || len(f.calls) != 0 {
			t.Errorf("invalid order=%+v; error=%v; calls=%+v", o, err, f.calls)
		}
	}
}

func TestExplicitEmptyProtection(t *testing.T) {
	f := newFake(t)
	f.sets["blocked_tcp"] = setFixture("tcp", elementFixture(22, 3600))
	b := build(t, `{"agent":"web01","never_block_ports":[]}`, f)
	o := order("block-port")
	o.Params["ports"] = []string{"22/tcp"}
	if _, err := b.execute(context.Background(), o); err != nil {
		t.Fatal(err)
	}
}

func TestUnblockProtectedAndExpiredPorts(t *testing.T) {
	f := newFake(t)
	f.sets["blocked_tcp"] = setFixture("tcp", `[]`)
	f.hook = func(c call) ([]byte, []byte, error, bool) {
		if strings.Contains(c.stdin, "{ 22 }") {
			return nil, []byte("No such file or directory"), errors.New("exit 1"), true
		}
		return nil, nil, nil, false
	}
	b := build(t, `{"agent":"web01"}`, f)
	o := order("unblock-port")
	o.Params["ports"] = []any{"22/tcp", "443/tcp"}
	o.TTL = -1 // recovery does not depend on TTL
	if _, err := b.execute(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 6 || f.calls[1].stdin != "delete element inet netnoodle blocked_tcp { 22 }\n" || f.calls[4].stdin != "delete element inet netnoodle blocked_tcp { 443 }\n" {
		t.Fatalf("unblock commands=%+v", f.calls)
	}
}

type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e) }
func (e exitError) ExitCode() int { return int(e) }

func TestServices(t *testing.T) {
	for _, tc := range []struct {
		action, state, settings string
		exit                    int
		wantErr                 bool
	}{
		{"stop-service", "inactive", `["nginx.service"]`, 3, false},
		{"start-service", "active", `["nginx.service"]`, 0, false},
		{"stop-service", "active", `["nginx.service"]`, 0, true},
		{"start-service", "inactive", `["nginx.service"]`, 3, true},
		{"stop-service", "inactive", `["nginx.service"]`, 4, true},
		{"start-service", "active", `["nginx.service"]`, 1, true},
		{"stop-service", "inactive", `[]`, 3, true},
		{"start-service", "active", `[]`, 0, true},
	} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			f := newFake(t)
			f.hook = func(c call) ([]byte, []byte, error, bool) {
				if c.program != "/usr/bin/systemctl" || c.stdin != "" || len(c.args) != 2 || c.args[1] != "nginx.service" {
					t.Fatalf("bad systemctl invocation: %+v", c)
				}
				if c.args[0] == "is-active" {
					var err error
					if tc.exit != 0 {
						err = exitError(tc.exit)
					}
					return []byte(tc.state + "\n"), []byte("verification diagnostic"), err, true
				}
				if c.args[0] != strings.TrimSuffix(tc.action, "-service") {
					t.Fatalf("wrong action: %+v", c)
				}
				return nil, nil, nil, true
			}
			b := build(t, `{"agent":"web01","services":`+tc.settings+`}`, f)
			o := order(tc.action)
			o.Params = map[string]any{"unit": "nginx.service"}
			_, err := b.execute(context.Background(), o)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v", err)
			}
			wantCalls := 2
			if tc.action == "stop-service" {
				wantCalls = 3
				if tc.exit == 4 {
					wantCalls = 1
				}
			}
			if tc.settings == "[]" {
				wantCalls = 0
			}
			if len(f.calls) != wantCalls {
				t.Fatalf("calls=%+v", f.calls)
			}
		})
	}
	f := newFake(t)
	b := build(t, `{"agent":"web01","services":["nginx.service"]}`, f)
	for _, unit := range []any{nil, 12, "other.service", "nginx.service; reboot", "--all"} {
		for _, action := range []string{"stop-service", "start-service"} {
			o := order(action)
			o.Params = map[string]any{"unit": unit}
			if _, err := b.execute(context.Background(), o); err == nil || len(f.calls) != 0 {
				t.Fatalf("unit=%v, err=%v, calls=%+v", unit, err, f.calls)
			}
		}
	}
}

func TestVerificationFailures(t *testing.T) {
	for _, elements := range []string{`[]`, `[443]`, `[{"elem":{"val":443,"timeout":0}}]`, `[{"elem":{"val":443,"timeout":3601}}]`, `[{"elem":{"val":443,"timeout":60}}]`, `[{"elem":{"val":444,"timeout":3600}}]`, `[{}]`, `[null]`} {
		t.Run(elements, func(t *testing.T) {
			f := newFake(t)
			f.sets["blocked_tcp"] = setFixture("tcp", elements)
			b := build(t, `{"agent":"web01"}`, f)
			if _, err := b.execute(context.Background(), order("block-port")); err == nil || !strings.Contains(err.Error(), "verification") {
				t.Fatalf("verification accepted %s: %v", elements, err)
			}
		})
	}
	f := newFake(t)
	f.hook = func(c call) ([]byte, []byte, error, bool) {
		if strings.HasPrefix(c.stdin, "delete element") {
			return nil, []byte("Operation not permitted"), exitError(1), true
		}
		return nil, nil, nil, false
	}
	b := build(t, `{"agent":"web01"}`, f)
	if _, err := b.execute(context.Background(), order("unblock-port")); err == nil || !strings.Contains(err.Error(), "rc 1") {
		t.Fatalf("unblock error=%v", err)
	}
}

func TestSettings(t *testing.T) {
	for _, raw := range []string{
		`{`, `null`, `[]`, `{}`, `{} {}`, `{"agent":""}`, `{"agent":" "}`,
		`{"agent":"web01","unknown":1}`, `{"agent":"web01","nft":"nft"}`,
		`{"agent":"web01","systemctl":"bin/systemctl"}`, `{"agent":"web01","nft":"C:/nft"}`,
		`{"agent":"web01","table":"Netnoodle"}`, `{"agent":"web01","table":"x; flush ruleset"}`,
		`{"agent":"web01","table":"` + strings.Repeat("a", 33) + `"}`,
		`{"agent":"web01","max_ttl":"bad"}`, `{"agent":"web01","max_ttl":"0s"}`,
		`{"agent":"web01","max_ttl":"-1h"}`, `{"agent":"web01","max_ttl":"1ms"}`,
		`{"agent":"web01","never_block_ports":[0]}`, `{"agent":"web01","never_block_ports":[65536]}`,
		`{"agent":"web01","never_block_ports":["22"]}`, `{"agent":"web01","never_block_ports":null}`,
		`{"agent":"web01","services":null}`, `{"agent":"web01","agent":null}`,
		`{"agent":"web01","services":["--all"]}`, `{"agent":"web01","services":["*.service"]}`,
		`{"agent":"web01","services":["nginx.service; reboot"]}`, `{"agent":"web01","services":["/nginx.service"]}`,
	} {
		if _, err := New("bad", json.RawMessage(raw)); err == nil {
			t.Errorf("accepted settings: %s", raw)
		}
	}
	f := newFake(t)
	b := build(t, `{"agent":"web01"}`, f)
	if b.Name() != "local-host" || b.maxTTL != 86400 || !b.neverBlock[22] || len(b.services) != 0 || len(f.calls) != 0 {
		t.Fatalf("incorrect defaults: %+v", b)
	}
	if !reflect.DeepEqual(b.Capabilities(), []proto.Capability{
		{Action: "block-port", TargetIDKinds: []string{"agent"}, TargetScope: []string{"agent=web01"}, Reversible: true, RevertAction: "unblock-port"},
		{Action: "unblock-port", TargetIDKinds: []string{"agent"}, TargetScope: []string{"agent=web01"}},
		{Action: "stop-service", TargetIDKinds: []string{"agent"}, TargetScope: []string{"agent=web01"}, Reversible: true, RevertAction: "start-service"},
		{Action: "start-service", TargetIDKinds: []string{"agent"}, TargetScope: []string{"agent=web01"}},
	}) {
		t.Fatal("incorrect capabilities")
	}
	if _, err := NewWithRunner("bad", json.RawMessage(`{"agent":"web01"}`), nil); err == nil {
		t.Fatal("accepted nil runner")
	}
	if _, err := actor.Registry.Build("host", "registered", json.RawMessage(`{"agent":"web01"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestCommandErrorsAndLimits(t *testing.T) {
	for _, stream := range []string{"stderr", "stdout", "error"} {
		t.Run(stream, func(t *testing.T) {
			f := newFake(t)
			f.hook = func(call) ([]byte, []byte, error, bool) {
				large := []byte(strings.Repeat("x", maxOutput+1))
				if stream == "stdout" {
					return large, nil, nil, true
				}
				if stream == "stderr" {
					return nil, large, nil, true
				}
				return nil, []byte("  diagnostic: " + strings.Repeat("e", 700) + "  "), exitError(1), true
			}
			b := build(t, `{"agent":"web01"}`, f)
			_, err := b.execute(context.Background(), order("block-port"))
			if err == nil || len(err.Error()) > 700 || (stream != "error" && !strings.Contains(err.Error(), "1 MiB")) || (stream == "error" && (!strings.Contains(err.Error(), "rc 1") || strings.Contains(err.Error(), "diagnostic:"))) {
				t.Fatalf("unsafe command error: %v", err)
			}
		})
	}
	var buf cappedBuffer
	if n, err := buf.Write([]byte(strings.Repeat("x", maxOutput+123))); n != maxOutput+123 || err != nil || buf.Len() != maxOutput || !buf.overflow {
		t.Fatal("buffer did not cap and drain output")
	}
	if n, _ := buf.Write([]byte("more")); n != 4 || buf.Len() != maxOutput {
		t.Fatal("full buffer did not drain output")
	}
	// os/exec copies pipes with io.Copy. In particular, a promoted
	// bytes.Buffer.ReadFrom must not bypass the capped Write method.
	var copied cappedBuffer
	if _, err := io.Copy(&copied, io.LimitReader(strings.NewReader(strings.Repeat("y", maxOutput+123)), maxOutput+123)); err != nil || copied.Len() != maxOutput || !copied.overflow {
		t.Fatal("io.Copy bypassed the output cap")
	}
}

func TestInvalidNFTJSON(t *testing.T) {
	for _, output := range []string{`{`, `{}`, `null`, `{"nftables":null}`, `{"nftables":[]}`, `{"nftables":[{"chain":{"family":"ip","table":"netnoodle","name":"input"}}]}`} {
		f := newFake(t)
		f.chain = output
		b := build(t, `{"agent":"web01"}`, f)
		if _, err := b.execute(context.Background(), order("block-port")); err == nil {
			t.Fatalf("accepted invalid nft JSON: %s", output)
		}
		if len(f.calls) != 2 {
			t.Fatalf("changed rules/elements after invalid JSON: %+v", f.calls)
		}
	}
}

func TestExampleConfig(t *testing.T) {
	data, err := os.ReadFile("../../../deploy/nn-actor.host.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg actor.Config
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DryRun == nil || !*cfg.DryRun {
		t.Fatal("example must default to dry run")
	}
	enabled := 0
	for _, spec := range cfg.Backends {
		if spec.Disabled {
			continue
		}
		enabled++
		b := build(t, string(spec.Settings), newFake(t))
		if spec.Type != "host" || b.settings.Agent != "web01" || len(b.services) != 0 {
			t.Fatal("example must enable only host port actions")
		}
	}
	if enabled != 1 || !reflect.DeepEqual(cfg.Allow, []actor.AllowRule{
		{Action: "block-port", Targets: []string{"agent=web01"}},
		{Action: "unblock-port", Targets: []string{"agent=web01"}},
	}) {
		t.Fatal("incorrect example allow rules or backend count")
	}
}
