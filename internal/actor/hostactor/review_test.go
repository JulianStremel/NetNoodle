package hostactor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
)

// Apply the element scripts to a tiny fake kernel so timeout refreshes and
// removals are verified against the resulting state rather than canned JSON.
func statefulNFT(t *testing.T) (*fakeRunner, map[string]map[int]int64) {
	f := newFake(t)
	sets := map[string]map[int]int64{"tcp": {}, "udp": {}}
	pattern := regexp.MustCompile(`^(add|delete) element inet netnoodle blocked_(tcp|udp) \{ ([0-9]+)(?: timeout ([0-9]+)s)? \}$`)
	refresh := func() {
		for proto, values := range sets {
			elems := []any{}
			for port, ttl := range values {
				elems = append(elems, map[string]any{"elem": map[string]any{"val": port, "timeout": ttl}})
			}
			b, _ := json.Marshal(elems)
			f.sets["blocked_"+proto] = setFixture(proto, string(b))
		}
	}
	refresh()
	f.hook = func(c call) ([]byte, []byte, error, bool) {
		for _, line := range strings.Split(c.stdin, "\n") {
			m := pattern.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			n, _ := strconv.Atoi(m[3])
			if m[1] == "delete" {
				delete(sets[m[2]], n)
			} else {
				ttl, _ := strconv.ParseInt(m[4], 10, 64)
				sets[m[2]][n] = ttl
			}
		}
		refresh()
		return nil, nil, nil, false
	}
	return f, sets
}

func TestPortHoldersAndTimeoutsSurviveRestart(t *testing.T) {
	f, sets := statefulNFT(t)
	b := build(t, `{"agent":"web01"}`, f)
	path := filepath.Join(t.TempDir(), "journal")
	j, err := actor.OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	b.SetJournal(j)
	for _, tc := range []struct {
		id        string
		ttl, want int64
	}{{"first", 60, 60}, {"longer", 120, 120}, {"shorter", 30, 120}} {
		o := order("block-port")
		o.ID = tc.id
		o.TTL = tc.ttl
		if _, err = b.execute(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		if got := sets["tcp"][443]; got > tc.want || got < tc.want-1 { // remaining TTL may lose a second under load
			t.Fatalf("%s shortened timeout: %v", tc.id, sets)
		}
	}
	b = build(t, `{"agent":"web01"}`, f)
	j, err = actor.OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	b.SetJournal(j)
	for _, tc := range []struct {
		id   string
		want int64
	}{{"first", 120}, {"shorter", 120}, {"longer", 0}} {
		o := order("unblock-port")
		o.RevertOf = tc.id
		msg, e := b.execute(context.Background(), o)
		if e != nil || (sets["tcp"][443] > tc.want || sets["tcp"][443] < tc.want-1) {
			t.Fatal(msg, e, sets)
		}
		if tc.want > 0 && !strings.Contains(msg, "other active orders") {
			t.Fatal(msg)
		}
	}
	// Expired holders never prevent recovery; UDP and TCP are independent.
	if err = j.Put("expired", actor.JournalEntry{Backend: b.name, Target: "web01", Action: "block-port", Expires: time.Now().Add(-time.Minute), Ports: []string{"443/tcp"}}); err != nil {
		t.Fatal(err)
	}
	if err = j.Put("udp", actor.JournalEntry{Backend: b.name, Target: "web01", Action: "block-port", Expires: time.Now().Add(time.Hour), Ports: []string{"443/udp"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = b.execute(context.Background(), order("unblock-port")); err != nil || sets["tcp"][443] != 0 {
		t.Fatal(err, sets)
	}
}

func TestServicePriorStateSurvivesRestart(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(fmt.Sprint(initial), func(t *testing.T) {
			f := newFake(t)
			active := initial
			starts := 0
			f.hook = func(c call) ([]byte, []byte, error, bool) {
				if c.program != "/usr/bin/systemctl" {
					t.Fatal(c)
				}
				switch c.args[0] {
				case "is-active":
					if active {
						return []byte("active\n"), nil, nil, true
					}
					return []byte("inactive\n"), nil, exitError(3), true
				case "stop":
					active = false
				case "start":
					active = true
					starts++
				default:
					t.Fatal(c)
				}
				return nil, nil, nil, true
			}
			b := build(t, `{"agent":"web01","services":["nginx.service"]}`, f)
			path := filepath.Join(t.TempDir(), "journal")
			j, err := actor.OpenJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			b.SetJournal(j)
			o := order("stop-service")
			o.ID = "stop"
			o.Params = map[string]any{"unit": "nginx.service"}
			if _, err = b.execute(context.Background(), o); err != nil || active {
				t.Fatal(err)
			}
			b = build(t, `{"agent":"web01","services":["nginx.service"]}`, f)
			j, err = actor.OpenJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			b.SetJournal(j)
			o.Action = "start-service"
			o.RevertOf = "stop"
			if _, err = b.execute(context.Background(), o); err != nil || active != initial || starts != map[bool]int{true: 1, false: 0}[initial] {
				t.Fatal(err, active, starts)
			}
		})
	}
}

func TestUncertainCommandsAndHostileOutput(t *testing.T) {
	for _, action := range []string{"block-port", "stop-service"} {
		t.Run(action, func(t *testing.T) {
			f := newFake(t)
			f.hook = func(c call) ([]byte, []byte, error, bool) {
				if len(c.args) > 0 && c.args[0] == "is-active" {
					return []byte("active\n"), nil, nil, true
				}
				return []byte("attacker instructions"), []byte("sensitive upstream text"), exitError(7), true
			}
			b := build(t, `{"agent":"web01","services":["nginx.service"]}`, f)
			o := order(action)
			if action == "stop-service" {
				o.Params = map[string]any{"unit": "nginx.service"}
			}
			_, err := b.execute(context.Background(), o)
			if !errors.Is(err, actor.ErrPossiblyApplied) || !strings.Contains(err.Error(), "rc 7") || strings.Contains(err.Error(), "upstream") || strings.Contains(err.Error(), "attacker") {
				t.Fatal(err)
			}
		})
	}

	f := newFake(t)
	b := build(t, `{"agent":"web01","services":["nginx.service"]}`, f)
	f.hook = func(call) ([]byte, []byte, error, bool) { return []byte("hostile"), nil, exitError(4), true }
	o := order("stop-service")
	o.Params = map[string]any{"unit": "nginx.service"}
	_, err := b.execute(context.Background(), o)
	if err == nil || errors.Is(err, actor.ErrPossiblyApplied) {
		t.Fatal(err)
	}
	f = newFake(t)
	b = build(t, `{"agent":"web01"}`, f)
	dir := filepath.Join(t.TempDir(), "state")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j, e := actor.OpenJournal(filepath.Join(dir, "journal"))
	if e != nil {
		t.Fatal(e)
	}
	b.SetJournal(j)
	if err = os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(dir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	o = order("block-port")
	o.ID = "persist-failure"
	if _, err = b.execute(context.Background(), o); err == nil || errors.Is(err, actor.ErrPossiblyApplied) || len(f.calls) != 0 {
		t.Fatal(err, f.calls)
	}

}

func TestEstablishedRuleBeforeDropsInBothChains(t *testing.T) {
	f := newFake(t)
	f.chain = chainFixture(0, 1, 2) // contains ct before drops
	b := build(t, `{"agent":"web01"}`, f)
	if err := b.ensureRules(context.Background()); err != nil || len(f.calls) != 2 {
		t.Fatal(err, f.calls)
	}
	// A late conntrack exemption must be moved before the first drop.
	f.chain = chainFixture(0, 1, 2, 3)
	// Remove the early conntrack rule, leaving only the late copy.
	var doc map[string][]json.RawMessage
	if err := json.Unmarshal([]byte(f.chain), &doc); err != nil {
		t.Fatal(err)
	}
	doc["nftables"] = append(doc["nftables"][:1], doc["nftables"][2:]...)
	data, _ := json.Marshal(doc)
	f.chain = string(data)
	f.calls = nil
	if err := b.ensureRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, chain := range []string{"input", "prerouting"} {
		found := false
		for _, c := range f.calls {
			if strings.Contains(c.stdin, "insert rule inet netnoodle "+chain+" ct state established,related accept") {
				found = true
			}
		}
		if !found {
			t.Fatalf("late conntrack exemption not repaired in %s", chain)
		}
	}
	if !b.neverBlock[22] || !b.neverBlock[7444] {
		t.Fatal("missing default management protection")
	}
}

func TestCommandSetupDoesNotExtendHolder(t *testing.T) {
	f, sets := statefulNFT(t)
	b := build(t, `{"agent":"web01"}`, f)
	// Supplying an already expired absolute deadline represents setup taking
	// longer than the holder's remaining lifetime. No block may be re-added.
	if _, err := b.changePorts(context.Background(), []port{{443, "tcp"}}, true, time.Now().Add(-time.Second)); err == nil || len(sets["tcp"]) != 0 {
		t.Fatal(err, sets)
	}
}

// Real output of nft 1.1 for `ct state established,related accept`: the
// anonymous set is a plain JSON list (found in the live test).
func TestRuleKindRealNFTJSON(t *testing.T) {
	var expr []map[string]any
	raw := `[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]`
	if err := json.Unmarshal([]byte(raw), &expr); err != nil {
		t.Fatal(err)
	}
	if ruleKind(expr) != 3 {
		t.Fatalf("ct rule from nft 1.1 not recognized: %d", ruleKind(expr))
	}
}
