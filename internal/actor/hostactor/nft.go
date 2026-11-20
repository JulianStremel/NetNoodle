package hostactor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

type nftIdentity struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
}

type nftRule struct {
	nftIdentity
	Chain  string           `json:"chain"`
	Handle uint64           `json:"handle"`
	Expr   []map[string]any `json:"expr"`
}

type nftSet struct {
	nftIdentity
	Type    string            `json:"type"`
	Flags   []string          `json:"flags"`
	Timeout uint64            `json:"timeout"`
	Elem    []json.RawMessage `json:"elem"`
}

type nftDocument struct {
	Nftables []struct {
		Chain *nftIdentity `json:"chain"`
		Rule  *nftRule     `json:"rule"`
		Set   *nftSet      `json:"set"`
	} `json:"nftables"`
}

func (b *Backend) list(ctx context.Context, kind, name string) (*nftDocument, error) {
	out, err := b.command(ctx, b.settings.NFT, []string{"-j", "list", kind, "inet", b.settings.Table, name}, "")
	if err != nil {
		return nil, err
	}
	var doc nftDocument
	if json.Unmarshal(out, &doc) != nil || doc.Nftables == nil {
		return nil, errors.New("host: invalid nft JSON")
	}
	return &doc, nil
}

var ruleExpressions = []string{
	`[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"accept":null}]`,
	`[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":"@blocked_tcp"}},{"drop":null}]`,
	`[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":"@blocked_udp"}},{"drop":null}]`,
	`[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":{"set":["established","related"]}}},{"accept":null}]`,
}

// Match full rule semantics rather than comments or string fragments. Counters
// do not change a rule's match or verdict; additional conditions do.
func ruleKind(expr []map[string]any) int {
	var statements []map[string]any
	for _, statement := range expr {
		if _, counter := statement["counter"]; counter && len(statement) == 1 {
			continue
		}
		statements = append(statements, statement)
	}
	if len(statements) != 2 {
		return -1
	}
	for i, raw := range ruleExpressions {
		var expected []map[string]any
		_ = json.Unmarshal([]byte(raw), &expected)
		if reflect.DeepEqual(statements, expected) {
			return i
		}
		// nft 1.x renders an anonymous set as a plain list
		// ("right":["established","related"]), older versions as {"set":[...]}.
		if m, ok := expected[0]["match"].(map[string]any); ok {
			if right, ok := m["right"].(map[string]any); ok && right["set"] != nil {
				set := right["set"]
				alt := []map[string]any{{"match": map[string]any{"op": m["op"], "left": m["left"], "right": set}}, expected[1]}
				if reflect.DeepEqual(statements, alt) {
					return i
				}
			}
		}
		// nft versions may render named set membership as "in".
		if i > 0 {
			expected[0]["match"].(map[string]any)["op"] = "in"
			if reflect.DeepEqual(statements, expected) {
				return i
			}
		}
	}
	return -1
}

func (b *Backend) ensureRules(ctx context.Context) error {
	for _, chain := range []string{"input", "prerouting"} {
		if err := b.ensureChainRules(ctx, chain); err != nil {
			return err
		}
	}
	return nil
}
func (b *Backend) ensureChainRules(ctx context.Context, chain string) error {
	doc, err := b.list(ctx, "chain", chain)
	if err != nil {
		return err
	}
	var found [4]bool
	chainFound, dropSeen := false, false
	var script strings.Builder
	for _, entry := range doc.Nftables {
		if c := entry.Chain; c != nil && c.Family == "inet" && c.Table == b.settings.Table && c.Name == chain {
			chainFound = true
		}
		r := entry.Rule
		if r == nil || r.Family != "inet" || r.Table != b.settings.Table || r.Chain != chain {
			continue
		}
		kind := ruleKind(r.Expr)
		if kind < 0 {
			continue
		}
		// Remove duplicate rules, and move a late loopback exemption ahead
		// of the drops. Never flush a chain or touch another table.
		if found[kind] || ((kind == 0 || kind == 3) && dropSeen) {
			if r.Handle == 0 {
				return errors.New("host: nft rule to repair has no handle")
			}
			fmt.Fprintf(&script, "delete rule inet %s %s handle %d\n", b.settings.Table, chain, r.Handle)
			continue
		}
		found[kind] = true
		if kind == 1 || kind == 2 {
			dropSeen = true
		}
	}
	if !chainFound {
		return errors.New("host: nft response is missing the requested chain")
	}
	if !found[0] {
		fmt.Fprintf(&script, "insert rule inet %s %s iifname \"lo\" accept\n", b.settings.Table, chain)
	}
	if !found[3] {
		fmt.Fprintf(&script, "insert rule inet %s %s ct state established,related accept\n", b.settings.Table, chain)
	}
	for i, protocol := range []string{"tcp", "udp"} {
		if !found[i+1] {
			fmt.Fprintf(&script, "add rule inet %s %s %s dport @blocked_%s drop\n", b.settings.Table, chain, protocol, protocol)
		}
	}
	if script.Len() > 0 {
		return b.script(ctx, script.String())
	}
	return nil
}

func (b *Backend) verifyPorts(ctx context.Context, ports []port, blocked bool, ttl int64) error {
	name := "blocked_" + ports[0].proto
	doc, err := b.list(ctx, "set", name)
	if err != nil {
		return fmt.Errorf("host: port verification failed: %w", err)
	}
	var set *nftSet
	for _, entry := range doc.Nftables {
		if s := entry.Set; s != nil && s.Family == "inet" && s.Table == b.settings.Table && s.Name == name {
			if set != nil {
				return errors.New("host: port verification failed: ambiguous set")
			}
			set = s
		}
	}
	if set == nil || set.Type != "inet_service" {
		return errors.New("host: port verification failed: missing or invalid set")
	}
	elements := map[int]uint64{}
	for _, raw := range set.Elem {
		var n int
		timeout := set.Timeout
		if json.Unmarshal(raw, &n) != nil {
			var wrapped struct {
				Elem *struct {
					Val     int     `json:"val"`
					Timeout *uint64 `json:"timeout"`
				} `json:"elem"`
			}
			if json.Unmarshal(raw, &wrapped) != nil || wrapped.Elem == nil {
				return errors.New("host: port verification failed: invalid set element")
			}
			n = wrapped.Elem.Val
			if wrapped.Elem.Timeout != nil {
				timeout = *wrapped.Elem.Timeout
			}
		}
		if n < 1 || n > 65535 {
			return errors.New("host: port verification failed: invalid port")
		}
		elements[n] = timeout
	}
	for _, p := range ports {
		timeout, exists := elements[p.number]
		if exists != blocked {
			return fmt.Errorf("host: port verification failed for %d/%s", p.number, p.proto)
		}
		if blocked && (!slices.Contains(set.Flags, "timeout") || timeout == 0 || timeout != uint64(ttl)) {
			return fmt.Errorf("host: port verification failed: missing or incorrect timeout for %d/%s", p.number, p.proto)
		}
	}
	return nil
}

func (b *Backend) portExists(ctx context.Context, p port) (bool, error) {
	doc, err := b.list(ctx, "set", "blocked_"+p.proto)
	if err != nil {
		return false, err
	}
	for _, entry := range doc.Nftables {
		if set := entry.Set; set != nil && set.Family == "inet" && set.Table == b.settings.Table && set.Name == "blocked_"+p.proto {
			for _, raw := range set.Elem {
				var n int
				if json.Unmarshal(raw, &n) != nil {
					var wrapped struct {
						Elem struct {
							Val int `json:"val"`
						} `json:"elem"`
					}
					if json.Unmarshal(raw, &wrapped) != nil {
						return false, errors.New("host: invalid set element")
					}
					n = wrapped.Elem.Val
				}
				if n == p.number {
					return true, nil
				}
			}
			return false, nil
		}
	}
	return false, errors.New("host: missing port set")
}
