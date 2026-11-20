package hostactor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/proto"
)

type port struct {
	number int
	proto  string
}

func parsePorts(value any) ([]port, error) {
	var values []string
	switch v := value.(type) {
	case []string:
		values = v
	case []any:
		if len(v) > 32 {
			return nil, errors.New("host: ports requires 1..32 entries")
		}
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, errors.New("host: ports must be strings")
			}
			values = append(values, s)
		}
	default:
		return nil, errors.New("host: ports must be a list of port/proto strings")
	}
	if len(values) == 0 || len(values) > 32 {
		return nil, errors.New("host: ports requires 1..32 entries")
	}
	result := make([]port, 0, len(values))
	seen := map[port]bool{}
	for _, value := range values {
		number, protocol, ok := strings.Cut(value, "/")
		n, err := strconv.Atoi(number)
		if !ok || err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != number || (protocol != "tcp" && protocol != "udp") {
			return nil, errors.New("host: ports must be port/tcp or port/udp with port 1..65535")
		}
		p := port{n, protocol}
		if !seen[p] {
			result = append(result, p)
			seen[p] = true
		}
	}
	return result, nil
}

// execute is portable command planning, used only by the Linux entry point
// and fake-runner tests. Validate the whole order before the first command.
func (b *Backend) execute(ctx context.Context, o proto.Order) (message string, err error) {
	sent := false
	ctx = context.WithValue(ctx, mutationKey{}, &sent)
	defer func() {
		if err != nil && sent {
			err = uncertain(err)
		}
	}()
	if len(o.Targets) != 1 || o.Targets[0].Kind != "agent" || o.Targets[0].Value != b.settings.Agent {
		return "", errors.New("host: exactly one agent target matching settings.agent is required")
	}
	switch o.Action {
	case "block-port", "unblock-port":
		ports, err := parsePorts(o.Params["ports"])
		if err != nil {
			return "", err
		}
		ttl := b.maxTTL
		if o.Action == "block-port" {
			if o.TTL < 0 {
				return "", errors.New("host: TTL must not be negative")
			}
			if o.TTL > 0 && o.TTL < ttl {
				ttl = o.TTL
			}
			for _, p := range ports {
				if b.neverBlock[p.number] {
					return "", errors.New("host: port is protected by never_block_ports")
				}
			}
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.journalPorts(ctx, o, ports, ttl)
	case "stop-service", "start-service":
		unit, ok := o.Params["unit"].(string)
		if !ok || !b.services[unit] {
			return "", errors.New("host: unit is not in services allowlist")
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		action, want := "stop", "inactive"
		if o.Action == "start-service" {
			action, want = "start", "active"
			if prior, ok := b.journal.Get(o.RevertOf, b.name, unit, "stop-service"); ok && !prior.Prior {
				return "service was inactive; left stopped", nil
			}
		} else {
			out, e := b.command(ctx, b.settings.Systemctl, []string{"is-active", unit}, "")
			var exit interface{ ExitCode() int }
			active := strings.TrimSpace(string(out)) == "active" && e == nil
			inactive := strings.TrimSpace(string(out)) == "inactive" && errors.As(e, &exit) && exit.ExitCode() == 3
			if !active && !inactive {
				return "", errors.New("host: cannot determine prior service state")
			}
			if e = b.journal.Put(o.ID, actor.JournalEntry{Backend: b.name, Target: unit, Action: o.Action, Expires: actor.OrderExpiry(o.TTL, o.NotAfter), Prior: active}); e != nil {
				return "", e
			}
		}
		if _, e := b.command(ctx, b.settings.Systemctl, []string{action, unit}, ""); e != nil {
			return "", e
		}
		out, e := b.command(ctx, b.settings.Systemctl, []string{"is-active", unit}, "")
		var exit interface{ ExitCode() int }
		inactive := want == "inactive" && errors.As(e, &exit) && exit.ExitCode() == 3
		if strings.TrimSpace(string(out)) != want || (e != nil && !inactive) {
			return "", errors.New("host: service verification failed")
		}
		return unit + " " + want + "; verified", nil
	default:
		return "", errors.New("host: unsupported action")
	}
}

func (b *Backend) script(ctx context.Context, script string) error {
	_, err := b.command(ctx, b.settings.NFT, []string{"-f", "-"}, script)
	return err
}

func (b *Backend) changePorts(ctx context.Context, ports []port, block bool, expiry time.Time) (string, error) {
	t := b.settings.Table
	// Also ensure empty sets for recovery. An expired/deleted element can
	// then be verified absent without interpreting localized ENOENT text.
	structure := fmt.Sprintf("add table inet %s\nadd set inet %s blocked_tcp { type inet_service; flags timeout; }\nadd set inet %s blocked_udp { type inet_service; flags timeout; }\nadd chain inet %s input { type filter hook input priority -10; policy accept; }\nadd chain inet %s prerouting { type filter hook prerouting priority -150; policy accept; }\n", t, t, t, t, t)
	if err := b.script(ctx, structure); err != nil {
		return "", err
	}
	if block {
		if err := b.ensureRules(ctx); err != nil {
			return "", err
		}
		var script strings.Builder
		for _, p := range ports {
			exists, e := b.portExists(ctx, p)
			if e != nil {
				return "", e
			}
			if exists {
				fmt.Fprintf(&script, "delete element inet %s blocked_%s { %d }\n", t, p.proto, p.number)
			}
		}
		// nft accepts relative timeouts. Compute the remaining lifetime after
		// discovery so command setup (and preceding ports) cannot extend a holder.
		ttl := int64(math.Ceil(time.Until(expiry).Seconds()))
		if ttl <= 0 {
			return "", errors.New("host: port holder expired before update")
		}
		for _, p := range ports {
			fmt.Fprintf(&script, "add element inet %s blocked_%s { %d timeout %ds }\n", t, p.proto, p.number, ttl)
		}
		if err := b.script(ctx, script.String()); err != nil {
			return "", err
		}
		for _, protocol := range []string{"tcp", "udp"} {
			var requested []port
			for _, p := range ports {
				if p.proto == protocol {
					requested = append(requested, p)
				}
			}
			if len(requested) > 0 {
				if err := b.verifyPorts(ctx, requested, true, ttl); err != nil {
					return "", err
				}
			}
		}
	} else {
		for _, p := range ports {
			err := b.script(ctx, fmt.Sprintf("delete element inet %s blocked_%s { %d }\n", t, p.proto, p.number))
			// Missing elements abort nft batches, so delete independently and
			// verify absence even on errors. Never hide a still-blocked port.
			if verify := b.verifyPorts(ctx, []port{p}, false, 0); verify != nil {
				return "", errors.Join(err, verify)
			}
		}
	}
	state := "unblocked"
	if block {
		state = "blocked"
	}
	return "ports " + state + "; verified", nil
}

func (b *Backend) journalPorts(ctx context.Context, o proto.Order, ports []port, ttl int64) (string, error) {
	now := time.Now()
	if o.Action == "block-port" {
		values := []string{}
		for _, p := range ports {
			values = append(values, strconv.Itoa(p.number)+"/"+p.proto)
		}
		if err := b.journal.Put(o.ID, actor.JournalEntry{Backend: b.name, Target: b.settings.Agent, Action: o.Action, Expires: now.Add(time.Duration(ttl) * time.Second), Ports: values}); err != nil {
			return "", err
		}
	} else {
		prior, ok := b.journal.Get(o.RevertOf, b.name, b.settings.Agent, "block-port")
		if ok {
			prior.Released = true
			if err := b.journal.Put(o.RevertOf, prior); err != nil {
				return "", err
			}
		}
	}
	held := false
	for _, p := range ports {
		latest := time.Time{}
		for _, entry := range b.journal.Entries() {
			if entry.Backend != b.name || entry.Target != b.settings.Agent || entry.Action != "block-port" || entry.Released || !entry.Expires.After(now) {
				continue
			}
			for _, value := range entry.Ports {
				if value == strconv.Itoa(p.number)+"/"+p.proto && entry.Expires.After(latest) {
					latest = entry.Expires
				}
			}
		}
		block := o.Action == "block-port" || !latest.IsZero()
		if latest.IsZero() && block {
			latest = now.Add(time.Duration(ttl) * time.Second)
		}
		if block && o.Action == "unblock-port" {
			held = true
		}
		if _, err := b.changePorts(ctx, []port{p}, block, latest); err != nil {
			return "", err
		}
	}
	if held {
		return "ports retained for other active orders; verified", nil
	}
	if o.Action == "block-port" {
		return "ports blocked; verified", nil
	}
	return "ports unblocked; verified", nil
}
