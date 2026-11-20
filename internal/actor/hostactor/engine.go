package hostactor

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

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
func (b *Backend) execute(ctx context.Context, o proto.Order) (string, error) {
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
		return b.changePorts(ctx, ports, o.Action == "block-port", ttl)
	case "stop-service", "start-service":
		unit, ok := o.Params["unit"].(string)
		if !ok || !b.services[unit] {
			return "", errors.New("host: unit is not in services allowlist")
		}
		action, want := "stop", "inactive"
		if o.Action == "start-service" {
			action, want = "start", "active"
		}
		if _, err := b.command(ctx, b.settings.Systemctl, []string{action, unit}, ""); err != nil {
			return "", err
		}
		out, err := b.command(ctx, b.settings.Systemctl, []string{"is-active", unit}, "")
		// systemctl is-active returns 3 for a known inactive service. Other
		// errors (including a missing unit, exit 4) must never verify a stop.
		var exit interface{ ExitCode() int }
		inactive := want == "inactive" && errors.As(err, &exit) && exit.ExitCode() == 3
		if strings.TrimSpace(string(out)) != want || (err != nil && !inactive) {
			if err != nil {
				return "", fmt.Errorf("host: service verification failed: %w", err)
			}
			return "", errors.New("host: service verification failed: unexpected state")
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

func (b *Backend) changePorts(ctx context.Context, ports []port, block bool, ttl int64) (string, error) {
	t := b.settings.Table
	// Also ensure empty sets for recovery. An expired/deleted element can
	// then be verified absent without interpreting localized ENOENT text.
	structure := fmt.Sprintf("add table inet %s\nadd set inet %s blocked_tcp { type inet_service; flags timeout; }\nadd set inet %s blocked_udp { type inet_service; flags timeout; }\nadd chain inet %s input { type filter hook input priority -10; policy accept; }\n", t, t, t, t)
	if err := b.script(ctx, structure); err != nil {
		return "", err
	}
	if block {
		if err := b.ensureRules(ctx); err != nil {
			return "", err
		}
		var script strings.Builder
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
