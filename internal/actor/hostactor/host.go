// Package hostactor implements locally scoped host actions for nn-actor.
// Only Linux can execute orders; the portable command planning code is also
// exercised with a fake Runner on other operating systems.
package hostactor

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

const commandTimeout = 15 * time.Second
const maxOutput = 1 << 20

var tableName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
var serviceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@:\\-]*\.service$`)

// Settings bind this backend to this host's agent peer name. Empty Services
// refuses both service actions. NeverBlockPorts defaults to [22, 7443, 7444]
// (SSH, server, pull agent). An explicit empty array is refused unless
// AllowEmptyNeverBlockPorts is set (security review 2026-11-20).
type Settings struct {
	Agent           string   `json:"agent"`
	NFT             string   `json:"nft"`
	Table           string   `json:"table"`
	MaxTTL          string   `json:"max_ttl"`
	NeverBlockPorts []int    `json:"never_block_ports"`
	Services        []string `json:"services"`
	Systemctl       string   `json:"systemctl"`
	// AllowEmptyNeverBlockPorts permits never_block_ports: [] (no protected port).
	AllowEmptyNeverBlockPorts bool `json:"allow_empty_never_block_ports"`
}

// Runner executes one program directly, without a shell. Implementations must
// honor ctx and bound each output stream to maxOutput bytes. Nonzero exits
// return an error (which may implement ExitCode() int, as exec.ExitError does).
type Runner interface {
	Run(ctx context.Context, program string, args []string, stdin string) (stdout, stderr []byte, err error)
}

type Backend struct {
	name       string
	settings   Settings
	maxTTL     int64 // seconds, rounded down so the configured cap is never exceeded
	neverBlock map[int]bool
	services   map[string]bool
	runner     Runner
	journal    *actor.Journal
	mu         sync.Mutex // serialize rule discovery and creation
}

func init() { actor.Registry.Register("host", New) }

// New validates settings without invoking nft or systemctl.
func New(name string, raw json.RawMessage) (actor.Backend, error) {
	return NewWithRunner(name, raw, nativeRunner())
}

// NewWithRunner supports testing command planning without host privileges.
// Execute still refuses every order on non-Linux platforms.
func NewWithRunner(name string, raw json.RawMessage, runner Runner) (*Backend, error) {
	s := Settings{NFT: "/usr/sbin/nft", Table: "netnoodle", MaxTTL: "24h", Systemctl: "/usr/bin/systemctl", NeverBlockPorts: []int{22, 7443, 7444}}
	if !json.Valid(raw) || registry.Decode(raw, &s) != nil || strings.TrimSpace(s.Agent) == "" || strings.ContainsAny(s.Agent, "\x00\r\n") {
		return nil, errors.New("host: invalid settings (agent is required; malformed JSON or unknown fields refused)")
	}
	// null is not an explicit empty allow/protection list.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for key, value := range fields {
		if string(value) == "null" {
			return nil, errors.New("host: settings must not be null: " + key)
		}
	}
	for _, executable := range []string{s.NFT, s.Systemctl} {
		// Use POSIX paths even when validating a Linux config on Windows.
		if !path.IsAbs(executable) || strings.ContainsAny(executable, "\x00\r\n") {
			return nil, errors.New("host: nft and systemctl must be absolute paths")
		}
	}
	if !tableName.MatchString(s.Table) {
		return nil, errors.New("host: table must match [a-z][a-z0-9_]{0,31}")
	}
	ttl, err := time.ParseDuration(s.MaxTTL)
	if err != nil || ttl < time.Second {
		return nil, errors.New("host: max_ttl must be a duration of at least one second")
	}
	if len(s.NeverBlockPorts) == 0 && !s.AllowEmptyNeverBlockPorts {
		return nil, errors.New("host: never_block_ports must protect management ports (SSH, server); explicitly set allow_empty_never_block_ports to override")
	}
	protected := make(map[int]bool, len(s.NeverBlockPorts))
	for _, port := range s.NeverBlockPorts {
		if port < 1 || port > 65535 {
			return nil, errors.New("host: never_block_ports must contain ports 1..65535")
		}
		protected[port] = true
	}
	services := make(map[string]bool, len(s.Services))
	for _, unit := range s.Services {
		if !serviceName.MatchString(unit) {
			return nil, errors.New("host: services must contain literal .service unit names")
		}
		services[unit] = true
	}
	if runner == nil {
		return nil, errors.New("host: command runner is required")
	}
	return &Backend{name: name, settings: s, maxTTL: int64(ttl / time.Second), neverBlock: protected, services: services, runner: runner, journal: &actor.Journal{}}, nil
}

func (b *Backend) SetJournal(j *actor.Journal) { b.journal = j }

func (b *Backend) Name() string { return b.name }

func (b *Backend) Capabilities() []proto.Capability {
	return []proto.Capability{
		{Action: "block-port", TargetIDKinds: []string{"agent"}, TargetScope: []string{"agent=" + b.settings.Agent}, Reversible: true, RevertAction: "unblock-port"},
		{Action: "unblock-port", TargetIDKinds: []string{"agent"}, TargetScope: []string{"agent=" + b.settings.Agent}},
		{Action: "stop-service", TargetIDKinds: []string{"agent"}, TargetScope: []string{"agent=" + b.settings.Agent}, Reversible: true, RevertAction: "start-service"},
		{Action: "start-service", TargetIDKinds: []string{"agent"}, TargetScope: []string{"agent=" + b.settings.Agent}},
	}
}
