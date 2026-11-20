package actor

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JulianStremel/netnoodle/internal/client"
	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

type AllowRule struct {
	Action  string   `json:"action"`
	Targets []string `json:"targets"`
}
type Config struct {
	Credentials string          `json:"credentials"`
	NonceFile   string          `json:"nonce_file"`
	DryRun      *bool           `json:"dry_run,omitempty"`
	MaxPerHour  int             `json:"max_per_hour,omitempty"`
	Backends    []registry.Spec `json:"backends"`
	Allow       []AllowRule     `json:"allow"`
}
type Runner struct {
	Name       string
	Key        ed25519.PublicKey
	Nonces     *orders.NonceStore
	Backends   []Backend
	Allow      []AllowRule
	DryRun     bool
	MaxPerHour int
	Now        func() time.Time
	executed   []time.Time
	outbox     *resultOutbox
	Journal    *Journal
}

// maxOrderLife is the longest order validity the actor accepts.
const maxOrderLife = time.Hour

func NewRunner(cfg Config, creds client.Credentials) (*Runner, error) {
	if creds.Role != "actor" {
		return nil, errors.New("credentials must have role actor")
	}
	key, e := base64.StdEncoding.DecodeString(creds.OrderKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("missing or invalid pinned order key; enroll again")
	}
	if cfg.MaxPerHour < 0 {
		return nil, errors.New("max_per_hour must be positive")
	}
	if cfg.MaxPerHour == 0 {
		cfg.MaxPerHour = 20
	}
	if cfg.NonceFile == "" {
		cfg.NonceFile = "nn-actor-nonces.json"
	}
	for _, r := range cfg.Allow {
		for _, p := range r.Targets {
			k, v, ok := strings.Cut(p, "=")
			if !ok || k == "" || v == "" {
				return nil, fmt.Errorf("invalid allow target %q", p)
			}
			if _, e := path.Match(v, ""); e != nil {
				return nil, e
			}
		}
	}
	ns, e := orders.OpenNonceStore(cfg.NonceFile)
	if e != nil {
		return nil, e
	}
	bs, e := registry.BuildAll(Registry, cfg.Backends)
	if e != nil {
		return nil, e
	}
	if e = validateRevertAllow(cfg.Allow, bs); e != nil {
		return nil, e
	}
	journal, e := OpenJournal(cfg.NonceFile + ".journal")
	if e != nil {
		return nil, e
	}
	for _, b := range bs {
		if aware, ok := b.(JournalAware); ok {
			aware.SetJournal(journal)
		}
	}
	outbox, e := openOutbox(cfg.NonceFile + ".outbox")
	if e != nil {
		return nil, e
	}
	return &Runner{outbox: outbox, Journal: journal, Name: creds.Name, Key: key, Nonces: ns, Backends: bs, Allow: cfg.Allow, DryRun: cfg.DryRun == nil || *cfg.DryRun, MaxPerHour: cfg.MaxPerHour, Now: time.Now}, nil
}
func (r *Runner) allowed(o proto.Order) bool {
	if len(o.Targets) == 0 {
		return false
	}
	for _, t := range o.Targets {
		if t.Value == "" {
			return false
		}
		ok := false
		for _, rule := range r.Allow {
			if rule.Action != o.Action {
				continue
			}
			for _, p := range rule.Targets {
				k, v, found := strings.Cut(p, "=")
				if !found || k != t.Kind {
					continue
				}
				match, e := path.Match(v, t.Value)
				if e == nil && match {
					ok = true
				}
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Handle is called serially by Run. Only a verified, fresh, locally permitted
// order can reach a backend. Only configured inverse actions marked Revert
// bypass the hourly rate limit.
func (r *Runner) Handle(ctx context.Context, env orders.Envelope) (res proto.OrderResult) {
	defer func() { res.Message = truncateMessage(res.Message) }()
	now := r.Now()
	res = proto.OrderResult{Version: proto.Version, Status: proto.OrderRejected, At: now}
	o, e := orders.Verify(r.Key, env)
	if e != nil {
		var id struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(env.Payload, &id)
		res.OrderID = id.ID
		res.Message = e.Error()
		return res
	}
	res.OrderID = o.ID
	reject := func(msg string) proto.OrderResult { res.Message = msg; return res }
	if o.Actor != r.Name {
		return reject("wrong actor")
	}
	if !o.NotAfter.After(now) {
		return reject("order expired")
	}
	// The server gives 10 minutes. A far expiry would widen the replay
	// window and keep nonces for a long time.
	if o.NotAfter.After(now.Add(maxOrderLife)) {
		return reject("order expiry too far in the future")
	}
	if o.ID == "" || o.TTL < 0 {
		return reject("invalid order")
	}
	if e = r.Nonces.Use(o.Nonce, o.NotAfter, now); e != nil {
		return reject(e.Error())
	}
	if !r.allowed(o) {
		return reject("action or target denied by allow list")
	}
	var backend Backend
	for _, b := range r.Backends {
		for _, c := range b.Capabilities() {
			if c.Action != o.Action {
				continue
			}
			ok := true
			for _, t := range o.Targets {
				if !slices.Contains(c.TargetIDKinds, t.Kind) || !matchesScope(c.TargetScope, t) {
					ok = false
				}
			}
			if ok {
				backend = b
				break
			}
		}
		if backend != nil {
			break
		}
	}
	if backend == nil {
		return reject("no backend for action and targets")
	}
	validRevert := false
	for _, b := range r.Backends {
		for _, c := range b.Capabilities() {
			if c.RevertAction != "" && c.RevertAction == o.Action {
				validRevert = true
			}
		}
	}
	if o.Revert && !validRevert {
		return reject("invalid revert action")
	}
	exempt := o.Revert && validRevert
	keep := r.executed[:0]
	for _, at := range r.executed {
		if at.After(now.Add(-time.Hour)) {
			keep = append(keep, at)
		}
	}
	r.executed = keep
	if !exempt && len(r.executed) >= r.MaxPerHour {
		return reject("hourly rate limit exceeded")
	}
	if !exempt {
		r.executed = append(r.executed, now)
	}
	res.Status = proto.OrderDone
	if r.DryRun {
		res.Message = fmt.Sprintf("dry run: would %s %v", o.Action, o.Targets)
		return res
	}
	res.Message, e = executeSafe(ctx, backend, o)
	if e != nil {
		res.Status = proto.OrderFailed
		res.Message = e.Error()
		if errors.Is(e, ErrPossiblyApplied) {
			res.Status = proto.OrderUncertain
			res.Message = "possibly applied: " + e.Error()
		}
	}
	return res
}
func executeSafe(ctx context.Context, b Backend, o proto.Order) (msg string, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("backend panic: %v", p)
		}
	}()
	return b.Execute(ctx, o)
}

type Protocol interface {
	Do(context.Context, string, string, any, any) error
}

func (r *Runner) Run(ctx context.Context, c Protocol) error {
	caps := []proto.Capability{}
	for _, b := range r.Backends {
		caps = append(caps, b.Capabilities()...)
	}
	if len(caps) > 64 {
		return errors.New("backends advertise more than 64 capabilities")
	}
	if e := r.outbox.flush(ctx, c); e != nil {
		return e
	}
	hello := proto.ActorHello{Version: proto.Version, Actor: r.Name, Capabilities: caps}
	for {
		if e := c.Do(ctx, "POST", "/v1/actor/hello", hello, nil); e != nil {
			if e = retryActor(ctx, e); e != nil {
				return e
			}
			continue
		}
		for {
			if e := r.outbox.flush(ctx, c); e != nil {
				return e
			}
			var envs []orders.Envelope
			if e := c.Do(ctx, "GET", "/v1/orders?wait=25", nil, &envs); e != nil {
				if e = retryActor(ctx, e); e != nil {
					return e
				}
				break
			}
			for _, env := range envs {
				// Never replace a persisted result with a replay rejection.
				if o, e := orders.Verify(r.Key, env); e == nil && r.outbox.contains(o.ID) {
					continue
				}
				res := r.Handle(ctx, env)

				if e := r.outbox.add(res); e != nil {
					return e
				}
				if e := r.outbox.flush(ctx, c); e != nil {
					return e
				}
			}
		}
	}
}
func retryActor(ctx context.Context, err error) error {
	slog.Warn("actor connection", "err", err)
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Every forward pattern must also be covered by a permission for its inverse.
func validateRevertAllow(rules []AllowRule, bs []Backend) error {
	for _, b := range bs {
		for _, c := range b.Capabilities() {
			if c.RevertAction == "" {
				continue
			}
			for _, rule := range rules {
				if rule.Action != c.Action {
					continue
				}
				for _, target := range rule.Targets {
					covered := false
					for _, inverse := range rules {
						if inverse.Action == c.RevertAction {
							for _, pattern := range inverse.Targets {
								if coversTarget(pattern, target) {
									covered = true
								}
							}
						}
					}
					if !covered {
						return fmt.Errorf("allow %s target %q requires the same target for revert action %s", c.Action, target, c.RevertAction)
					}
				}
			}
		}
	}
	return nil
}

// Exact patterns, literal targets and broader simple prefix globs can be proven
// to cover a rule without sampling target values. Complex globs require the
// identical pattern, so validation fails closed for ambiguous containment.
func coversTarget(inverse, forward string) bool {
	if inverse == forward {
		return true
	}
	ik, iv, iok := strings.Cut(inverse, "=")
	fk, fv, fok := strings.Cut(forward, "=")
	if !iok || !fok || ik != fk {
		return false
	}
	if !strings.ContainsAny(fv, "*?[\\") {
		matched, e := path.Match(iv, fv)
		return e == nil && matched
	}
	if !strings.HasSuffix(iv, "*") {
		return false
	}
	prefix := strings.TrimSuffix(iv, "*")
	return !strings.ContainsAny(prefix, "*?[\\") && !strings.ContainsAny(fv, "?[\\") && strings.HasPrefix(fv, prefix) && !strings.Contains(strings.TrimPrefix(fv, prefix), "/")
}

// Scope globs use path.Match; a trailing /* covers the whole identifier subtree
// (including source/cluster/vmid). Empty scope preserves v1's unrestricted scope.
func matchesScope(patterns []string, t proto.Identifier) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		kind, glob, ok := strings.Cut(pattern, "=")
		if !ok || kind != t.Kind {
			continue
		}
		if matched, err := path.Match(glob, t.Value); err == nil && matched {
			return true
		}
		if strings.HasSuffix(glob, "/*") && !strings.ContainsAny(strings.TrimSuffix(glob, "/*"), "*?[\\") && strings.HasPrefix(t.Value, strings.TrimSuffix(glob, "*")) {
			return true
		}
	}
	return false
}
func truncateMessage(s string) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= 4000 {
		return s
	}
	n := 4000
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
