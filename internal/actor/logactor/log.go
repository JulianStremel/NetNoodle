// Package logactor implements a backend that only logs verified orders.
package logactor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	"github.com/JulianStremel/netnoodle/internal/actor"
	"github.com/JulianStremel/netnoodle/internal/decide"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

type Backend struct {
	name  string
	kinds []string
}

func init() {
	actor.Registry.Register("log", func(name string, raw json.RawMessage) (actor.Backend, error) {
		cfg := struct {
			TargetIDKinds []string `json:"target_id_kinds"`
		}{[]string{"mac", "ip", "agent", "proxmox.guest"}}
		if e := registry.Decode(raw, &cfg); e != nil {
			return nil, e
		}
		if len(cfg.TargetIDKinds) == 0 || len(cfg.TargetIDKinds) > 16 {
			return nil, fmt.Errorf("log: require 1 to 16 target kinds")
		}
		return &Backend{name, cfg.TargetIDKinds}, nil
	})
}
func (b *Backend) Name() string { return b.name }
func (b *Backend) Capabilities() []proto.Capability {
	pairs := map[string]string{"isolate": "unisolate", "block-port": "unblock-port", "stop-service": "start-service"}
	out := []proto.Capability{}
	for _, a := range decide.KnownActions {
		r := pairs[a]
		out = append(out, proto.Capability{Action: a, TargetIDKinds: slices.Clone(b.kinds), Reversible: r != "", RevertAction: r})
		if r != "" {
			out = append(out, proto.Capability{Action: r, TargetIDKinds: slices.Clone(b.kinds), Reversible: true, RevertAction: a})
		}
	}
	return out
}
func (b *Backend) Execute(ctx context.Context, o proto.Order) (string, error) {
	msg := fmt.Sprintf("log: %s %v", o.Action, o.Targets)
	slog.InfoContext(ctx, msg, "backend", b.name, "order", o.ID)
	return msg, nil
}
