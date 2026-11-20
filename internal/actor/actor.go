// Package actor defines Go actor backends for the nn-actor program.
// Each backend wraps one external system (UniFi, Proxmox, ...) and
// announces what it can do as proto.Capability values. The server picks a
// backend only through those capabilities, so a new backend needs no change
// in the server.
package actor

import (
	"context"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

// Backend executes verified orders. The nn-actor program checks the
// signature, expiry, nonce and local allowlist before it calls Execute.
type Backend interface {
	Name() string
	Capabilities() []proto.Capability
	Execute(ctx context.Context, o proto.Order) (message string, err error)
}

var Registry = registry.New[Backend]("actor backend")
