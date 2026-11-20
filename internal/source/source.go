// Package source defines in-process discovery sources: programs inside the
// server that pull data from an API (UniFi, Proxmox, ...) on a timer.
//
// Out-of-process sources (nn-scan, nn-agent, third-party programs) do not
// use this package. They POST the same proto.Observation to /v1/observations.
package source

import (
	"context"

	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/registry"
)

// Source produces observations. Poll is called once per poll interval and
// returns when the poll is finished. emit may be called many times.
type Source interface {
	Name() string
	Poll(ctx context.Context, emit func(proto.Observation) error) error
}

// Registry holds all source types. Implementations register in init().
var Registry = registry.New[Source]("source")
