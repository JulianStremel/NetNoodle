//go:build linux

package hostactor

import (
	"context"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

func (b *Backend) Execute(ctx context.Context, o proto.Order) (string, error) {
	return b.execute(ctx, o)
}
