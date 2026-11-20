//go:build !linux

package hostactor

import (
	"context"
	"errors"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

func (b *Backend) Execute(context.Context, proto.Order) (string, error) {
	return "", errors.New("host: orders require Linux")
}

type unsupportedRunner struct{}

func nativeRunner() Runner { return unsupportedRunner{} }

func (unsupportedRunner) Run(context.Context, string, []string, string) ([]byte, []byte, error) {
	return nil, nil, errors.New("host: commands require Linux")
}
