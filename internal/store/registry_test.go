package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
)

var backendSequence atomic.Uint64

func TestRegistryOpenerArguments(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{}{}, "context")
	sentinel := errors.New("opener error")
	name := fmt.Sprintf("contract-arguments-%d", backendSequence.Add(1))
	store.Register(name, func(got context.Context, dir string, settings json.RawMessage) (store.Store, error) {
		if got != ctx || dir != "data-dir" || string(settings) != `{"custom":true}` {
			t.Errorf("opener arguments: %v %q %s", got, dir, settings)
		}
		return nil, sentinel
	})
	_, err := store.Open(ctx, registry.Spec{Type: name, Settings: json.RawMessage(`{"custom":true}`)}, "data-dir")
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "contract-arguments") {
		t.Fatal(err)
	}
}

func TestRegistryUnknownBackend(t *testing.T) {
	_, err := store.Open(context.Background(), registry.Spec{Type: "missing-backend"}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), `store: unknown type "missing-backend"`) {
		t.Fatal(err)
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	opener := func(context.Context, string, json.RawMessage) (store.Store, error) { return nil, nil }
	name := fmt.Sprintf("contract-duplicate-%d", backendSequence.Add(1))
	store.Register(name, opener)
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate backend did not panic")
		}
	}()
	store.Register(name, opener)
}
