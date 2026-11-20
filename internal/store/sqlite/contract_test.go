package sqlite_test

import (
	"context"
	"testing"

	"github.com/JulianStremel/netnoodle/internal/registry"
	"github.com/JulianStremel/netnoodle/internal/store"
	_ "github.com/JulianStremel/netnoodle/internal/store/sqlite"
	"github.com/JulianStremel/netnoodle/internal/store/storetest"
)

func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		t.Helper()
		st, err := store.Open(context.Background(), registry.Spec{Type: "sqlite"}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := st.Close(); err != nil {
				t.Error(err)
			}
		})
		return st
	})
}
