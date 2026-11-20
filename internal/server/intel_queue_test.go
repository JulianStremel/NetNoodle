package server

import (
	"testing"

	"github.com/JulianStremel/netnoodle/internal/intel"
)

// TestMatchQueueKeepsEveryDevice: the match queue has no fixed size and
// holds each device once (security review 2026-11-20).
func TestMatchQueueKeepsEveryDevice(t *testing.T) {
	in := newIntelState()
	in.matchers = []intel.Matcher{&fakeMatcher{}}
	s := &Server{intel: in}
	ids := make([]int64, 10000)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	s.enqueueMatch(ids...)
	s.enqueueMatch(ids...) // duplicates are ignored
	if len(in.queue) != len(ids) {
		t.Fatal(len(in.queue))
	}
	for want := int64(1); want <= int64(len(ids)); want++ {
		if id, ok := in.nextMatch(); !ok || id != want {
			t.Fatal(id, ok, want)
		}
	}
	if _, ok := in.nextMatch(); ok || len(in.pending) != 0 {
		t.Fatal("queue not empty")
	}
}
