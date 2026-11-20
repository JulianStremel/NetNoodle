package actor

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/orders"
)

// ErrPossiblyApplied means a mutating request was sent but its outcome could
// not be confirmed. Callers must preserve it when adding diagnostic context.
var ErrPossiblyApplied = errors.New("mutation outcome uncertain")

// JournalAware receives the runner's durable prior-state journal before use.
type JournalAware interface{ SetJournal(*Journal) }

// JournalEntry records intent BEFORE mutation, including state needed by a
// later revert. Backend and Target bind RevertOf to the original resource.
type JournalEntry struct {
	Backend   string    `json:"backend"`
	Target    string    `json:"target"`
	Action    string    `json:"action"`
	Expires   time.Time `json:"expires"`
	Prior     bool      `json:"prior,omitempty"`
	PriorDown []string  `json:"prior_down,omitempty"`
	Changed   []string  `json:"changed,omitempty"`
	Ports     []string  `json:"ports,omitempty"`
	Released  bool      `json:"released,omitempty"`
}

// Journal's zero value is an in-memory journal for standalone backend tests.
// Production runners always open a file next to the nonce store.
type Journal struct {
	mu      sync.Mutex
	path    string
	entries map[string]JournalEntry
}

func OpenJournal(path string) (*Journal, error) {
	j := &Journal{path: path, entries: map[string]JournalEntry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(b, &j.entries) != nil || j.entries == nil {
		return nil, errors.New("invalid actor journal")
	}
	// Persist pruning on open as well as on every update.
	if err := j.Put("", JournalEntry{}); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *Journal) Entries() map[string]JournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	result := make(map[string]JournalEntry, len(j.entries))
	for id, e := range j.entries {
		e.PriorDown = append([]string(nil), e.PriorDown...)
		e.Changed = append([]string(nil), e.Changed...)
		e.Ports = append([]string(nil), e.Ports...)
		result[id] = e
	}
	return result
}

func (j *Journal) Get(id, backend, target, action string) (JournalEntry, bool) {
	e, ok := j.Entries()[id]
	return e, ok && id != "" && e.Backend == backend && e.Target == target && e.Action == action
}

func (j *Journal) Put(id string, entry JournalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	next := make(map[string]JournalEntry, len(j.entries)+1)
	cutoff := time.Now().Add(-48 * time.Hour)
	for key, e := range j.entries {
		if !e.Expires.Before(cutoff) {
			next[key] = e
		}
	}
	if id != "" {
		entry.Changed = append([]string(nil), entry.Changed...)
		entry.PriorDown = append([]string(nil), entry.PriorDown...)
		entry.Ports = append([]string(nil), entry.Ports...)
		next[id] = entry
	}
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if j.path != "" {
		if err = orders.WriteFileDurable(j.path, b); err != nil {
			return err
		}
	}
	j.entries = next
	return nil
}

func OrderExpiry(ttl int64, fallback time.Time) time.Time {
	if ttl > int64((1<<63-1)/time.Second) {
		ttl = int64((1<<63 - 1) / time.Second)
	}
	if ttl > 0 {
		return time.Now().Add(time.Duration(ttl) * time.Second)
	}
	return fallback
}
