// Package notify defines notification channels (webhook, log, ...).
package notify

import (
	"context"
	"time"

	"netnoodle/internal/registry"
)

// Event is something a human should know about.
type Event struct {
	Type     string            `json:"type"` // e.g. "device.new", "finding.new", "approval.needed"
	Severity string            `json:"severity,omitempty"`
	Title    string            `json:"title"`
	Detail   string            `json:"detail,omitempty"`
	Link     string            `json:"link,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	At       time.Time         `json:"at"`
}

// Notifier delivers events.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, e Event) error
}

var Registry = registry.New[Notifier]("notifier")
