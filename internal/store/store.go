// Package store defines the persistence interfaces. Consumers depend on
// these interfaces only; internal/store/sqlite is the first implementation.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// User is an operator account for the web UI.
type User struct {
	ID       int64
	Name     string
	PassHash []byte
	Created  time.Time
}

// Users stores operator accounts.
type Users interface {
	CountUsers(ctx context.Context) (int, error)
	CreateUser(ctx context.Context, name string, passHash []byte) (int64, error)
	UserByName(ctx context.Context, name string) (User, error)
	SetPassword(ctx context.Context, id int64, passHash []byte) error
}

// Sessions stores web UI sessions. Only the hash of the session token is kept.
type Sessions interface {
	CreateSession(ctx context.Context, tokenHash []byte, userID int64, expires time.Time) error
	SessionUser(ctx context.Context, tokenHash []byte, now time.Time) (User, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error
	PurgeSessions(ctx context.Context, now time.Time) error
}

// Event is one entry of the event log shown in the UI.
type Event struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Type    string    `json:"type"`
	Actor   string    `json:"actor"`
	Summary string    `json:"summary"`
	Data    string    `json:"data,omitempty"`
}

// Events stores the event log.
type Events interface {
	AddEvent(ctx context.Context, e Event) error
	ListEvents(ctx context.Context, limit int) ([]Event, error)
}

// Store is the full persistence interface.
type Store interface {
	Users
	Sessions
	Events
	Close() error
}
