// Package store defines the persistence interfaces. Consumers depend on
// these interfaces only; internal/store/sqlite is the first implementation.
package store

import (
	"context"
	"errors"
	"time"

	"netnoodle/internal/inventory"
	"netnoodle/internal/proto"
)

var (
	// ErrNotFound is returned when a record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a unique value exists already.
	ErrConflict = errors.New("already exists")
)

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

// Peer is a program that talks to the server: a source, an agent or an actor.
type Peer struct {
	ID       int64     `json:"id"`
	Name     string    `json:"name"`
	Role     string    `json:"role"` // source | agent | actor
	Disabled bool      `json:"disabled"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
}

// Peer roles.
const (
	RoleSource = "source"
	RoleAgent  = "agent"
	RoleActor  = "actor"
)

// JoinToken lets a peer enroll. Only its hash is stored.
type JoinToken struct {
	ID       int64     `json:"id"`
	Role     string    `json:"role"`
	Name     string    `json:"name,omitempty"` // fixed peer name, or empty
	UsesLeft int       `json:"uses_left"`
	Expires  time.Time `json:"expires"`
	Created  time.Time `json:"created"`
}

// Peers stores enrolled programs and join tokens.
type Peers interface {
	CreateJoinToken(ctx context.Context, hash []byte, role, name string, uses int, expires time.Time) (int64, error)
	ListJoinTokens(ctx context.Context, now time.Time) ([]JoinToken, error)
	DeleteJoinToken(ctx context.Context, id int64) error
	// Enroll uses one use of the join token and creates the peer.
	Enroll(ctx context.Context, joinHash []byte, name string, tokenHash []byte, now time.Time) (Peer, error)
	PeerByToken(ctx context.Context, hash []byte) (Peer, error)
	TouchPeer(ctx context.Context, id int64, now time.Time) error
	ListPeers(ctx context.Context) ([]Peer, error)
	SetPeerDisabled(ctx context.Context, id int64, disabled bool) error
}

// DeviceRef is a short reference to a device.
type DeviceRef struct {
	ID   int64  `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// DeviceRow is one line of the device list.
type DeviceRow struct {
	ID          int64              `json:"id"`
	Kind        string             `json:"kind"`
	Name        string             `json:"name"`
	ParentID    int64              `json:"parent_id,omitempty"`
	FirstSeen   time.Time          `json:"first_seen"`
	LastSeen    time.Time          `json:"last_seen"`
	Identifiers []proto.Identifier `json:"identifiers"`
	Sources     []string           `json:"sources"`
	Components  int                `json:"components"`
	Services    int                `json:"services"`
}

// IDRow is an identifier with its provenance.
type IDRow struct {
	proto.Identifier
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ComponentRow is one installed component of a device.
type ComponentRow struct {
	PURL       string    `json:"purl"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Confidence string    `json:"confidence"`
	Source     string    `json:"source"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// ServiceRow is one service of a device.
type ServiceRow struct {
	proto.Service
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DeviceDetail is the full record of one device.
type DeviceDetail struct {
	ID         int64             `json:"id"`
	Kind       string            `json:"kind"`
	Name       string            `json:"name"`
	ParentID   int64             `json:"parent_id,omitempty"`
	FirstSeen  time.Time         `json:"first_seen"`
	LastSeen   time.Time         `json:"last_seen"`
	Attributes map[string]string `json:"attributes"`
	Interfaces []proto.Interface `json:"interfaces"`
	IDs        []IDRow           `json:"identifiers"`
	Components []ComponentRow    `json:"components"`
	Services   []ServiceRow      `json:"services"`
	Children   []DeviceRef       `json:"children"`
}

// Inventory is the device store: the write side used by the inventory
// package plus the read side used by the UI.
type Inventory interface {
	inventory.Store
	ListDevices(ctx context.Context) ([]DeviceRow, error)
	GetDevice(ctx context.Context, id int64) (DeviceDetail, error)
	RenameDevice(ctx context.Context, id int64, name string) error
	PurgeObservations(ctx context.Context, before time.Time) error
}

// Store is the full persistence interface.
type Store interface {
	Users
	Sessions
	Events
	Peers
	Inventory
	Close() error
}
