// Package store defines the persistence interfaces. Consumers depend on
// these interfaces only; internal/store/sqlite is the first implementation.
package store

import (
	"context"
	"errors"
	"time"

	"netnoodle/internal/intel"
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
	// CreateSession stores a session only if the user's password hash is
	// still passHash (the one that was checked); else ErrConflict. A
	// password change during a login cannot leave a session behind.
	CreateSession(ctx context.Context, tokenHash []byte, userID int64, passHash []byte, expires time.Time) error
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
	// PurgeEvents deletes events older than before.
	PurgeEvents(ctx context.Context, before time.Time) error
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
	Enroll(ctx context.Context, joinHash []byte, name string, tokenHash []byte, now time.Time, allow func(name string) error) (Peer, error)
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
	Findings    int                `json:"findings"`  // open findings
	MaxScore    float64            `json:"max_score"` // highest CVSS score of the open findings
	KEV         int                `json:"kev"`       // open findings that are known exploited
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

// Finding is one vulnerability in one component of one device.
type Finding struct {
	DeviceID   int64  `json:"device_id"`
	PURL       string `json:"purl"`
	VulnID     string `json:"vuln_id"`
	Fixed      string `json:"fixed"`
	Confidence string `json:"confidence"`
}

// FindingFilter selects findings for ListFindings.
type FindingFilter struct {
	DeviceID int64   // 0: all devices
	State    string  // "open" (default), "resolved" or "all"
	MinScore float64 // only findings with at least this CVSS score
	KEV      bool    // only known exploited
	Limit    int     // default 2000, maximum 20000
}

// FindingRow is a finding with the data of its vulnerability and device.
type FindingRow struct {
	Finding
	Source     string            `json:"source"`
	State      string            `json:"state"`
	DeviceName string            `json:"device_name"`
	DeviceKind string            `json:"device_kind"`
	Package    string            `json:"package"`
	Version    string            `json:"version"`
	Aliases    []string          `json:"aliases"`
	Summary    string            `json:"summary"`
	Score      float64           `json:"score"`
	Vector     string            `json:"vector"`
	KEV        bool              `json:"kev"`
	EPSS       float64           `json:"epss"`
	EPSSPct    float64           `json:"epss_pct"`
	Facts      map[string]string `json:"facts,omitempty"`
	Exposed    []string          `json:"exposed"` // listening, non-loopback services of the package, e.g. "80/tcp"
	FirstSeen  time.Time         `json:"first_seen"`
	LastSeen   time.Time         `json:"last_seen"`
	ResolvedAt time.Time         `json:"resolved_at,omitzero"`
}

// FindingStats counts the open findings.
type FindingStats struct {
	Open     int `json:"open"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	KEV      int `json:"kev"`
	Exposed  int `json:"exposed"`
	Devices  int `json:"devices"`
	Vulns    int `json:"vulns"`
}

// Intel stores vulnerabilities and findings.
type Intel interface {
	// DeviceComponents returns the components of a device (one per PURL).
	DeviceComponents(ctx context.Context, deviceID int64) ([]proto.Component, error)
	// DevicesWithComponents returns the IDs of all devices that have components.
	DevicesWithComponents(ctx context.Context) ([]int64, error)
	// PutVulns inserts or updates vulnerabilities.
	PutVulns(ctx context.Context, vs []intel.Vuln, at time.Time) error
	// SyncFindings makes fs the open findings of the device for this source.
	// Findings not in fs are resolved. It returns the findings that are new
	// or open again.
	SyncFindings(ctx context.Context, deviceID int64, source string, fs []Finding, at time.Time) ([]Finding, error)
	ListFindings(ctx context.Context, f FindingFilter) ([]FindingRow, error)
	FindingStats(ctx context.Context) (FindingStats, error)
}

// Store is the full persistence interface.
type Store interface {
	Users
	Sessions
	Events
	Peers
	Inventory
	Intel
	Close() error
}
