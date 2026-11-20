// Package store defines the persistence interfaces. Consumers depend on
// these interfaces only; internal/store/sqlite is the first implementation.
package store

import (
	"context"
	"errors"
	"time"

	"fmt"
	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"regexp"
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
	RecentDeviceClaims(context.Context, int64, time.Time, time.Time) ([]DeviceClaim, error)
	// PurgeEvents deletes events older than before.
	PurgeEvents(ctx context.Context, before time.Time) error
}

type DeviceClaim struct {
	Agent string    `json:"agent"`
	At    time.Time `json:"at"`
}

// Peer is a program that talks to the server: a source, an agent or an actor.
type Peer struct {
	Version  string    `json:"version"`
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
	SetPeerVersion(ctx context.Context, id int64, version string) error
	TouchPeer(ctx context.Context, id int64, now time.Time) error
	ListPeers(ctx context.Context) ([]Peer, error)
	SetPeerDisabled(ctx context.Context, id int64, disabled bool) error
}

// PullPeer is an agent peer that the server pulls reports from.
type PullPeer struct {
	Peer
	Transport   string        `json:"transport"`
	Address     string        `json:"address"`
	Pin         string        `json:"pin,omitempty"` // agent certificate fingerprint; empty until paired
	PairCode    string        `json:"-"`
	PairExpires time.Time     `json:"pair_expires,omitzero"`
	Interval    time.Duration `json:"interval_ns"`
	NextPull    time.Time     `json:"next_pull"`
	LastPull    time.Time     `json:"last_pull,omitzero"`
	LastError   string        `json:"last_error,omitempty"`
}

// Pulls stores pull peers.
type Pulls interface {
	// CreatePullPeer creates an agent peer without a usable token and its
	// pull settings. ErrConflict if the name exists.
	CreatePullPeer(ctx context.Context, p PullPeer, tokenHash []byte, now time.Time) (PullPeer, error)
	ListPullPeers(ctx context.Context) ([]PullPeer, error)
	GetPullPeer(ctx context.Context, id int64) (PullPeer, error)
	// DuePullPeers returns enabled pull peers with next_pull <= now.
	DuePullPeers(ctx context.Context, now time.Time) ([]PullPeer, error)
	// SetPairCode sets a new pairing code and deletes the pin.
	SetPairCode(ctx context.Context, id int64, code string, expires, next time.Time) error
	// SetPin pins the agent certificate if the code is still the given
	// one, and deletes the code. ErrConflict if the code changed.
	SetPin(ctx context.Context, id int64, code, pin string) error
	// SetPullResult records the outcome of a pull or pairing attempt.
	// ok updates last_pull.
	SetPullResult(ctx context.Context, id int64, ok bool, at, next time.Time, errText string) error
	// SetNextPull schedules the next attempt.
	SetNextPull(ctx context.Context, id int64, next time.Time) error
}

// DeviceRef is a short reference to a device.
type DeviceRef struct {
	ID   int64  `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// DeviceRow is one line of the device list.
type DeviceRow struct {
	Attributes  map[string]string  `json:"-"` // reachability inputs, loaded with the inventory
	Interfaces  []proto.Interface  `json:"-"`
	Tags        []string           `json:"tags"`
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

// DeviceService is a service with its device.
type DeviceService struct {
	DeviceID int64 `json:"device_id"`
	proto.Service
}

// DeviceDetail is the full record of one device.
type DeviceDetail struct {
	Tags       []string          `json:"tags"`
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
	// ListAllServices returns the services of all devices.
	ListAllServices(ctx context.Context) ([]DeviceService, error)
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
	Pulls
	Inventory
	Intel
	Tags
	Settings
	Proposals
	Orders
	Close() error
}

// Tags are operator-owned labels; reports cannot change them.
type Tags interface {
	SetTags(context.Context, int64, []string) error
	Tags(context.Context, int64) ([]string, error)
}

var tagPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

func ValidateTags(tags []string) error {
	if len(tags) > 32 {
		return fmt.Errorf("at most 32 tags per device")
	}
	for _, t := range tags {
		if !tagPattern.MatchString(t) {
			return fmt.Errorf("invalid tag %q", t)
		}
	}
	return nil
}

type Settings interface {
	GetSetting(context.Context, string) (string, error)
	SetSetting(context.Context, string, string) error
}
type Proposal struct {
	TargetSnapshot []proto.Identifier `json:"target_snapshot"`
	// Keys are kind=value. False (including absent legacy evidence) fails closed.
	TargetReportedElsewhere map[string]bool `json:"target_reported_elsewhere"`
	OverrideAgentOnly       bool            `json:"override_agent_only"`
	RecentClaims            []DeviceClaim   `json:"recent_claims,omitempty"`
	ID                      int64           `json:"id"`
	DeviceID                int64           `json:"device_id"`
	DeviceName              string          `json:"device_name"`
	VulnID                  string          `json:"vuln_id"`
	PURL                    string          `json:"purl"`
	Action                  string          `json:"action"`
	Tier                    string          `json:"tier"`
	State                   string          `json:"state"`
	Reason                  string          `json:"reason"`
	DecidedBy               []string        `json:"decided_by"`
	Params                  map[string]any  `json:"params"`
	TTL                     int64           `json:"ttl_s"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
	ExpiresAt               time.Time       `json:"expires_at,omitzero"`
	DecidedUser             string          `json:"decided_user"`
	DecidedAt               time.Time       `json:"decided_at,omitzero"`
}
type ProposalFilter struct {
	State    string
	DeviceID int64
	Limit    int
}
type Proposals interface {
	OpenVulnIDs(context.Context, int64) ([]string, error)
	// UpsertProposal returns the saved record and whether it was inserted or
	// a closed/notification row was reopened into pending/auto.
	// Reviewed and executed decisions retain their scope.
	UpsertProposal(context.Context, Proposal) (Proposal, bool, error)
	ListProposals(context.Context, ProposalFilter) ([]Proposal, error)
	ProposalStats(context.Context) (map[string]int, error)
	PurgeProposals(context.Context, time.Time) error
	GetProposal(context.Context, int64) (Proposal, error)
	DecideProposal(context.Context, int64, string, string, time.Time, ...bool) error
	SnapshotTargets(context.Context, int64) ([]proto.Identifier, map[string]bool, error)
	// ExpireProposals closes pending proposals whose seven-day approval window
	// ended by cutoff+7d, using creation time for legacy rows without a deadline.
	ExpireProposals(context.Context, time.Time) error
	ResolveProposals(context.Context, int64, []string) error
}
