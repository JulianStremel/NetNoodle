// Package proto holds the v1 wire types shared by the server, sources,
// agents and actors. The JSON Schemas in api/v1 describe the same shapes;
// the Rust crate agent/nn-proto mirrors them.
//
// Nothing in here is specific to one source or one actor. The server only
// reasons about identifiers, kinds and capabilities.
package proto

import "time"

// Version is the protocol version carried in every envelope.
const Version = "v1"

// Strength tells the identity resolver how much it may trust an identifier.
type Strength string

const (
	// Strong identifiers identify exactly one entity (a MAC that is not
	// locally administered, an agent id, a hypervisor guest id).
	Strong Strength = "strong"
	// Weak identifiers are hints that can move between entities over time
	// (IP addresses, host names).
	Weak Strength = "weak"
)

// Identifier is one (kind, value) pair that names an entity.
// Kinds are free-form dotted names such as "mac", "ip", "hostname",
// "agent", "unifi.client", "proxmox.guest", "docker.container".
type Identifier struct {
	Kind     string   `json:"kind"`
	Value    string   `json:"value"`
	Strength Strength `json:"strength"`
}

// EntityKind is a coarse class of entity.
type EntityKind string

const (
	KindHost          EntityKind = "host"
	KindVM            EntityKind = "vm"
	KindContainer     EntityKind = "container"
	KindNetworkDevice EntityKind = "network-device"
	KindUnknown       EntityKind = "unknown"
)

// Confidence of a component or service version.
type Confidence string

const (
	High Confidence = "high" // read from a package database
	Low  Confidence = "low"  // guessed, e.g. from a banner
)

// Component is one piece of installed software.
type Component struct {
	PURL       string     `json:"purl"` // package URL including version
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Confidence Confidence `json:"confidence,omitempty"`
}

// Service is a listening network service.
type Service struct {
	Port       int        `json:"port"`
	Proto      string     `json:"proto"` // tcp | udp
	Address    string     `json:"address,omitempty"`
	Product    string     `json:"product,omitempty"`
	Version    string     `json:"version,omitempty"`
	Process    string     `json:"process,omitempty"`
	Component  string     `json:"component,omitempty"` // PURL of the owning package
	Banner     string     `json:"banner,omitempty"`
	Confidence Confidence `json:"confidence,omitempty"`
}

// Interface is a network interface of an entity.
type Interface struct {
	Name string   `json:"name,omitempty"`
	MAC  string   `json:"mac,omitempty"`
	IPs  []string `json:"ips,omitempty"`
	Kind string   `json:"kind,omitempty"` // "vpn" for a VPN or overlay interface
	VPN  string   `json:"vpn,omitempty"`  // tailscale | wireguard | zerotier | tun
}

// Entity is one observed thing plus, optionally, its children
// (VMs of a hypervisor node, containers of a host).
type Entity struct {
	Kind        EntityKind        `json:"kind"`
	Identifiers []Identifier      `json:"identifiers"`
	Name        string            `json:"name,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Components  []Component       `json:"components,omitempty"`
	Services    []Service         `json:"services,omitempty"`
	Interfaces  []Interface       `json:"interfaces,omitempty"`
	// Parent names the parent entity when it is not given by nesting,
	// for example a VM that a hypervisor API reports by node name.
	Parent   []Identifier `json:"parent,omitempty"`
	Children []Entity     `json:"children,omitempty"`
}

// Observation is what every source (scanner, API importer, agent,
// third-party program) sends to the server.
type Observation struct {
	Version    string    `json:"version"`
	Source     string    `json:"source"` // source instance name, e.g. "scan-lan"
	ObservedAt time.Time `json:"observed_at"`
	// Complete is true when the source reports the full state of each
	// entity (an agent), so missing components were removed. Scanners and
	// importers send partial views and leave it false.
	Complete bool     `json:"complete,omitempty"`
	Entities []Entity `json:"entities"`
}

// Capability is one action an actor can execute.
type Capability struct {
	Action        string         `json:"action"`          // abstract action, e.g. "isolate", "stop-service"
	TargetIDKinds []string       `json:"target_id_kinds"` // identifier kinds the actor can address
	ParamsSchema  map[string]any `json:"params_schema,omitempty"`
	Reversible    bool           `json:"reversible"`
	RevertAction  string         `json:"revert_action,omitempty"`
}

// ActorHello is sent by an actor when it connects.
type ActorHello struct {
	Version      string       `json:"version"`
	Actor        string       `json:"actor"`
	Capabilities []Capability `json:"capabilities"`
}

// Order is a signed instruction from the server to one actor.
type Order struct {
	Version  string            `json:"version"`
	ID       string            `json:"id"`
	Actor    string            `json:"actor"`
	Action   string            `json:"action"`
	Targets  []Identifier      `json:"targets"`
	Params   map[string]any    `json:"params,omitempty"`
	TTL      int64             `json:"ttl_seconds,omitempty"` // 0 = permanent
	Revert   bool              `json:"revert,omitempty"`      // true if this order undoes an earlier one
	RevertOf string            `json:"revert_of,omitempty"`
	NotAfter time.Time         `json:"not_after"`
	Nonce    string            `json:"nonce"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// SignedOrder wraps an order with an ed25519 signature over its
// canonical JSON encoding (the exact bytes in Payload).
type SignedOrder struct {
	Payload   []byte `json:"payload"`   // JSON of Order
	Signature []byte `json:"signature"` // ed25519 over Payload
	KeyID     string `json:"key_id"`
}

// OrderStatus is the outcome reported by an actor.
type OrderStatus string

const (
	OrderDone     OrderStatus = "done"
	OrderFailed   OrderStatus = "failed"
	OrderRejected OrderStatus = "rejected" // signature, expiry, nonce or allowlist check failed
)

// OrderResult is sent by the actor after it handled an order.
type OrderResult struct {
	Version string      `json:"version"`
	OrderID string      `json:"order_id"`
	Status  OrderStatus `json:"status"`
	Message string      `json:"message,omitempty"`
	At      time.Time   `json:"at"`
}
