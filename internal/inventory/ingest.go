// Package inventory turns observations into a deduplicated device tree.
//
// The rules (docs/architecture.md, 3.4):
//  1. A strong identifier that is known decides the device.
//  2. Strong identifiers of two devices in one entity merge those devices.
//  3. Without a strong match, a weak identifier (ip, hostname) can match,
//     but only if the candidate has no conflicting strong identifier of
//     the same kind.
//  4. Otherwise the entity is a new device.
//
// The logic only uses the Tx interface, so any store can implement it.
package inventory

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
)

// Device is the data used to create or update a device record.
type Device struct {
	Kind       proto.EntityKind
	Name       string
	ParentID   int64
	Attributes map[string]string
	Interfaces []proto.Interface
	Seen       time.Time
}

// Tx is one store transaction for the inventory.
type Tx interface {
	// Lookup returns the device that holds an identifier.
	Lookup(kind, value string) (deviceID int64, ok bool, err error)
	// Identifiers returns all identifiers of a device.
	Identifiers(deviceID int64) ([]proto.Identifier, error)
	// ParentOf returns the parent of a device (0 if none).
	ParentOf(deviceID int64) (int64, error)
	// CountChildren returns the number of devices with this parent.
	CountChildren(parentID int64) (int, error)
	CreateDevice(d Device) (int64, error)
	// UpdateDevice records a new sighting. It sets kind and name only if
	// they are unknown or empty, merges attributes and sets the parent if
	// ParentID is not zero.
	UpdateDevice(id int64, d Device) error
	// PutIdentifier attaches an identifier to a device. If another device
	// holds it, the identifier moves.
	PutIdentifier(deviceID int64, id proto.Identifier, source string, at time.Time) error
	// Merge moves everything from drop to keep and deletes drop.
	Merge(keep, drop int64) error
	// Tags returns the operator tags of a device.
	Tags(deviceID int64) ([]string, error)
	// PutComponents and PutServices upsert rows of one source. If complete
	// is true, rows of that source that are not in the list are removed.
	PutComponents(deviceID int64, source string, comps []proto.Component, complete bool, at time.Time) error
	PutServices(deviceID int64, source string, svcs []proto.Service, complete bool, at time.Time) error
	// SeenBy records that a source saw a device.
	SeenBy(deviceID int64, source string, at time.Time) error
	SaveObservation(source string, at time.Time, payload []byte) error
}

// Store runs fn in one transaction. If fn returns an error, nothing is kept.
type Store interface {
	InventoryTx(ctx context.Context, fn func(Tx) error) error
}

// NewDevice describes a device that an ingest created.
type NewDevice struct {
	ID          int64              `json:"id"`
	Name        string             `json:"name"`
	Kind        proto.EntityKind   `json:"kind"`
	Identifiers []proto.Identifier `json:"identifiers"`
	Source      string             `json:"source"`
}

// Result summarizes one ingest.
type Result struct {
	Devices []int64     `json:"devices"` // all devices touched, in order
	New     []NewDevice `json:"new,omitempty"`
	Merged  [][2]int64  `json:"merged,omitempty"` // [keep, drop]
	// MergeRefused are device pairs [kept, other] that a source report
	// connected, but that were not merged because one of them is
	// agent-owned or has operator tags (security review 2026-11-20).
	MergeRefused [][2]int64 `json:"merge_refused,omitempty"`
	Skipped      int        `json:"skipped,omitempty"`
	// Claimed are existing devices that an agent report took over (first
	// report of an agent, or a container that matched a guest by MAC).
	Claimed []int64 `json:"claimed,omitempty"`
}

// Ingest normalizes the observation and applies it in one transaction.
// raw is the original payload; it is kept for audit and debugging.
func Ingest(ctx context.Context, st Store, obs proto.Observation, raw []byte, now time.Time) (Result, error) {
	return IngestAs(ctx, st, obs, raw, now, "")
}

// IngestAs is Ingest for an observation of agent peer `agent` (empty for a
// source). The caller must have applied PrepareAgent. An agent report
// changes only the agent's own device: it never merges devices and never
// takes a strong identifier from another device.
func IngestAs(ctx context.Context, st Store, obs proto.Observation, raw []byte, now time.Time, agent string) (Result, error) {
	var res Result
	if obs.ObservedAt.IsZero() || obs.ObservedAt.After(now.Add(5*time.Minute)) {
		obs.ObservedAt = now
	}
	err := st.InventoryTx(ctx, func(tx Tx) error {
		res = Result{}
		if raw != nil {
			if err := tx.SaveObservation(obs.Source, now, raw); err != nil {
				return err
			}
		}
		r := &resolver{tx: tx, obs: &obs, res: &res, agent: agent}
		for i := range obs.Entities {
			e := &obs.Entities[i]
			if !NormalizeEntity(e) {
				res.Skipped++
				continue
			}
			if _, err := r.apply(e, 0); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

type resolver struct {
	tx    Tx
	obs   *proto.Observation
	res   *Result
	agent string // agent peer name; "" for sources
	// keepIDs is set while an entity whose merge was refused is applied:
	// its identifiers that another device holds stay with that device.
	keepIDs bool
}

func (r *resolver) apply(e *proto.Entity, parentID int64) (int64, error) {
	tx, at := r.tx, r.obs.ObservedAt

	if parentID == 0 && len(e.Parent) > 0 {
		pid, err := r.parentFromIDs(e.Parent)
		if err != nil {
			return 0, err
		}
		parentID = pid
	}

	var dev int64
	var err error
	switch {
	case r.agent != "" && parentID != 0:
		dev, err = r.resolveAgentChild(e, parentID)
		if errors.Is(err, errChildLimit) {
			r.res.Skipped++
			return 0, nil
		}
	case r.agent != "":
		dev, err = r.resolveAgent(e)
	default:
		r.keepIDs = false
		dev, err = r.resolve(e)
	}
	if err != nil {
		return 0, err
	}
	if parentID == dev {
		parentID = 0
	}
	d := Device{Kind: e.Kind, Name: e.Name, ParentID: parentID, Attributes: e.Attributes, Interfaces: e.Interfaces, Seen: at}
	if e.Name != "" {
		if d.Attributes == nil {
			d.Attributes = map[string]string{}
		}
		d.Attributes["name."+r.obs.Source] = e.Name
	}
	if dev == 0 {
		if dev, err = tx.CreateDevice(d); err != nil {
			return 0, err
		}
		r.res.New = append(r.res.New, NewDevice{ID: dev, Name: e.Name, Kind: e.Kind, Identifiers: e.Identifiers, Source: r.obs.Source})
	} else if err := tx.UpdateDevice(dev, d); err != nil {
		return 0, err
	}
	r.res.Devices = append(r.res.Devices, dev)
	if err := tx.SeenBy(dev, r.obs.Source, at); err != nil {
		return 0, err
	}

	for _, id := range e.Identifiers {
		if r.keepIDs {
			owner, ok, err := tx.Lookup(id.Kind, id.Value)
			if err != nil {
				return 0, err
			}
			if ok && owner != dev {
				continue
			}
		}
		if r.agent != "" && !movableByAgent[id.Kind] {
			// An agent must not take an identifier (whatever strength it
			// claims) from another device. Only IP addresses and host
			// names may move, as they do with DHCP.
			owner, ok, err := tx.Lookup(id.Kind, id.Value)
			if err != nil {
				return 0, err
			}
			if ok && owner != dev {
				continue
			}
		}
		if err := tx.PutIdentifier(dev, id, r.obs.Source, at); err != nil {
			return 0, err
		}
	}
	if len(e.Components) > 0 || r.obs.Complete {
		if err := tx.PutComponents(dev, r.obs.Source, e.Components, r.obs.Complete, at); err != nil {
			return 0, err
		}
	}
	if len(e.Services) > 0 || r.obs.Complete {
		if err := tx.PutServices(dev, r.obs.Source, e.Services, r.obs.Complete, at); err != nil {
			return 0, err
		}
	}
	for i := range e.Children {
		if _, err := r.apply(&e.Children[i], dev); err != nil {
			return 0, err
		}
	}
	return dev, nil
}

// resolve returns the existing device for e, or 0 for a new device.
func (r *resolver) resolve(e *proto.Entity) (int64, error) {
	found := map[int64]bool{}
	for _, id := range e.Identifiers {
		if id.Strength != proto.Strong {
			continue
		}
		dev, ok, err := r.tx.Lookup(id.Kind, id.Value)
		if err != nil {
			return 0, err
		}
		if ok {
			found[dev] = true
		}
	}
	switch len(found) {
	case 0:
		return r.matchWeak(e)
	case 1:
		for d := range found {
			return d, nil
		}
	}
	// Several devices share strong identifiers with this entity: they are
	// one device. Keep the oldest (lowest id).
	ids := make([]int64, 0, len(found))
	for d := range found {
		ids = append(ids, d)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	keep := ids[0]
	// Source data can contain values that a device controls (for example
	// the MACs that an IoT device reports to Home Assistant). A source must
	// not merge devices that an agent describes or that an operator tagged:
	// a merge moves identifiers, tags and pending decisions.
	for _, d := range ids {
		locked, err := r.mergeLocked(d)
		if err != nil {
			return 0, err
		}
		if locked {
			keep = r.primary(e, ids)
			for _, other := range ids {
				if other != keep {
					r.res.MergeRefused = append(r.res.MergeRefused, [2]int64{keep, other})
				}
			}
			r.keepIDs = true
			return keep, nil
		}
	}
	for _, drop := range ids[1:] {
		if err := r.tx.Merge(keep, drop); err != nil {
			return 0, err
		}
		r.res.Merged = append(r.res.Merged, [2]int64{keep, drop})
	}
	return keep, nil
}

// mergeLocked reports whether a source may not merge device dev with
// another device: an agent owns it, or an operator tagged it.
func (r *resolver) mergeLocked(dev int64) (bool, error) {
	ids, err := r.tx.Identifiers(dev)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if id.Kind == AgentKind || id.Kind == ChildKind {
			return true, nil
		}
	}
	tags, err := r.tx.Tags(dev)
	return len(tags) > 0, err
}

// primary selects the device for an entity whose merge was refused: the
// device that holds the entity's first strong identifier that is not a
// MAC address (a source-specific ID), else the oldest device.
func (r *resolver) primary(e *proto.Entity, ids []int64) int64 {
	for _, id := range e.Identifiers {
		if id.Strength != proto.Strong || id.Kind == "mac" {
			continue
		}
		if dev, ok, err := r.tx.Lookup(id.Kind, id.Value); err == nil && ok {
			return dev
		}
	}
	return ids[0]
}

// weakOrder is the order in which weak identifier kinds are tried.
var weakOrder = []string{"ip", "hostname"}

func (r *resolver) matchWeak(e *proto.Entity) (int64, error) {
	for _, kind := range weakOrder {
		for _, id := range e.Identifiers {
			if id.Kind != kind || id.Strength != proto.Weak {
				continue
			}
			cand, ok, err := r.tx.Lookup(id.Kind, id.Value)
			if err != nil || !ok {
				if err != nil {
					return 0, err
				}
				continue
			}
			conflict, err := r.conflicts(cand, e.Identifiers)
			if err != nil {
				return 0, err
			}
			if !conflict {
				return cand, nil
			}
		}
	}
	return 0, nil
}

// conflicts is true if the candidate device has a strong identifier of a
// kind that the entity also has, with a different value. Example: the
// candidate holds the IP address but has another MAC address, so the IP
// moved to a new device (DHCP).
func (r *resolver) conflicts(cand int64, ids []proto.Identifier) (bool, error) {
	have, err := r.tx.Identifiers(cand)
	if err != nil {
		return false, err
	}
	candStrong := map[string]bool{}
	for _, h := range have {
		if h.Strength == proto.Strong {
			candStrong[h.Kind] = true
		}
	}
	for _, id := range ids {
		if id.Strength == proto.Strong && candStrong[id.Kind] {
			return true, nil
		}
	}
	return false, nil
}

// parentFromIDs finds the parent device by its strong identifiers, or
// creates a placeholder device that a later observation fills in.
func (r *resolver) parentFromIDs(ids []proto.Identifier) (int64, error) {
	var strong []proto.Identifier
	for _, id := range ids {
		if id.Strength == proto.Strong {
			strong = append(strong, id)
		}
	}
	if len(strong) == 0 {
		return 0, nil
	}
	tmp := proto.Entity{Kind: proto.KindUnknown, Identifiers: strong}
	dev, err := r.resolve(&tmp)
	if err != nil || dev != 0 {
		return dev, err
	}
	at := r.obs.ObservedAt
	if dev, err = r.tx.CreateDevice(Device{Kind: proto.KindUnknown, Seen: at}); err != nil {
		return 0, err
	}
	r.res.New = append(r.res.New, NewDevice{ID: dev, Kind: proto.KindUnknown, Identifiers: strong, Source: r.obs.Source})
	for _, id := range strong {
		if err := r.tx.PutIdentifier(dev, id, r.obs.Source, at); err != nil {
			return 0, err
		}
	}
	return dev, nil
}
