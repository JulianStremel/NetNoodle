package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

var _ inventory.Store = (*DB)(nil)

// InventoryTx runs fn in one transaction.
func (s *DB) InventoryTx(ctx context.Context, fn func(inventory.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&invTx{ctx: ctx, tx: tx}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

type invTx struct {
	ctx context.Context
	tx  *sql.Tx
}

func (t *invTx) exec(q string, args ...any) error {
	_, err := t.tx.ExecContext(t.ctx, q, args...)
	return err
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func (t *invTx) Lookup(kind, value string) (int64, bool, error) {
	var id int64
	err := t.tx.QueryRowContext(t.ctx, `SELECT device_id FROM device_ids WHERE kind = ? AND value = ?`, kind, value).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return id, err == nil, err
}

func (t *invTx) Identifiers(deviceID int64) ([]proto.Identifier, error) {
	rows, err := t.tx.QueryContext(t.ctx, `SELECT kind, value, strength FROM device_ids WHERE device_id = ?`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proto.Identifier
	for rows.Next() {
		var id proto.Identifier
		if err := rows.Scan(&id.Kind, &id.Value, &id.Strength); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func marshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (t *invTx) CreateDevice(d inventory.Device) (int64, error) {
	if d.Attributes == nil {
		d.Attributes = map[string]string{}
	}
	if d.Interfaces == nil {
		d.Interfaces = []proto.Interface{}
	}
	r, err := t.tx.ExecContext(t.ctx, `INSERT INTO devices(kind, name, parent_id, attributes, interfaces, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		string(d.Kind), d.Name, nullID(d.ParentID), marshal(d.Attributes), marshal(d.Interfaces), ts(d.Seen), ts(d.Seen))
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

type devRow struct {
	kind, name, attrs, ifaces string
	parent                    sql.NullInt64
	first, last               string
}

func (t *invTx) row(id int64) (devRow, error) {
	var r devRow
	err := t.tx.QueryRowContext(t.ctx, `SELECT kind, name, parent_id, attributes, interfaces, first_seen, last_seen
		FROM devices WHERE id = ?`, id).Scan(&r.kind, &r.name, &r.parent, &r.attrs, &r.ifaces, &r.first, &r.last)
	return r, notFound(err)
}

// maxDeviceAttrs limits the attributes of one device. New keys win; old
// keys that are not in the update are dropped first when the limit is hit.
const maxDeviceAttrs = 512

func mergeAttrs(oldJSON string, add map[string]string) string {
	m := map[string]string{}
	_ = json.Unmarshal([]byte(oldJSON), &m)
	for k, v := range add {
		m[k] = v
	}
	if len(m) > maxDeviceAttrs {
		keys := make([]string, 0, len(m))
		for k := range m {
			if _, isNew := add[k]; !isNew {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			if len(m) <= maxDeviceAttrs {
				break
			}
			delete(m, k)
		}
	}
	return marshal(m)
}

func (t *invTx) UpdateDevice(id int64, d inventory.Device) error {
	r, err := t.row(id)
	if err != nil {
		return err
	}
	if (r.kind == "" || r.kind == string(proto.KindUnknown)) && d.Kind != "" {
		r.kind = string(d.Kind)
	}
	if r.name == "" {
		r.name = d.Name
	}
	r.attrs = mergeAttrs(r.attrs, d.Attributes)
	if len(d.Interfaces) > 0 {
		r.ifaces = marshal(d.Interfaces)
	}
	parent := r.parent
	if d.ParentID != 0 && d.ParentID != id {
		parent = sql.NullInt64{Int64: d.ParentID, Valid: true}
	}
	last := r.last
	if s := ts(d.Seen); s > last {
		last = s
	}
	return t.exec(`UPDATE devices SET kind = ?, name = ?, parent_id = ?, attributes = ?, interfaces = ?, last_seen = ? WHERE id = ?`,
		r.kind, r.name, parent, r.attrs, r.ifaces, last, id)
}

func (t *invTx) PutIdentifier(deviceID int64, id proto.Identifier, source string, at time.Time) error {
	// SQLite evaluates the SET expressions against the old row.
	return t.exec(`INSERT INTO device_ids(kind, value, strength, device_id, source, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(kind, value) DO UPDATE SET
			first_seen = CASE WHEN device_ids.device_id = excluded.device_id THEN device_ids.first_seen ELSE excluded.first_seen END,
			strength   = CASE WHEN excluded.strength = 'strong'
			                   OR (device_ids.strength = 'strong' AND device_ids.device_id = excluded.device_id)
			                  THEN 'strong' ELSE 'weak' END,
			device_id  = excluded.device_id,
			source     = excluded.source,
			last_seen  = excluded.last_seen`,
		id.Kind, id.Value, string(id.Strength), deviceID, source, ts(at), ts(at))
}

func (t *invTx) Merge(keep, drop int64) error {
	if keep == drop {
		return nil
	}
	k, err := t.row(keep)
	if err != nil {
		return err
	}
	d, err := t.row(drop)
	if err != nil {
		return err
	}
	if k.kind == string(proto.KindUnknown) {
		k.kind = d.kind
	}
	if k.name == "" {
		k.name = d.name
	}
	dm := map[string]string{}
	_ = json.Unmarshal([]byte(d.attrs), &dm)
	km := map[string]string{}
	_ = json.Unmarshal([]byte(k.attrs), &km)
	for key, v := range km { // keep wins
		dm[key] = v
	}
	k.attrs = marshal(dm)
	if k.ifaces == "[]" {
		k.ifaces = d.ifaces
	}
	if d.first < k.first {
		k.first = d.first
	}
	if d.last > k.last {
		k.last = d.last
	}
	if !k.parent.Valid && d.parent.Valid && d.parent.Int64 != keep {
		k.parent = d.parent
	}
	if k.parent.Valid && k.parent.Int64 == drop {
		k.parent = sql.NullInt64{}
	}
	steps := []struct {
		q    string
		args []any
	}{
		{`UPDATE device_ids SET device_id = ? WHERE device_id = ?`, []any{keep, drop}},
		{`UPDATE OR IGNORE components SET device_id = ? WHERE device_id = ?`, []any{keep, drop}},
		{`UPDATE OR IGNORE services SET device_id = ? WHERE device_id = ?`, []any{keep, drop}},
		{`UPDATE OR IGNORE device_sources SET device_id = ? WHERE device_id = ?`, []any{keep, drop}},
		{`UPDATE devices SET parent_id = ? WHERE parent_id = ? AND id <> ?`, []any{keep, drop, keep}},
		{`DELETE FROM devices WHERE id = ?`, []any{drop}},
		{`UPDATE devices SET kind = ?, name = ?, parent_id = ?, attributes = ?, interfaces = ?, first_seen = ?, last_seen = ? WHERE id = ?`,
			[]any{k.kind, k.name, k.parent, k.attrs, k.ifaces, k.first, k.last, keep}},
	}
	for _, s := range steps {
		if err := t.exec(s.q, s.args...); err != nil {
			return err
		}
	}
	return nil
}

func (t *invTx) PutComponents(deviceID int64, source string, comps []proto.Component, complete bool, at time.Time) error {
	stmt, err := t.tx.PrepareContext(t.ctx, `INSERT INTO components(device_id, purl, source, name, version, confidence, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id, purl, source) DO UPDATE SET
			name = excluded.name, version = excluded.version, confidence = excluded.confidence, last_seen = excluded.last_seen`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := ts(at)
	for _, c := range comps {
		if _, err := stmt.ExecContext(t.ctx, deviceID, c.PURL, source, c.Name, c.Version, string(c.Confidence), now, now); err != nil {
			return err
		}
	}
	if complete {
		return t.exec(`DELETE FROM components WHERE device_id = ? AND source = ? AND last_seen < ?`, deviceID, source, now)
	}
	return nil
}

func (t *invTx) PutServices(deviceID int64, source string, svcs []proto.Service, complete bool, at time.Time) error {
	stmt, err := t.tx.PrepareContext(t.ctx, `INSERT INTO services(device_id, proto, port, source, address, product, version,
			process, component, banner, confidence, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id, proto, port, source) DO UPDATE SET
			address = excluded.address, product = excluded.product, version = excluded.version,
			process = excluded.process, component = excluded.component, banner = excluded.banner,
			confidence = excluded.confidence, last_seen = excluded.last_seen`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := ts(at)
	for _, s := range svcs {
		if _, err := stmt.ExecContext(t.ctx, deviceID, s.Proto, s.Port, source, s.Address, s.Product, s.Version,
			s.Process, s.Component, s.Banner, string(s.Confidence), now, now); err != nil {
			return err
		}
	}
	if complete {
		return t.exec(`DELETE FROM services WHERE device_id = ? AND source = ? AND last_seen < ?`, deviceID, source, now)
	}
	return nil
}

func (t *invTx) SeenBy(deviceID int64, source string, at time.Time) error {
	return t.exec(`INSERT INTO device_sources(device_id, source, first_seen, last_seen) VALUES (?, ?, ?, ?)
		ON CONFLICT(device_id, source) DO UPDATE SET last_seen = MAX(device_sources.last_seen, excluded.last_seen)`,
		deviceID, source, ts(at), ts(at))
}

func (t *invTx) SaveObservation(source string, at time.Time, payload []byte) error {
	return t.exec(`INSERT INTO observations(source, received_at, payload) VALUES (?, ?, ?)`, source, ts(at), payload)
}

// PurgeObservations deletes raw observations received before t.
func (s *DB) PurgeObservations(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM observations WHERE received_at < ?`, ts(before))
	return err
}

// --- read side for the UI ---

func (s *DB) ListDevices(ctx context.Context) ([]store.DeviceRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, d.kind, d.name, COALESCE(d.parent_id, 0), d.first_seen, d.last_seen,
			(SELECT COUNT(*) FROM components c WHERE c.device_id = d.id),
			(SELECT COUNT(*) FROM services v WHERE v.device_id = d.id),
			(SELECT COUNT(*) FROM findings f WHERE f.device_id = d.id AND f.state = 'open'),
			(SELECT COALESCE(MAX(x.score), 0) FROM findings f JOIN vulns x ON x.id = f.vuln_id WHERE f.device_id = d.id AND f.state = 'open'),
			(SELECT COUNT(*) FROM findings f JOIN vulns x ON x.id = f.vuln_id WHERE f.device_id = d.id AND f.state = 'open' AND x.kev = 1)
		FROM devices d ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	var out []store.DeviceRow
	byID := map[int64]int{}
	for rows.Next() {
		var r store.DeviceRow
		var first, last string
		if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &r.ParentID, &first, &last, &r.Components, &r.Services, &r.Findings, &r.MaxScore, &r.KEV); err != nil {
			rows.Close()
			return nil, err
		}
		r.FirstSeen, r.LastSeen = parseTS(first), parseTS(last)
		r.Identifiers = []proto.Identifier{}
		r.Sources = []string{}
		byID[r.ID] = len(out)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	ids, err := s.db.QueryContext(ctx, `SELECT device_id, kind, value, strength FROM device_ids ORDER BY device_id, kind, value`)
	if err != nil {
		return nil, err
	}
	for ids.Next() {
		var dev int64
		var id proto.Identifier
		if err := ids.Scan(&dev, &id.Kind, &id.Value, &id.Strength); err != nil {
			ids.Close()
			return nil, err
		}
		if i, ok := byID[dev]; ok {
			out[i].Identifiers = append(out[i].Identifiers, id)
		}
	}
	ids.Close()
	if err := ids.Err(); err != nil {
		return nil, err
	}

	srcs, err := s.db.QueryContext(ctx, `SELECT device_id, source FROM device_sources ORDER BY device_id, source`)
	if err != nil {
		return nil, err
	}
	defer srcs.Close()
	for srcs.Next() {
		var dev int64
		var src string
		if err := srcs.Scan(&dev, &src); err != nil {
			return nil, err
		}
		if i, ok := byID[dev]; ok {
			out[i].Sources = append(out[i].Sources, src)
		}
	}
	return out, srcs.Err()
}

func (s *DB) GetDevice(ctx context.Context, id int64) (store.DeviceDetail, error) {
	var d store.DeviceDetail
	var first, last, attrs, ifaces string
	err := s.db.QueryRowContext(ctx, `SELECT id, kind, name, COALESCE(parent_id, 0), attributes, interfaces, first_seen, last_seen
		FROM devices WHERE id = ?`, id).Scan(&d.ID, &d.Kind, &d.Name, &d.ParentID, &attrs, &ifaces, &first, &last)
	if err != nil {
		return d, notFound(err)
	}
	d.FirstSeen, d.LastSeen = parseTS(first), parseTS(last)
	d.Attributes = map[string]string{}
	_ = json.Unmarshal([]byte(attrs), &d.Attributes)
	_ = json.Unmarshal([]byte(ifaces), &d.Interfaces)

	q := func(query string, scan func(*sql.Rows) error) error {
		rows, err := s.db.QueryContext(ctx, query, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if err := scan(rows); err != nil {
				return err
			}
		}
		return rows.Err()
	}
	d.IDs = []store.IDRow{}
	if err := q(`SELECT kind, value, strength, source, first_seen, last_seen FROM device_ids WHERE device_id = ? ORDER BY kind, value`,
		func(r *sql.Rows) error {
			var x store.IDRow
			var f, l string
			if err := r.Scan(&x.Kind, &x.Value, &x.Strength, &x.Source, &f, &l); err != nil {
				return err
			}
			x.FirstSeen, x.LastSeen = parseTS(f), parseTS(l)
			d.IDs = append(d.IDs, x)
			return nil
		}); err != nil {
		return d, err
	}
	d.Components = []store.ComponentRow{}
	if err := q(`SELECT purl, name, version, confidence, source, first_seen, last_seen FROM components WHERE device_id = ? ORDER BY name, purl`,
		func(r *sql.Rows) error {
			var x store.ComponentRow
			var f, l string
			if err := r.Scan(&x.PURL, &x.Name, &x.Version, &x.Confidence, &x.Source, &f, &l); err != nil {
				return err
			}
			x.FirstSeen, x.LastSeen = parseTS(f), parseTS(l)
			d.Components = append(d.Components, x)
			return nil
		}); err != nil {
		return d, err
	}
	d.Services = []store.ServiceRow{}
	if err := q(`SELECT proto, port, address, product, version, process, component, banner, confidence, source, first_seen, last_seen
		FROM services WHERE device_id = ? ORDER BY proto, port`,
		func(r *sql.Rows) error {
			var x store.ServiceRow
			var f, l string
			if err := r.Scan(&x.Proto, &x.Port, &x.Address, &x.Product, &x.Version, &x.Process, &x.Component, &x.Banner,
				&x.Confidence, &x.Source, &f, &l); err != nil {
				return err
			}
			x.FirstSeen, x.LastSeen = parseTS(f), parseTS(l)
			d.Services = append(d.Services, x)
			return nil
		}); err != nil {
		return d, err
	}
	d.Children = []store.DeviceRef{}
	if err := q(`SELECT id, kind, name FROM devices WHERE parent_id = ? ORDER BY id`,
		func(r *sql.Rows) error {
			var x store.DeviceRef
			if err := r.Scan(&x.ID, &x.Kind, &x.Name); err != nil {
				return err
			}
			d.Children = append(d.Children, x)
			return nil
		}); err != nil {
		return d, err
	}
	return d, nil
}

// RenameDevice sets the display name of a device.
func (s *DB) RenameDevice(ctx context.Context, id int64, name string) error {
	r, err := s.db.ExecContext(ctx, `UPDATE devices SET name = ? WHERE id = ?`, strings.TrimSpace(name), id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}
