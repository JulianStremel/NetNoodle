package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

// DeviceComponents returns one component per PURL of the device.
func (s *DB) DeviceComponents(ctx context.Context, deviceID int64) ([]proto.Component, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT purl, MIN(name), MIN(version), MIN(confidence)
		FROM components WHERE device_id = ? GROUP BY purl ORDER BY purl`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proto.Component
	for rows.Next() {
		var c proto.Component
		var conf string
		if err := rows.Scan(&c.PURL, &c.Name, &c.Version, &conf); err != nil {
			return nil, err
		}
		c.Confidence = proto.Confidence(conf)
		out = append(out, c)
	}
	return out, rows.Err()
}

// DevicesWithComponents returns the IDs of all devices with components.
func (s *DB) DevicesWithComponents(ctx context.Context) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT device_id FROM components ORDER BY device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func jsonText(v any, empty string) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return empty
	}
	return string(b)
}

func tsOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return ts(t)
}

// PutVulns inserts or updates vulnerabilities.
func (s *DB) PutVulns(ctx context.Context, vs []intel.Vuln, at time.Time) error {
	if len(vs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO vulns(id, aliases, summary, score, vector, kev, epss, epss_pct,
			published, modified, refs, facts, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET aliases = excluded.aliases, summary = excluded.summary,
			score = excluded.score, vector = excluded.vector, kev = excluded.kev, epss = excluded.epss,
			epss_pct = excluded.epss_pct, published = excluded.published, modified = excluded.modified,
			refs = excluded.refs, facts = excluded.facts, updated_at = excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := ts(at)
	for _, v := range vs {
		kev := 0
		if v.KEV {
			kev = 1
		}
		if _, err := stmt.ExecContext(ctx, v.ID, jsonText(v.Aliases, "[]"), v.Summary, v.Score, v.Vector, kev,
			v.EPSS, v.EPSSPct, tsOrEmpty(v.Published), tsOrEmpty(v.Modified),
			jsonText(v.Refs, "[]"), jsonText(v.Facts, "{}"), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SyncFindings makes fs the open findings of the device for this source.
func (s *DB) SyncFindings(ctx context.Context, deviceID int64, source string, fs []store.Finding, at time.Time) ([]store.Finding, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	prev := map[[2]string]string{}
	rows, err := tx.QueryContext(ctx, `SELECT purl, vuln_id, state FROM findings WHERE device_id = ? AND source = ?`, deviceID, source)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p, v, st string
		if err := rows.Scan(&p, &v, &st); err != nil {
			rows.Close()
			return nil, err
		}
		prev[[2]string{p, v}] = st
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO findings(device_id, purl, vuln_id, source, fixed, confidence,
			state, first_seen, last_seen, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, '')
		ON CONFLICT(device_id, purl, vuln_id, source) DO UPDATE SET fixed = excluded.fixed,
			confidence = excluded.confidence, state = 'open', last_seen = excluded.last_seen, resolved_at = ''`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	now := ts(at)
	var opened []store.Finding
	done := map[[2]string]bool{}
	for _, f := range fs {
		k := [2]string{f.PURL, f.VulnID}
		if done[k] {
			continue
		}
		done[k] = true
		if _, err := stmt.ExecContext(ctx, deviceID, f.PURL, f.VulnID, source, f.Fixed, f.Confidence, now, now); err != nil {
			return nil, err
		}
		if st, ok := prev[k]; !ok || st != "open" {
			f.DeviceID = deviceID
			opened = append(opened, f)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET state = 'resolved', resolved_at = ?
		WHERE device_id = ? AND source = ? AND state = 'open' AND last_seen < ?`, now, deviceID, source, now); err != nil {
		return nil, err
	}
	return opened, tx.Commit()
}

// exposedSQL lists the listening, non-loopback services of a finding's package.
const exposedSQL = `(SELECT group_concat(s.port || '/' || s.proto, ',') FROM services s
	WHERE s.device_id = f.device_id AND s.component = f.purl
	AND s.address NOT LIKE '127.%' AND s.address != '::1')`

// ListFindings returns findings, most urgent first: known exploited,
// exposed, then by CVSS score and EPSS.
func (s *DB) ListFindings(ctx context.Context, flt store.FindingFilter) ([]store.FindingRow, error) {
	var where []string
	var args []any
	switch flt.State {
	case "", "open":
		where = append(where, "f.state = 'open'")
	case "resolved":
		where = append(where, "f.state = 'resolved'")
	}
	if flt.DeviceID != 0 {
		where = append(where, "f.device_id = ?")
		args = append(args, flt.DeviceID)
	}
	if flt.MinScore > 0 {
		where = append(where, "v.score >= ?")
		args = append(args, flt.MinScore)
	}
	if flt.KEV {
		where = append(where, "v.kev = 1")
	}
	limit := flt.Limit
	if limit <= 0 {
		limit = 2000
	}
	limit = min(limit, 20000)
	q := `SELECT f.device_id, f.purl, f.vuln_id, f.fixed, f.confidence, f.source, f.state,
			f.first_seen, f.last_seen, f.resolved_at, d.name, d.kind,
			COALESCE(c.name, ''), COALESCE(c.version, ''),
			v.aliases, v.summary, v.score, v.vector, v.kev, v.epss, v.epss_pct, v.facts,
			COALESCE(` + exposedSQL + `, '') AS exposed
		FROM findings f
		JOIN vulns v ON v.id = f.vuln_id
		JOIN devices d ON d.id = f.device_id
		LEFT JOIN (SELECT device_id, purl, MIN(name) AS name, MIN(version) AS version
			FROM components GROUP BY device_id, purl) c ON c.device_id = f.device_id AND c.purl = f.purl`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += ` ORDER BY v.kev DESC, (exposed != '') DESC, v.score DESC, v.epss DESC, f.device_id, f.vuln_id LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.FindingRow{}
	for rows.Next() {
		var r store.FindingRow
		var first, last, resolved, aliases, facts, exposed string
		var kev int
		if err := rows.Scan(&r.DeviceID, &r.PURL, &r.VulnID, &r.Fixed, &r.Confidence, &r.Source, &r.State,
			&first, &last, &resolved, &r.DeviceName, &r.DeviceKind, &r.Package, &r.Version,
			&aliases, &r.Summary, &r.Score, &r.Vector, &kev, &r.EPSS, &r.EPSSPct, &facts, &exposed); err != nil {
			return nil, err
		}
		r.FirstSeen, r.LastSeen = parseTS(first), parseTS(last)
		if resolved != "" {
			r.ResolvedAt = parseTS(resolved)
		}
		r.KEV = kev == 1
		_ = json.Unmarshal([]byte(aliases), &r.Aliases)
		_ = json.Unmarshal([]byte(facts), &r.Facts)
		if r.Aliases == nil {
			r.Aliases = []string{}
		}
		r.Exposed = []string{}
		if exposed != "" {
			r.Exposed = strings.Split(exposed, ",")
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FindingStats counts the open findings.
func (s *DB) FindingStats(ctx context.Context) (store.FindingStats, error) {
	var st store.FindingStats
	var crit, high, med, low, unk, kev, exp sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
			SUM(v.score >= 9), SUM(v.score >= 7 AND v.score < 9), SUM(v.score >= 4 AND v.score < 7),
			SUM(v.score > 0 AND v.score < 4), SUM(v.score = 0), SUM(v.kev),
			SUM(`+exposedSQL+` IS NOT NULL),
			COUNT(DISTINCT f.device_id), COUNT(DISTINCT f.vuln_id)
		FROM findings f JOIN vulns v ON v.id = f.vuln_id WHERE f.state = 'open'`).
		Scan(&st.Open, &crit, &high, &med, &low, &unk, &kev, &exp, &st.Devices, &st.Vulns)
	st.Critical, st.High, st.Medium = int(crit.Int64), int(high.Int64), int(med.Int64)
	st.Low, st.Unknown, st.KEV, st.Exposed = int(low.Int64), int(unk.Int64), int(kev.Int64), int(exp.Int64)
	return st, err
}
