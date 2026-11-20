package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

func (s *DB) SetTags(ctx context.Context, id int64, tags []string) error {
	if e := store.ValidateTags(tags); e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var n int
	if e = tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE id=?`, id).Scan(&n); e != nil {
		return notFound(e)
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM device_tags WHERE device_id=?`, id); e != nil {
		return e
	}
	for _, t := range tags {
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO device_tags VALUES (?,?)`, id, t); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *DB) Tags(ctx context.Context, id int64) ([]string, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT tag FROM device_tags WHERE device_id=? ORDER BY tag`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if e = rows.Scan(&t); e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (s *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	e := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	return v, notFound(e)
}
func (s *DB) SetSetting(ctx context.Context, key, value string) error {
	_, e := s.db.ExecContext(ctx, `INSERT INTO settings VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, ts(time.Now()))
	return e
}

const proposalSelect = `SELECT p.id,p.device_id,d.name,p.vuln_id,p.purl,p.action,p.tier,p.state,p.reason,p.decided_by,p.params,p.ttl_s,p.created_at,p.updated_at,p.expires_at,p.decided_user,p.decided_at FROM proposals p JOIN devices d ON d.id=p.device_id`

func scanProposal(r interface{ Scan(...any) error }) (store.Proposal, error) {
	var p store.Proposal
	var by, params, c, u, x, a string
	e := r.Scan(&p.ID, &p.DeviceID, &p.DeviceName, &p.VulnID, &p.PURL, &p.Action, &p.Tier, &p.State, &p.Reason, &by, &params, &p.TTL, &c, &u, &x, &p.DecidedUser, &a)
	if e != nil {
		return p, notFound(e)
	}
	if e = json.Unmarshal([]byte(by), &p.DecidedBy); e != nil {
		return p, e
	}
	if e = json.Unmarshal([]byte(params), &p.Params); e != nil {
		return p, e
	}
	p.CreatedAt = parseTS(c)
	p.UpdatedAt = parseTS(u)
	if x != "" {
		p.ExpiresAt = parseTS(x)
	}
	if a != "" {
		p.DecidedAt = parseTS(a)
	}
	return p, nil
}
func (s *DB) GetProposal(ctx context.Context, id int64) (store.Proposal, error) {
	return scanProposal(s.db.QueryRowContext(ctx, proposalSelect+` WHERE p.id=?`, id))
}
func (s *DB) UpsertProposal(ctx context.Context, p store.Proposal) (store.Proposal, bool, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return p, false, e
	}
	defer tx.Rollback()
	// This lookup and write share a transaction. The partial index also enforces it.
	old, e := scanProposal(tx.QueryRowContext(ctx, proposalSelect+` WHERE p.device_id=? AND p.vuln_id=? AND p.action=? AND p.state IN ('pending','approved','auto')`, p.DeviceID, p.VulnID, p.Action))
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		return p, false, e
	}
	fresh := errors.Is(e, store.ErrNotFound)
	if !fresh && old.State == "approved" {
		return old, false, nil
	}
	if p.State != "pending" && p.State != "auto" && p.State != "notify" {
		return p, false, fmt.Errorf("invalid proposal state")
	}
	by, e := json.Marshal(p.DecidedBy)
	if e != nil {
		return p, false, e
	}
	params, e := json.Marshal(p.Params)
	if e != nil {
		return p, false, e
	}
	if p.DecidedBy == nil {
		by = []byte("[]")
	}
	if p.Params == nil {
		params = []byte("{}")
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	p.UpdatedAt = p.CreatedAt
	if p.State == "pending" {
		p.ExpiresAt = p.CreatedAt.Add(7 * 24 * time.Hour)
	}
	if fresh {
		r, err := tx.ExecContext(ctx, `INSERT INTO proposals(device_id,vuln_id,purl,action,tier,state,reason,decided_by,params,ttl_s,created_at,updated_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.DeviceID, p.VulnID, p.PURL, p.Action, p.Tier, p.State, p.Reason, string(by), string(params), p.TTL, ts(p.CreatedAt), ts(p.UpdatedAt), tsOrEmpty(p.ExpiresAt))
		if err != nil {
			return p, false, err
		}
		p.ID, _ = r.LastInsertId()
	} else {
		p.ID = old.ID
		p.CreatedAt = old.CreatedAt
		if p.State == "pending" {
			p.ExpiresAt = p.CreatedAt.Add(7 * 24 * time.Hour)
		}
		_, e = tx.ExecContext(ctx, `UPDATE proposals SET purl=?,tier=?,state=?,reason=?,decided_by=?,params=?,ttl_s=?,updated_at=?,expires_at=? WHERE id=?`, p.PURL, p.Tier, p.State, p.Reason, string(by), string(params), p.TTL, ts(p.UpdatedAt), tsOrEmpty(p.ExpiresAt), p.ID)
		if e != nil {
			return p, false, e
		}
	}
	if e = tx.Commit(); e != nil {
		return p, false, e
	}
	p, e = s.GetProposal(ctx, p.ID)
	return p, fresh || old.State != p.State, e
}
func (s *DB) ListProposals(ctx context.Context, f store.ProposalFilter) ([]store.Proposal, error) {
	q := proposalSelect + ` WHERE 1=1`
	args := []any{}
	if f.State != "" && f.State != "all" {
		q += ` AND p.state=?`
		args = append(args, f.State)
	}
	if f.DeviceID != 0 {
		q += ` AND p.device_id=?`
		args = append(args, f.DeviceID)
	}
	if f.Limit <= 0 {
		f.Limit = 2000
	}
	if f.Limit > 20000 {
		f.Limit = 20000
	}
	args = append(args, f.Limit)
	rows, e := s.db.QueryContext(ctx, q+` ORDER BY p.id DESC LIMIT ?`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []store.Proposal{}
	for rows.Next() {
		p, e := scanProposal(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *DB) DecideProposal(ctx context.Context, id int64, state, user string, at time.Time) error {
	if state != "approved" && state != "rejected" {
		return fmt.Errorf("invalid decision")
	}
	r, e := s.db.ExecContext(ctx, `UPDATE proposals SET state=?,decided_user=?,decided_at=?,updated_at=? WHERE id=? AND state='pending'`, state, user, ts(at), ts(at), id)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return store.ErrConflict
	}
	return nil
}
func (s *DB) ExpireProposals(ctx context.Context, before time.Time) error {
	_, e := s.db.ExecContext(ctx, `UPDATE proposals SET state='expired',updated_at=? WHERE state='pending' AND created_at<?`, ts(time.Now()), ts(before))
	return e
}
func (s *DB) ResolveProposals(ctx context.Context, id int64, open []string) error {
	// A temporary set avoids SQLite's parameter limit on large inventories.
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS decide_open_vulns (id TEXT PRIMARY KEY); DELETE FROM decide_open_vulns`); e != nil {
		return e
	}
	for _, v := range open {
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO decide_open_vulns VALUES (?)`, v); e != nil {
			return e
		}
	}
	_, e = tx.ExecContext(ctx, `UPDATE proposals SET state='resolved',updated_at=? WHERE device_id=? AND state IN ('pending','approved','auto') AND vuln_id NOT IN (SELECT id FROM decide_open_vulns)`, ts(time.Now()), id)
	if e != nil {
		return e
	}
	return tx.Commit()
}

// OpenVulnIDs returns the full set, independently of the UI's row limit.
func (s *DB) OpenVulnIDs(ctx context.Context, id int64) ([]string, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT DISTINCT vuln_id FROM findings WHERE device_id=? AND state='open'`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if e = rows.Scan(&v); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
