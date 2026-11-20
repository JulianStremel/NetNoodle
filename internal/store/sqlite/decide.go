package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/proto"
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
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now := time.Now()
	if _, e = tx.ExecContext(ctx, `INSERT INTO settings VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, ts(now)); e != nil {
		return e
	}
	if key == "decide.killswitch" && value == "on" {
		// One update, atomic with the setting so readers never see a partial switch.
		if _, e = tx.ExecContext(ctx, `UPDATE proposals SET state='pending',tier='approve',target_snapshot='[]',decided_user='',decided_at='',reason='kill switch',updated_at=?,expires_at=? WHERE state='auto' OR (state='no-actor' AND tier='auto') OR id IN (SELECT proposal_id FROM orders WHERE state='queued' AND revert=0)`, ts(now), ts(now.Add(7*24*time.Hour))); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE orders SET state='cancelled',message='kill switch',done_at=? WHERE state='queued' AND revert=0`, ts(now)); e != nil {
			return e
		}
	}
	return tx.Commit()
}

const proposalSelect = `SELECT p.id,p.device_id,d.name,p.vuln_id,p.purl,p.action,p.tier,p.state,p.reason,p.decided_by,p.params,p.ttl_s,p.created_at,p.updated_at,p.expires_at,p.decided_user,p.decided_at,p.target_snapshot FROM proposals p JOIN devices d ON d.id=p.device_id`

func scanProposal(r interface{ Scan(...any) error }) (store.Proposal, error) {
	var p store.Proposal
	var by, params, c, u, x, a, snapshot string
	e := r.Scan(&p.ID, &p.DeviceID, &p.DeviceName, &p.VulnID, &p.PURL, &p.Action, &p.Tier, &p.State, &p.Reason, &by, &params, &p.TTL, &c, &u, &x, &p.DecidedUser, &a, &snapshot)
	if e != nil {
		return p, notFound(e)
	}
	if e = json.Unmarshal([]byte(by), &p.DecidedBy); e != nil {
		return p, e
	}
	if e = json.Unmarshal([]byte(params), &p.Params); e != nil {
		return p, e
	}
	if e = json.Unmarshal([]byte(snapshot), &p.TargetSnapshot); e != nil {
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
	// Reviewed and executed scopes are immutable during finding re-evaluation.
	locked, err := scanProposal(tx.QueryRowContext(ctx, proposalSelect+` WHERE p.device_id=? AND p.vuln_id=? AND p.action=? AND p.state IN ('approved','ordered','done','failed','no-actor','reverted') ORDER BY p.id DESC LIMIT 1`, p.DeviceID, p.VulnID, p.Action))
	if err == nil {
		return locked, false, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return p, false, err
	}
	old, e := scanProposal(tx.QueryRowContext(ctx, proposalSelect+` WHERE p.device_id=? AND p.vuln_id=? AND p.action=? AND p.state NOT IN ('approved','rejected','ordered','done','failed','no-actor','reverted') AND NOT EXISTS(SELECT 1 FROM orders WHERE proposal_id=p.id) ORDER BY p.updated_at DESC,p.id DESC LIMIT 1`, p.DeviceID, p.VulnID, p.Action))
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		return p, false, e
	}
	fresh := errors.Is(e, store.ErrNotFound)
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
	if p.State == "pending" || p.State == "auto" {
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
		if old.State != "resolved" && old.State != "expired" {
			p.CreatedAt = old.CreatedAt
		}
		if p.State == "pending" {
			if old.State == "pending" {
				p.ExpiresAt = old.ExpiresAt
			} else {
				p.ExpiresAt = p.UpdatedAt.Add(7 * 24 * time.Hour)
			}
		}
		_, e = tx.ExecContext(ctx, `UPDATE proposals SET purl=?,tier=?,state=?,reason=?,decided_by=?,params=?,ttl_s=?,created_at=?,updated_at=?,expires_at=? WHERE id=?`, p.PURL, p.Tier, p.State, p.Reason, string(by), string(params), p.TTL, ts(p.CreatedAt), ts(p.UpdatedAt), tsOrEmpty(p.ExpiresAt), p.ID)
		if e != nil {
			return p, false, e
		}
	}
	snapshot := "[]"
	if p.State == "auto" {
		if !fresh && old.State == "auto" {
			b, _ := json.Marshal(old.TargetSnapshot)
			snapshot = string(b)
		} else {
			snapshot, e = targetSnapshot(ctx, tx, p.DeviceID)
			if e != nil {
				return p, false, e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE proposals SET target_snapshot=? WHERE id=?`, snapshot, p.ID); e != nil {
		return p, false, e
	}
	if e = tx.Commit(); e != nil {
		return p, false, e
	}
	p, e = s.GetProposal(ctx, p.ID)
	reopened := old.State != "pending" && old.State != "auto" && (p.State == "pending" || p.State == "auto")
	return p, fresh || reopened, e
}
func (s *DB) ListProposals(ctx context.Context, f store.ProposalFilter) ([]store.Proposal, error) {
	q := proposalSelect + ` WHERE 1=1`
	args := []any{}
	if f.State != "" && f.State != "all" {
		states := strings.Split(f.State, ",")
		q += ` AND p.state IN (` + strings.TrimSuffix(strings.Repeat("?,", len(states)), ",") + `)`
		for _, state := range states {
			args = append(args, state)
		}
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
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var device int64
	if e = tx.QueryRowContext(ctx, `SELECT device_id FROM proposals WHERE id=?`, id).Scan(&device); e != nil {
		return notFound(e)
	}
	snapshot := "[]"
	if state == "approved" {
		snapshot, e = targetSnapshot(ctx, tx, device)
		if e != nil {
			return e
		}
	}
	r, e := tx.ExecContext(ctx, `UPDATE proposals SET state=?,decided_user=?,decided_at=?,updated_at=?,expires_at=?,target_snapshot=? WHERE id=? AND state='pending' AND (expires_at='' OR expires_at>?)`, state, user, ts(at), ts(at), ts(at.Add(7*24*time.Hour)), snapshot, id, ts(at))
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return store.ErrConflict
	}
	return tx.Commit()
}

func targetSnapshot(ctx context.Context, tx *sql.Tx, device int64) (string, error) {
	rows, e := tx.QueryContext(ctx, `SELECT kind,value,strength FROM device_ids WHERE device_id=? AND strength='strong' AND kind NOT IN ('ip','hostname') AND value<>'' ORDER BY kind,value LIMIT 32`, device)
	if e != nil {
		return "", e
	}
	defer rows.Close()
	ids := []proto.Identifier{}
	for rows.Next() {
		var id proto.Identifier
		if e = rows.Scan(&id.Kind, &id.Value, &id.Strength); e != nil {
			return "", e
		}
		ids = append(ids, id)
	}
	if e = rows.Err(); e != nil {
		return "", e
	}
	b, e := json.Marshal(ids)
	return string(b), e
}

func (s *DB) ExpireProposals(ctx context.Context, before time.Time) error {
	_, e := s.db.ExecContext(ctx, `UPDATE proposals SET state='expired',updated_at=? WHERE id IN (SELECT id FROM proposals WHERE state IN ('pending','approved','no-actor') AND NOT EXISTS(SELECT 1 FROM orders WHERE proposal_id=proposals.id AND revert=0 AND state<>'cancelled') AND ((expires_at<>'' AND expires_at<=?) OR (expires_at='' AND created_at<?)) LIMIT 200)`, ts(time.Now()), ts(before.Add(7*24*time.Hour)), ts(before))
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
	if _, e = tx.ExecContext(ctx, `INSERT INTO events(at,type,actor,summary,data)
 SELECT ?, 'order.finding-fixed','server','finding fixed on ' || (SELECT name FROM devices WHERE id=?) || '; revert available','{"severity":"info"}'
 FROM orders o JOIN proposals p ON p.id=o.proposal_id WHERE p.device_id=? AND p.vuln_id NOT IN (SELECT id FROM decide_open_vulns) AND o.state='done' AND o.revert=0 AND o.finding_fixed_notified=0`, ts(time.Now()), id, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE orders SET finding_fixed_notified=1 WHERE state='done' AND revert=0 AND proposal_id IN (SELECT id FROM proposals WHERE device_id=? AND vuln_id NOT IN (SELECT id FROM decide_open_vulns))`, id); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `UPDATE proposals SET state='resolved',updated_at=? WHERE device_id=? AND state IN ('notify','pending','auto','ordered','done','no-actor') AND vuln_id NOT IN (SELECT id FROM decide_open_vulns)`, ts(time.Now()), id)
	if e != nil {
		return e
	}
	return tx.Commit()
}

func (s *DB) ProposalStats(ctx context.Context) (map[string]int, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT state,COUNT(*) FROM proposals GROUP BY state`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var state string
		var count int
		if e := rows.Scan(&state, &count); e != nil {
			return nil, e
		}
		out[state] = count
	}
	return out, rows.Err()
}

// PurgeProposals retains active proposals and recently updated history.
func (s *DB) PurgeProposals(ctx context.Context, before time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `DELETE FROM orders WHERE id IN (SELECT id FROM orders WHERE state IN ('done','rejected','cancelled','expired','failed') AND done_at<>'' AND done_at<? AND revert_due_at='' AND (revert=1 OR revert_action='' OR reverted=1 OR state<>'done') AND NOT EXISTS(SELECT 1 FROM orders r WHERE r.revert_of=orders.id AND r.state IN ('queued','sent','uncertain')) AND NOT EXISTS(SELECT 1 FROM orders original WHERE original.id=orders.revert_of AND (original.state='uncertain' OR original.revert_due_at<>'')) LIMIT 200)`, ts(before)); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `DELETE FROM proposals WHERE id IN (SELECT id FROM proposals WHERE state IN ('rejected','resolved','expired','notify','done','failed','reverted') AND updated_at<? AND NOT EXISTS(SELECT 1 FROM orders WHERE proposal_id=proposals.id) LIMIT 200)`, ts(before))
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
