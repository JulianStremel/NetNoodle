package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

const pullCols = `p.id, p.name, p.role, p.disabled, p.created_at, p.last_seen, p.version,
	q.transport, q.address, q.pin, q.pair_code, q.pair_expires, q.interval_s, q.next_pull, q.last_pull, q.last_error`

func scanPull(row interface{ Scan(...any) error }) (store.PullPeer, error) {
	var p store.PullPeer
	var created, next string
	var last, pexp, lpull sql.NullString
	var disabled int
	var interval int64
	err := row.Scan(&p.ID, &p.Name, &p.Role, &disabled, &created, &last, &p.Version,
		&p.Transport, &p.Address, &p.Pin, &p.PairCode, &pexp, &interval, &next, &lpull, &p.LastError)
	if err != nil {
		return p, notFound(err)
	}
	p.Disabled = disabled != 0
	p.Created = parseTS(created)
	if last.Valid {
		p.LastSeen = parseTS(last.String)
	}
	if pexp.Valid {
		p.PairExpires = parseTS(pexp.String)
	}
	if lpull.Valid {
		p.LastPull = parseTS(lpull.String)
	}
	p.Interval = time.Duration(interval) * time.Second
	p.NextPull = parseTS(next)
	return p, nil
}

func nullTS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return ts(t)
}

func (s *DB) CreatePullPeer(ctx context.Context, p store.PullPeer, tokenHash []byte, now time.Time) (store.PullPeer, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `INSERT INTO peers(name, role, token_hash, created_at) VALUES (?, ?, ?, ?)`,
		p.Name, store.RoleAgent, tokenHash, ts(now))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return p, store.ErrConflict
		}
		return p, err
	}
	p.ID, _ = r.LastInsertId()
	if _, err := tx.ExecContext(ctx, `INSERT INTO pull_peers(peer_id, transport, address, pin, pair_code, pair_expires, interval_s, next_pull)
		VALUES (?, ?, ?, '', ?, ?, ?, ?)`, p.ID, p.Transport, p.Address, p.PairCode, nullTS(p.PairExpires),
		int64(p.Interval/time.Second), ts(p.NextPull)); err != nil {
		return p, err
	}
	if err := tx.Commit(); err != nil {
		return p, err
	}
	return s.GetPullPeer(ctx, p.ID)
}

func (s *DB) queryPulls(ctx context.Context, where string, args ...any) ([]store.PullPeer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+pullCols+` FROM pull_peers q JOIN peers p ON p.id = q.peer_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.PullPeer{}
	for rows.Next() {
		p, err := scanPull(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *DB) ListPullPeers(ctx context.Context) ([]store.PullPeer, error) {
	return s.queryPulls(ctx, `ORDER BY p.name`)
}

func (s *DB) GetPullPeer(ctx context.Context, id int64) (store.PullPeer, error) {
	return scanPull(s.db.QueryRowContext(ctx, `SELECT `+pullCols+` FROM pull_peers q JOIN peers p ON p.id = q.peer_id WHERE q.peer_id = ?`, id))
}

func (s *DB) DuePullPeers(ctx context.Context, now time.Time) ([]store.PullPeer, error) {
	return s.queryPulls(ctx, `WHERE p.disabled = 0 AND q.next_pull <= ? ORDER BY q.next_pull`, ts(now))
}

func affected(r sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) SetPairCode(ctx context.Context, id int64, code string, expires, next time.Time) error {
	return affected(s.db.ExecContext(ctx, `UPDATE pull_peers SET pin = '', pair_code = ?, pair_expires = ?, next_pull = ?, last_error = ''
		WHERE peer_id = ?`, code, ts(expires), ts(next), id))
}

func (s *DB) SetPin(ctx context.Context, id int64, code, pin string) error {
	err := affected(s.db.ExecContext(ctx, `UPDATE pull_peers SET pin = ?, pair_code = '', pair_expires = NULL
		WHERE peer_id = ? AND pair_code = ? AND pair_code != ''`, pin, id, code))
	if err == store.ErrNotFound {
		return store.ErrConflict
	}
	return err
}

func (s *DB) SetPullResult(ctx context.Context, id int64, ok bool, at, next time.Time, errText string) error {
	if ok {
		return affected(s.db.ExecContext(ctx, `UPDATE pull_peers SET next_pull = ?, last_error = ?, last_pull = ? WHERE peer_id = ?`,
			ts(next), errText, ts(at), id))
	}
	return affected(s.db.ExecContext(ctx, `UPDATE pull_peers SET next_pull = ?, last_error = ? WHERE peer_id = ?`, ts(next), errText, id))
}

func (s *DB) SetNextPull(ctx context.Context, id int64, next time.Time) error {
	return affected(s.db.ExecContext(ctx, `UPDATE pull_peers SET next_pull = ? WHERE peer_id = ?`, ts(next), id))
}
