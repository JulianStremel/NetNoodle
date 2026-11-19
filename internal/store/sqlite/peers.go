package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"netnoodle/internal/store"
)

func (s *DB) CreateJoinToken(ctx context.Context, hash []byte, role, name string, uses int, expires time.Time) (int64, error) {
	if uses < 1 {
		uses = 1
	}
	r, err := s.db.ExecContext(ctx, `INSERT INTO join_tokens(token_hash, role, name, uses_left, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, hash, role, name, uses, ts(expires), ts(time.Now()))
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *DB) ListJoinTokens(ctx context.Context, now time.Time) ([]store.JoinToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, role, name, uses_left, expires_at, created_at FROM join_tokens
		WHERE uses_left > 0 AND expires_at > ? ORDER BY id`, ts(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.JoinToken{}
	for rows.Next() {
		var j store.JoinToken
		var exp, created string
		if err := rows.Scan(&j.ID, &j.Role, &j.Name, &j.UsesLeft, &exp, &created); err != nil {
			return nil, err
		}
		j.Expires, j.Created = parseTS(exp), parseTS(created)
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *DB) DeleteJoinToken(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM join_tokens WHERE id = ?`, id)
	return err
}

// Enroll consumes one use of a join token and creates the peer, in one
// transaction. A join token with a fixed name ignores the requested name.
func (s *DB) Enroll(ctx context.Context, joinHash []byte, name string, tokenHash []byte, now time.Time, allow func(name string) error) (store.Peer, error) {
	var p store.Peer
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()

	var jid int64
	var role, fixed string
	err = tx.QueryRowContext(ctx, `SELECT id, role, name FROM join_tokens
		WHERE token_hash = ? AND uses_left > 0 AND expires_at > ?`, joinHash, ts(now)).Scan(&jid, &role, &fixed)
	if err != nil {
		return p, notFound(err)
	}
	if fixed != "" {
		name = fixed
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return p, errors.New("peer name is required")
	}
	if allow != nil {
		if err := allow(name); err != nil {
			return p, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE join_tokens SET uses_left = uses_left - 1 WHERE id = ?`, jid); err != nil {
		return p, err
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO peers(name, role, token_hash, created_at, last_seen) VALUES (?, ?, ?, ?, ?)`,
		name, role, tokenHash, ts(now), ts(now))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return p, store.ErrConflict
		}
		return p, err
	}
	p.ID, _ = r.LastInsertId()
	p.Name, p.Role, p.Created, p.LastSeen = name, role, now, now
	return p, tx.Commit()
}

func scanPeer(row interface{ Scan(...any) error }) (store.Peer, error) {
	var p store.Peer
	var created string
	var last sql.NullString
	var disabled int
	err := row.Scan(&p.ID, &p.Name, &p.Role, &disabled, &created, &last)
	if err != nil {
		return p, notFound(err)
	}
	p.Disabled = disabled != 0
	p.Created = parseTS(created)
	if last.Valid {
		p.LastSeen = parseTS(last.String)
	}
	return p, nil
}

func (s *DB) PeerByToken(ctx context.Context, hash []byte) (store.Peer, error) {
	return scanPeer(s.db.QueryRowContext(ctx, `SELECT id, name, role, disabled, created_at, last_seen
		FROM peers WHERE token_hash = ?`, hash))
}

func (s *DB) TouchPeer(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE peers SET last_seen = ? WHERE id = ?`, ts(now), id)
	return err
}

func (s *DB) ListPeers(ctx context.Context) ([]store.Peer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, role, disabled, created_at, last_seen FROM peers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Peer{}
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *DB) SetPeerDisabled(ctx context.Context, id int64, disabled bool) error {
	d := 0
	if disabled {
		d = 1
	}
	r, err := s.db.ExecContext(ctx, `UPDATE peers SET disabled = ? WHERE id = ?`, d, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}
