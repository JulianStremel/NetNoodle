package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/JulianStremel/netnoodle/internal/store"
)

func (s *DB) CreateOnboard(ctx context.Context, o store.OnboardSession, hash []byte, role string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM onboarding WHERE state IN ('created','enrolled','connected')`).Scan(&n); err != nil {
		return err
	}
	if n >= 20 {
		return store.ErrConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM peers WHERE name=?`, o.Name).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return store.ErrConflict
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO join_tokens(token_hash,role,name,uses_left,expires_at,created_at) VALUES (?,?,?,1,?,?)`, hash, role, o.Name, ts(o.Expires), ts(now))
	if err != nil {
		return err
	}
	jid, err := r.LastInsertId()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO onboarding(id,secret_hash,join_id,kind,name,platform,state,expires,updated) VALUES (?,?,?,?,?,?,'created',?,?)`, o.ID, o.SecretHash, jid, o.Kind, o.Name, o.Platform, ts(o.Expires), ts(now))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return store.ErrConflict
		}
		return err
	}
	return tx.Commit()
}

func scanOnboard(row interface{ Scan(...any) error }) (store.OnboardSession, error) {
	var o store.OnboardSession
	var exp, updated, steps string
	err := row.Scan(&o.ID, &o.SecretHash, &o.JoinID, &o.Kind, &o.Name, &o.Platform, &o.State, &o.Error, &o.PeerID, &exp, &updated, &steps)
	if err != nil {
		return o, notFound(err)
	}
	o.Expires, o.Updated = parseTS(exp), parseTS(updated)
	err = json.Unmarshal([]byte(steps), &o.Steps)
	return o, err
}

const onboardCols = `id,secret_hash,join_id,kind,name,platform,state,error,peer_id,expires,updated,steps`

func (s *DB) GetOnboard(ctx context.Context, id string) (store.OnboardSession, error) {
	return scanOnboard(s.db.QueryRowContext(ctx, `SELECT `+onboardCols+` FROM onboarding WHERE id=?`, id))
}
func (s *DB) ConnectOnboard(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE onboarding SET state='connected',updated=? WHERE peer_id=? AND state='enrolled' AND expires>?`, ts(now), id, ts(now))
	return err
}
func (s *DB) AddOnboardStep(ctx context.Context, id string, step store.OnboardStep) error {
	if len(step.Name) == 0 || len(step.Name) > 64 || len(step.Message) > 1024 {
		return store.ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	o, err := scanOnboard(tx.QueryRowContext(ctx, `SELECT `+onboardCols+` FROM onboarding WHERE id=?`, id))
	if err != nil {
		return err
	}
	if len(o.Steps) >= 64 || !o.Expires.After(step.At) || (o.State != "created" && o.State != "enrolled" && o.State != "connected") {
		return store.ErrConflict
	}
	if step.Name == "done" {
		if !step.OK || o.State != "connected" {
			return store.ErrConflict
		}
		o.State = "done"
	}
	o.Steps = append(o.Steps, step)
	b, err := json.Marshal(o.Steps)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE onboarding SET steps=?,state=?,updated=? WHERE id=?`, string(b), o.State, ts(step.At), id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// rollbackOnboard runs inside the same transaction as the state change.
func rollbackOnboard(ctx context.Context, tx *sql.Tx, o store.OnboardSession, state, reason string, now time.Time) error {
	if o.PeerID != 0 {
		// An actor can have sent its first hello before the installer failed.
		if _, err := tx.ExecContext(ctx, `DELETE FROM orders WHERE actor_peer_id=?`, o.PeerID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM peers WHERE id=?`, o.PeerID); err != nil {
			return err
		}
	}
	// Keep the consumed row: SQLite can reuse a deleted integer primary key.
	if _, err := tx.ExecContext(ctx, `UPDATE join_tokens SET uses_left=0 WHERE id=?`, o.JoinID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE onboarding SET state=?,error=?,updated=? WHERE id=?`, state, reason, ts(now), o.ID)
	return err
}
func (s *DB) AbortOnboard(ctx context.Context, id, reason string, now time.Time) error {
	if len(reason) > 1024 {
		return store.ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	o, err := scanOnboard(tx.QueryRowContext(ctx, `SELECT `+onboardCols+` FROM onboarding WHERE id=?`, id))
	if err != nil {
		return err
	}
	if o.State == "done" {
		return store.ErrConflict
	}
	if o.State == "aborted" || o.State == "expired" {
		return nil
	}
	if err = rollbackOnboard(ctx, tx, o, "aborted", reason, now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *DB) ExpireOnboard(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT `+onboardCols+` FROM onboarding WHERE state IN ('created','enrolled','connected') AND expires<=?`, ts(now))
	if err != nil {
		return err
	}
	var expired []store.OnboardSession
	for rows.Next() {
		o, e := scanOnboard(rows)
		if e != nil {
			rows.Close()
			return e
		}
		expired = append(expired, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, o := range expired {
		if err = rollbackOnboard(ctx, tx, o, "expired", "setup code expired", now); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM onboarding WHERE state IN ('done','aborted','expired') AND updated<=?`, ts(now.Add(-7*24*time.Hour)))
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *DB) PairOnboard(ctx context.Context, id, address, code string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	o, err := scanOnboard(tx.QueryRowContext(ctx, `SELECT `+onboardCols+` FROM onboarding WHERE id=?`, id))
	if err != nil {
		return err
	}
	if o.Kind != "agent-pull" || o.State != "enrolled" || !o.Expires.After(now) {
		return store.ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO pull_peers(peer_id,transport,address,pair_code,pair_expires,interval_s,next_pull) VALUES (?,'https',?,?,?,3600,?)`, o.PeerID, address, code, ts(o.Expires), ts(now))
	if err != nil {
		return store.ErrConflict
	}
	// Pull peers do not keep a usable bearer token.
	_, err = tx.ExecContext(ctx, `UPDATE peers SET token_hash=randomblob(32) WHERE id=?`, o.PeerID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
