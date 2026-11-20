package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/JulianStremel/netnoodle/internal/orders"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func (s *DB) SetActorCaps(ctx context.Context, id int64, caps []proto.Capability, now time.Time) error {
	if caps == nil {
		caps = []proto.Capability{}
	}
	b, e := json.Marshal(caps)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, `INSERT INTO actor_caps VALUES (?,?,?) ON CONFLICT(peer_id) DO UPDATE SET caps=excluded.caps,updated_at=excluded.updated_at`, id, string(b), ts(now))
	return e
}
func (s *DB) ListActors(ctx context.Context) ([]store.ActorCaps, error) {
	ps, e := s.ListPeers(ctx)
	if e != nil {
		return nil, e
	}
	out := []store.ActorCaps{}
	for _, p := range ps {
		if p.Role != store.RoleActor {
			continue
		}
		a := store.ActorCaps{Peer: p, Capabilities: []proto.Capability{}}
		var b, u string
		e = s.db.QueryRowContext(ctx, `SELECT caps,updated_at FROM actor_caps WHERE peer_id=?`, p.ID).Scan(&b, &u)
		if e == nil {
			if e = json.Unmarshal([]byte(b), &a.Capabilities); e != nil {
				return nil, e
			}
			a.UpdatedAt = parseTS(u)
		} else if !errors.Is(e, sql.ErrNoRows) {
			return nil, e
		}
		out = append(out, a)
	}
	return out, nil
}

const orderSelect = `SELECT id,proposal_id,actor_peer_id,state,payload,sig,created_at,sent_at,done_at,message,revert_action,revert_due_at,reverted,revert_attempts FROM orders`

func scanOrder(r interface{ Scan(...any) error }) (store.Order, error) {
	var o store.Order
	var c, s, d, due string
	e := r.Scan(&o.ID, &o.ProposalID, &o.ActorPeerID, &o.State, &o.Envelope.Payload, &o.Envelope.Sig, &c, &s, &d, &o.Message, &o.RevertAction, &due, &o.Reverted, &o.RevertAttempts)
	if e != nil {
		return o, notFound(e)
	}
	if e = json.Unmarshal(o.Envelope.Payload, &o.Order); e != nil {
		return o, e
	}
	o.CreatedAt = parseTS(c)
	o.SentAt = parseTS(s)
	o.DoneAt = parseTS(d)
	o.RevertDueAt = parseTS(due)
	return o, nil
}
func (s *DB) GetOrder(ctx context.Context, id string) (store.Order, error) {
	return scanOrder(s.db.QueryRowContext(ctx, orderSelect+` WHERE id=?`, id))
}

// Worker queries have no UI row limit, so older work cannot be starved by history.
func (s *DB) PlanningProposals(ctx context.Context) ([]store.Proposal, error) {
	rows, err := s.db.QueryContext(ctx, proposalSelect+` WHERE p.state IN ('approved','auto','no-actor') AND NOT EXISTS(SELECT 1 FROM orders WHERE proposal_id=p.id AND revert=0) ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Proposal{}
	for rows.Next() {
		p, err := scanProposal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *DB) queryOrders(ctx context.Context, query string, args ...any) ([]store.Order, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Order{}
	for rows.Next() {
		o, err := scanOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
func (s *DB) DueReverts(ctx context.Context, now time.Time) ([]store.Order, error) {
	return s.queryOrders(ctx, orderSelect+` WHERE state='done' AND revert=0 AND reverted=0 AND revert_action<>'' AND revert_attempts<6
	 AND ((revert_due_at<>'' AND revert_due_at<=?) OR (revert_attempts=0 AND proposal_id IN (SELECT id FROM proposals WHERE state='resolved')))
	 AND NOT EXISTS(SELECT 1 FROM orders r WHERE r.revert_of=orders.id AND r.state IN ('queued','sent')) ORDER BY created_at,id`, ts(now))
}
func (s *DB) ExpiringOrders(ctx context.Context, now time.Time) ([]store.Order, error) {
	return s.queryOrders(ctx, orderSelect+` WHERE state IN ('queued','sent') AND not_after<=?`, ts(now))
}
func (s *DB) ListOrders(ctx context.Context, f store.OrderFilter) ([]store.Order, error) {
	q := orderSelect + ` WHERE 1=1`
	args := []any{}
	if f.ProposalID != 0 {
		q += ` AND proposal_id=?`
		args = append(args, f.ProposalID)
	}
	if f.State != "" {
		q += ` AND state=?`
		args = append(args, f.State)
	}
	if f.Limit <= 0 {
		f.Limit = 2000
	}
	if f.Limit > 20000 {
		f.Limit = 20000
	}
	args = append(args, f.Limit)
	rows, e := s.db.QueryContext(ctx, q+` ORDER BY created_at DESC,id LIMIT ?`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []store.Order{}
	for rows.Next() {
		o, e := scanOrder(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
func (s *DB) QueueOrder(ctx context.Context, o store.Order) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var state string
	if e = tx.QueryRowContext(ctx, `SELECT state FROM proposals WHERE id=?`, o.ProposalID).Scan(&state); e != nil {
		return notFound(e)
	}
	if !o.Revert && state != "approved" && state != "auto" && state != "no-actor" {
		return store.ErrConflict
	}
	if o.Revert {
		// Reserve an attempt and consume its schedule atomically with insertion.
		r, e := tx.ExecContext(ctx, `UPDATE orders SET revert_attempts=revert_attempts+1,revert_due_at='' WHERE id=? AND state='done' AND revert=0 AND reverted=0 AND revert_action<>'' AND revert_attempts<6 AND NOT EXISTS(SELECT 1 FROM orders r WHERE r.revert_of=? AND r.state IN ('queued','sent'))`, o.RevertOf, o.RevertOf)
		if e != nil {
			return e
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return store.ErrConflict
		}
	}
	targets, e := json.Marshal(o.Targets)
	if e != nil {
		return e
	}
	params, e := json.Marshal(o.Params)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO orders(id,proposal_id,actor_peer_id,action,targets,params,ttl_s,revert,revert_of,state,payload,sig,created_at,not_after,revert_action) VALUES (?,?,?,?,?,?,?,?,?,'queued',?,?,?,?,?)`, o.ID, o.ProposalID, o.ActorPeerID, o.Action, string(targets), string(params), o.TTL, o.Revert, o.RevertOf, o.Envelope.Payload, o.Envelope.Sig, ts(o.CreatedAt), ts(o.NotAfter), o.RevertAction)
	if e != nil {
		return e
	}
	if !o.Revert {
		if _, e = tx.ExecContext(ctx, `UPDATE proposals SET state='ordered',updated_at=? WHERE id=?`, ts(o.CreatedAt), o.ProposalID); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *DB) SendOrders(ctx context.Context, peer int64, now time.Time) ([]orders.Envelope, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT payload,sig FROM orders WHERE actor_peer_id=? AND state='queued' AND not_after>? ORDER BY created_at,id LIMIT 64`, peer, ts(now))
	if e != nil {
		return nil, e
	}
	out := []orders.Envelope{}
	ids := []string{}
	for rows.Next() {
		var env orders.Envelope
		if e = rows.Scan(&env.Payload, &env.Sig); e != nil {
			rows.Close()
			return nil, e
		}
		var o proto.Order
		if e = json.Unmarshal(env.Payload, &o); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, o.ID)
		out = append(out, env)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for _, id := range ids {
		if _, e = tx.ExecContext(ctx, `UPDATE orders SET state='sent',sent_at=? WHERE id=?`, ts(now), id); e != nil {
			return nil, e
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}
func (s *DB) FinishOrder(ctx context.Context, peer int64, r proto.OrderResult, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	o, e := scanOrder(tx.QueryRowContext(ctx, orderSelect+` WHERE id=? AND actor_peer_id=?`, r.OrderID, peer))
	if e != nil {
		return e
	}
	if o.State != "sent" || !o.NotAfter.After(now) {
		return store.ErrConflict
	}
	if r.Status != proto.OrderDone && r.Status != proto.OrderFailed && r.Status != proto.OrderRejected {
		return store.ErrConflict
	}
	due := time.Time{}
	if r.Status == proto.OrderDone && !o.Revert && o.RevertAction != "" {
		var proposalState string
		if e = tx.QueryRowContext(ctx, `SELECT state FROM proposals WHERE id=?`, o.ProposalID).Scan(&proposalState); e != nil {
			return e
		}
		if proposalState == "resolved" {
			due = now
		} else if o.TTL > 0 {
			due = now.Add(time.Duration(o.TTL) * time.Second)
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE orders SET state=?,done_at=?,message=?,revert_due_at=? WHERE id=?`, r.Status, ts(now), r.Message, tsOrEmpty(due), o.ID); e != nil {
		return e
	}
	if o.Revert {
		if r.Status == proto.OrderDone {
			_, e = tx.ExecContext(ctx, `UPDATE orders SET reverted=1,revert_due_at='' WHERE id=?`, o.RevertOf)
			if e == nil {
				_, e = tx.ExecContext(ctx, `UPDATE proposals SET state='reverted',updated_at=? WHERE id=?`, ts(now), o.ProposalID)
			}
		} else {
			_, e = tx.ExecContext(ctx, `UPDATE orders SET revert_due_at=? WHERE id=? AND revert_attempts<6`, ts(now.Add(10*time.Minute)), o.RevertOf)
		}
	} else {
		state := "failed"
		if r.Status == proto.OrderDone {
			state = "done"
		}
		_, e = tx.ExecContext(ctx, `UPDATE proposals SET state=?,reason=CASE WHEN ?='failed' THEN ? ELSE reason END,updated_at=? WHERE id=?`, state, state, r.Message, ts(now), o.ProposalID)
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *DB) ExpireOrders(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `UPDATE proposals SET state='failed',reason='order expired',updated_at=? WHERE id IN (SELECT proposal_id FROM orders WHERE revert=0 AND state IN ('queued','sent') AND not_after<=?)`, ts(now), ts(now)); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE orders SET revert_due_at=? WHERE revert_attempts<6 AND id IN (SELECT revert_of FROM orders WHERE revert=1 AND state IN ('queued','sent') AND not_after<=?)`, ts(now.Add(10*time.Minute)), ts(now)); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE orders SET state='expired',message='order expired',done_at=? WHERE state IN ('queued','sent') AND not_after<=?`, ts(now), ts(now)); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *DB) SetProposalOrderState(ctx context.Context, id int64, state, msg string, now time.Time) error {
	_, e := s.db.ExecContext(ctx, `UPDATE proposals SET state=?,reason=CASE WHEN ?='' THEN reason ELSE ? END,updated_at=? WHERE id=? AND state IN ('approved','auto','no-actor')`, state, msg, msg, ts(now), id)
	return e
}
func (s *DB) ScheduleRevert(ctx context.Context, id string, now time.Time) error {
	r, e := s.db.ExecContext(ctx, `UPDATE orders SET revert_due_at=? WHERE id=? AND state='done' AND revert=0 AND reverted=0 AND revert_action<>'' AND revert_attempts<6 AND NOT EXISTS(SELECT 1 FROM orders r WHERE r.revert_of=? AND r.state IN ('queued','sent'))`, ts(now), id, id)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return store.ErrConflict
	}
	return nil
}
