package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
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
		if p.Role != store.RoleActor || p.Provisional {
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

const orderSelect = `SELECT id,proposal_id,actor_peer_id,state,payload,sig,created_at,sent_at,done_at,message,revert_action,revert_due_at,reverted,revert_attempts,result_json<>'' FROM orders`

func scanOrder(r interface{ Scan(...any) error }) (store.Order, error) {
	var o store.Order
	var c, s, d, due string
	e := r.Scan(&o.ID, &o.ProposalID, &o.ActorPeerID, &o.State, &o.Envelope.Payload, &o.Envelope.Sig, &c, &s, &d, &o.Message, &o.RevertAction, &due, &o.Reverted, &o.RevertAttempts, &o.ResultRecorded)
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

// Worker queries process bounded batches, independently of UI limits.
func (s *DB) PlanningProposals(ctx context.Context) ([]store.Proposal, error) {
	rows, err := s.db.QueryContext(ctx, proposalSelect+` WHERE p.state IN ('approved','auto','no-actor') AND NOT EXISTS(SELECT 1 FROM orders WHERE proposal_id=p.id AND revert=0 AND state<>'cancelled') ORDER BY p.updated_at,p.id LIMIT 200`)
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
	return s.queryOrders(ctx, orderSelect+` WHERE state IN ('done','uncertain','failed') AND revert=0 AND reverted=0 AND revert_action<>'' AND revert_attempts<6
 AND revert_due_at<>'' AND revert_due_at<=?
 AND NOT EXISTS(SELECT 1 FROM orders r WHERE r.revert_of=orders.id AND r.state IN ('queued','sent')) ORDER BY revert_blocked,revert_due_at,id LIMIT 200`, ts(now))
}
func (s *DB) ExpiringOrders(ctx context.Context, now time.Time) ([]store.Order, error) {
	return s.queryOrders(ctx, orderSelect+` WHERE state IN ('queued','sent') AND not_after<=? ORDER BY not_after,id LIMIT 200`, ts(now))
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
	if !o.Revert {
		var kill string
		if e = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='decide.killswitch'`).Scan(&kill); e != nil {
			return e
		}
		if kill == "on" {
			return store.ErrConflict
		}
		p, e := scanProposal(tx.QueryRowContext(ctx, proposalSelect+` WHERE p.id=?`, o.ProposalID))
		if e != nil {
			return e
		}
		deadline := p.ExpiresAt
		if deadline.IsZero() {
			deadline = p.CreatedAt.Add(7 * 24 * time.Hour)
		}
		if (p.State == "approved" || p.State == "no-actor") && !deadline.After(o.CreatedAt) {
			return store.ErrConflict
		}
		if len(o.Targets) == 0 {
			return store.ErrConflict
		}
		for _, id := range o.Targets {
			pinned := false
			for _, snap := range p.TargetSnapshot {
				if snap.Kind == id.Kind && snap.Value == id.Value && store.StrongTarget(snap) {
					pinned = true
				}
			}
			if !pinned || !store.StrongTarget(id) {
				return store.ErrConflict
			}
			var n int
			if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_ids WHERE device_id=? AND kind=? AND value=? AND strength='strong'`, p.DeviceID, id.Kind, id.Value).Scan(&n); e != nil {
				return e
			}
			if n != 1 {
				return store.ErrConflict
			}
		}
	}
	if o.Revert {
		// Reserve an attempt and consume its schedule atomically with insertion.
		r, e := tx.ExecContext(ctx, `UPDATE orders SET revert_attempts=revert_attempts+1,revert_due_at='' WHERE id=? AND (state IN ('done','uncertain') OR (state='failed' AND revert_due_at<>'')) AND revert=0 AND reverted=0 AND revert_action<>'' AND revert_attempts<6 AND NOT EXISTS(SELECT 1 FROM orders r WHERE r.revert_of=? AND r.state IN ('queued','sent'))`, o.RevertOf, o.RevertOf)
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
func (s *DB) SendOrders(ctx context.Context, peer int64, now time.Time, revertsOnly bool) ([]orders.Envelope, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT payload,sig FROM orders WHERE EXISTS(SELECT 1 FROM peers WHERE peers.id=orders.actor_peer_id AND disabled=0 AND provisional=0) AND (revert=1 OR ?=0) AND actor_peer_id=? AND state='queued' AND not_after>? AND (revert=1 OR (SELECT value FROM settings WHERE key='decide.killswitch')='off') ORDER BY created_at,id LIMIT 64`, revertsOnly, peer, ts(now))
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
	// Compare the original result, including its unmodified timestamp, before any clamping.
	result, e := json.Marshal(r)
	if e != nil {
		return e
	}
	var previous string
	if e = tx.QueryRowContext(ctx, `SELECT result_json FROM orders WHERE id=?`, o.ID).Scan(&previous); e != nil {
		return e
	}
	if previous != "" {
		if previous == string(result) {
			return nil
		}
		return store.ErrConflict
	}
	if r.Status != proto.OrderDone && r.Status != proto.OrderFailed && r.Status != proto.OrderRejected && r.Status != proto.OrderUncertain {
		return store.ErrConflict
	}
	if (o.State != "sent" && o.State != "expired" && o.State != "uncertain") || o.SentAt.IsZero() || now.After(o.NotAfter.Add(24*time.Hour)) {
		return store.ErrConflict
	}
	if r.Status == proto.OrderRejected && (o.State != "sent" || !now.Before(o.NotAfter)) {
		return store.ErrConflict
	}
	at := r.At
	if at.Before(o.SentAt) {
		at = o.SentAt
	}
	if at.After(now) {
		at = now
	}
	due := time.Time{}
	if o.State == "uncertain" && r.Status != proto.OrderDone {
		due = o.RevertDueAt
	}
	if r.Status == proto.OrderUncertain && !o.Revert && o.RevertAction != "" && !o.Reverted {
		due = now
	}
	if r.Status == proto.OrderDone && !o.Revert && o.RevertAction != "" && o.TTL > 0 && !o.Reverted {
		due = at.Add(time.Duration(o.TTL) * time.Second)
	}
	if _, e = tx.ExecContext(ctx, `UPDATE orders SET state=?,done_at=?,message=?,revert_due_at=?,result_json=? WHERE id=?`, r.Status, ts(now), r.Message, tsOrEmpty(due), string(result), o.ID); e != nil {
		return e
	}
	if o.Revert {
		if r.Status == proto.OrderDone {
			_, e = tx.ExecContext(ctx, `UPDATE orders SET reverted=1,revert_due_at='' WHERE id=?`, o.RevertOf)
			if e == nil {
				_, e = tx.ExecContext(ctx, `UPDATE proposals SET state='reverted',updated_at=? WHERE id=?`, ts(now), o.ProposalID)
			}
		} else {
			refund := 0
			if r.Status == proto.OrderRejected && strings.Contains(strings.ToLower(r.Message), "rate limit") {
				refund = 1
			}
			_, e = tx.ExecContext(ctx, `UPDATE orders SET revert_attempts=MAX(0,revert_attempts-?),revert_due_at=CASE WHEN revert_attempts-?<6 THEN ? ELSE '' END WHERE id=?`, refund, refund, ts(now.Add(10*time.Minute)), o.RevertOf)
		}
	} else {
		if r.Status == proto.OrderDone {
			// Resolution observed before the result also cannot shorten the TTL.
			if _, e = tx.ExecContext(ctx, `INSERT INTO events(at,type,actor,summary,data) SELECT ?,'order.finding-fixed','server','finding fixed on '||d.name||'; revert available','{"severity":"info"}' FROM proposals p JOIN devices d ON d.id=p.device_id WHERE p.id=? AND p.state='resolved' AND (SELECT finding_fixed_notified FROM orders WHERE id=?)=0`, ts(now), o.ProposalID, o.ID); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, `UPDATE orders SET finding_fixed_notified=1 WHERE id=? AND proposal_id IN (SELECT id FROM proposals WHERE state='resolved')`, o.ID); e != nil {
				return e
			}
		}
		message := r.Message
		if r.Status == proto.OrderUncertain {
			message = "possibly applied: " + strings.TrimPrefix(message, "possibly applied: ") + "; precautionary revert sent"
		}
		state := "failed"
		if r.Status == proto.OrderDone {
			state = "done"
		}
		if o.Reverted {
			state = "reverted"
		}
		_, e = tx.ExecContext(ctx, `UPDATE proposals SET state=?,reason=CASE WHEN ?='failed' THEN ? ELSE reason END,updated_at=? WHERE id=?`, state, state, message, ts(now), o.ProposalID)
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
	rows, e := tx.QueryContext(ctx, orderSelect+` WHERE state IN ('queued','sent') AND not_after<=? ORDER BY not_after,id LIMIT 200`, ts(now))
	if e != nil {
		return e
	}
	batch := []store.Order{}
	for rows.Next() {
		o, err := scanOrder(rows)
		if err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, o := range batch {
		state, msg := "expired", "order expired"
		due := time.Time{}
		if o.Revert {
			if _, e = tx.ExecContext(ctx, `UPDATE orders SET revert_due_at=? WHERE id=? AND revert_attempts<6`, ts(now.Add(10*time.Minute)), o.RevertOf); e != nil {
				return e
			}
		} else {
			if o.State == "sent" && o.RevertAction != "" {
				state = "uncertain"
				msg = "no result from actor; revert sent as precaution"
				due = now
			}
			if _, e = tx.ExecContext(ctx, `UPDATE proposals SET state='failed',reason=?,updated_at=? WHERE id=?`, msg, ts(now), o.ProposalID); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, `UPDATE orders SET state=?,message=?,done_at=?,revert_due_at=? WHERE id=?`, state, msg, ts(now), tsOrEmpty(due), o.ID); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *DB) SetProposalOrderState(ctx context.Context, id int64, state, msg string, now time.Time) error {
	_, e := s.db.ExecContext(ctx, `UPDATE proposals SET state=?,reason=CASE WHEN ?='' THEN reason ELSE ? END,decided_user=CASE WHEN ?='pending' THEN '' ELSE decided_user END,decided_at=CASE WHEN ?='pending' THEN '' ELSE decided_at END,override_agent_only=CASE WHEN ?='pending' THEN 0 ELSE override_agent_only END,target_reported_elsewhere=CASE WHEN ?='pending' THEN '{}' ELSE target_reported_elsewhere END,target_snapshot=CASE WHEN ?='pending' THEN '[]' ELSE target_snapshot END,tier=CASE WHEN ?='pending' THEN 'approve' ELSE tier END,updated_at=?,expires_at=CASE WHEN ?='pending' THEN ? ELSE expires_at END WHERE id=? AND state IN ('approved','auto','no-actor')`, state, msg, msg, state, state, state, state, state, state, ts(now), state, ts(now.Add(7*24*time.Hour)), id)
	return e
}
func (s *DB) ScheduleRevert(ctx context.Context, id string, now time.Time) error {
	r, e := s.db.ExecContext(ctx, `UPDATE orders SET revert_due_at=? WHERE id=? AND state IN ('done','uncertain') AND revert=0 AND reverted=0 AND revert_action<>'' AND revert_attempts<6 AND NOT EXISTS(SELECT 1 FROM orders r WHERE r.revert_of=? AND r.state IN ('queued','sent'))`, ts(now), id, id)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return store.ErrConflict
	}
	return nil
}

func (s *DB) MarkRevertBlocked(ctx context.Context, id string) (bool, error) {
	r, e := s.db.ExecContext(ctx, `UPDATE orders SET revert_blocked=1 WHERE id=? AND revert_blocked=0`, id)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
