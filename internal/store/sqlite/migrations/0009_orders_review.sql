DROP INDEX proposals_mutable;
ALTER TABLE proposals ADD COLUMN merge_key INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proposals ADD COLUMN target_snapshot TEXT NOT NULL DEFAULT '[]';
-- Existing approvals have no decision-time identity evidence.
UPDATE proposals SET state='pending', tier='approve', merge_key=id, decided_user='', decided_at='', expires_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','+7 days'), reason='device identity changed; approve again'
 WHERE state IN ('approved','auto','no-actor');
DROP INDEX orders_actor_state;
DROP INDEX orders_proposal_once;
DROP INDEX orders_revert_open;
ALTER TABLE orders RENAME TO orders_old;
CREATE TABLE orders (
 id TEXT PRIMARY KEY, proposal_id INTEGER NOT NULL REFERENCES proposals(id), actor_peer_id INTEGER NOT NULL REFERENCES peers(id),
 action TEXT NOT NULL, targets TEXT NOT NULL, params TEXT NOT NULL, ttl_s INTEGER NOT NULL, revert INTEGER NOT NULL, revert_of TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL CHECK(state IN ('queued','sent','done','failed','rejected','expired','uncertain','cancelled')),
 payload BLOB NOT NULL, sig BLOB NOT NULL, created_at TEXT NOT NULL, sent_at TEXT NOT NULL DEFAULT '', done_at TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT '', not_after TEXT NOT NULL,
 revert_due_at TEXT NOT NULL DEFAULT '', reverted INTEGER NOT NULL DEFAULT 0,
 revert_action TEXT NOT NULL DEFAULT '', revert_attempts INTEGER NOT NULL DEFAULT 0,
 result_json TEXT NOT NULL DEFAULT '', revert_blocked INTEGER NOT NULL DEFAULT 0, finding_fixed_notified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX orders_actor_state ON orders(actor_peer_id,state);
CREATE UNIQUE INDEX orders_proposal_once ON orders(proposal_id) WHERE revert=0 AND state<>'cancelled';
CREATE UNIQUE INDEX orders_revert_open ON orders(revert_of) WHERE revert=1 AND state IN ('queued','sent');

INSERT INTO orders (id,proposal_id,actor_peer_id,action,targets,params,ttl_s,revert,revert_of,state,payload,sig,created_at,sent_at,done_at,message,not_after,revert_due_at,reverted,revert_action,revert_attempts) SELECT id,proposal_id,actor_peer_id,action,targets,params,ttl_s,revert,revert_of,state,payload,sig,created_at,sent_at,done_at,message,not_after,revert_due_at,reverted,revert_action,revert_attempts FROM orders_old;
DROP TABLE orders_old;
CREATE INDEX orders_state_expiry ON orders(state,not_after);
CREATE INDEX orders_revert_due ON orders(revert_due_at) WHERE revert=0 AND reverted=0;

-- Moved approvals remain distinct pending reviews after a device merge.
CREATE UNIQUE INDEX proposals_mutable ON proposals(device_id,vuln_id,action,merge_key) WHERE state NOT IN ('approved','rejected','ordered','done','failed','no-actor','reverted','resolved');
