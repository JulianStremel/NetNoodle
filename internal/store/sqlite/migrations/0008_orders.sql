DROP INDEX proposals_mutable;
DROP INDEX proposals_state;
ALTER TABLE proposals RENAME TO proposals_old;
CREATE TABLE proposals (
 id INTEGER PRIMARY KEY,
 device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 vuln_id TEXT NOT NULL, purl TEXT NOT NULL, action TEXT NOT NULL,
 tier TEXT NOT NULL CHECK(tier IN ('none','notify','approve','auto')),
 state TEXT NOT NULL CHECK(state IN ('notify','auto','pending','approved','rejected','expired','resolved','ordered','done','failed','no-actor','reverted')),
 reason TEXT NOT NULL, decided_by TEXT NOT NULL DEFAULT '[]', params TEXT NOT NULL DEFAULT '{}', ttl_s INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT NOT NULL DEFAULT '', decided_user TEXT NOT NULL DEFAULT '', decided_at TEXT NOT NULL DEFAULT ''
);
INSERT INTO proposals SELECT * FROM proposals_old;
DROP TABLE proposals_old;
CREATE UNIQUE INDEX proposals_mutable ON proposals(device_id,vuln_id,action) WHERE state NOT IN ('approved','rejected','ordered','done','failed','no-actor','reverted','resolved');
CREATE INDEX proposals_state ON proposals(state,created_at);
CREATE TABLE actor_caps (
 peer_id INTEGER PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE,
 caps TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE orders (
 id TEXT PRIMARY KEY, proposal_id INTEGER NOT NULL REFERENCES proposals(id), actor_peer_id INTEGER NOT NULL REFERENCES peers(id),
 action TEXT NOT NULL, targets TEXT NOT NULL, params TEXT NOT NULL, ttl_s INTEGER NOT NULL, revert INTEGER NOT NULL, revert_of TEXT NOT NULL DEFAULT '',
 state TEXT NOT NULL CHECK(state IN ('queued','sent','done','failed','rejected','expired')),
 payload BLOB NOT NULL, sig BLOB NOT NULL, created_at TEXT NOT NULL, sent_at TEXT NOT NULL DEFAULT '', done_at TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT '', not_after TEXT NOT NULL,
 revert_due_at TEXT NOT NULL DEFAULT '', reverted INTEGER NOT NULL DEFAULT 0,
 revert_action TEXT NOT NULL DEFAULT '', revert_attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX orders_actor_state ON orders(actor_peer_id,state);
CREATE UNIQUE INDEX orders_proposal_once ON orders(proposal_id) WHERE revert=0;
CREATE UNIQUE INDEX orders_revert_open ON orders(revert_of) WHERE revert=1 AND state IN ('queued','sent');
