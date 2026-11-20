CREATE TABLE device_tags (
 device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 tag TEXT NOT NULL,
 PRIMARY KEY(device_id,tag)
);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
INSERT INTO settings VALUES ('decide.killswitch','off',strftime('%Y-%m-%dT%H:%M:%SZ','now'));
CREATE TABLE proposals (
 id INTEGER PRIMARY KEY,
 device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 vuln_id TEXT NOT NULL,
 purl TEXT NOT NULL,
 action TEXT NOT NULL,
 tier TEXT NOT NULL CHECK(tier IN ('none','notify','approve','auto')),
 state TEXT NOT NULL CHECK(state IN ('notify','auto','pending','approved','rejected','expired','resolved')),
 reason TEXT NOT NULL,
 decided_by TEXT NOT NULL DEFAULT '[]',
 params TEXT NOT NULL DEFAULT '{}',
 ttl_s INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 expires_at TEXT NOT NULL DEFAULT '',
 decided_user TEXT NOT NULL DEFAULT '',
 decided_at TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX proposals_open ON proposals(device_id,vuln_id,action) WHERE state IN ('pending','approved','auto');
CREATE INDEX proposals_state ON proposals(state,created_at);
