-- Pull peers: agents that the server pulls reports from (docs/design/pull-mode.md).
-- The peer row has role 'agent' and a random token hash that is never given out.
CREATE TABLE pull_peers (
    peer_id      INTEGER PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE,
    transport    TEXT NOT NULL,
    address      TEXT NOT NULL,
    pin          TEXT NOT NULL DEFAULT '',   -- agent certificate fingerprint; empty until paired
    pair_code    TEXT NOT NULL DEFAULT '',   -- one-time pairing code; empty when paired
    pair_expires TEXT,
    interval_s   INTEGER NOT NULL,
    next_pull    TEXT NOT NULL,
    last_pull    TEXT,
    last_error   TEXT NOT NULL DEFAULT ''
);
