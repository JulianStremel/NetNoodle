CREATE TABLE onboarding (
    id TEXT PRIMARY KEY,
    secret_hash BLOB NOT NULL CHECK(length(secret_hash)=32),
    join_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('created','enrolled','connected','done','aborted','expired')),
    error TEXT NOT NULL DEFAULT '',
    peer_id INTEGER NOT NULL DEFAULT 0,
    expires TEXT NOT NULL,
    updated TEXT NOT NULL,
    steps TEXT NOT NULL DEFAULT '[]'
);
CREATE UNIQUE INDEX onboarding_open_name ON onboarding(name)
    WHERE state IN ('created','enrolled','connected');
CREATE INDEX onboarding_expiry ON onboarding(state,expires);

-- A revoked token ID must not attach a later peer if SQLite reuses the ID.
CREATE TRIGGER onboarding_token_deleted BEFORE DELETE ON join_tokens BEGIN
    UPDATE onboarding SET join_id=0 WHERE join_id=OLD.id;
END;

-- An installation must never acquire ownership of a reused peer ID.
CREATE TRIGGER onboarding_peer_deleted BEFORE DELETE ON peers BEGIN
    UPDATE onboarding SET peer_id=0 WHERE peer_id=OLD.id;
END;
