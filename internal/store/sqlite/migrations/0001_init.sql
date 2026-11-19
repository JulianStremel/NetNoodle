CREATE TABLE users (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    pass_hash  BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);
CREATE INDEX sessions_expires ON sessions(expires_at);

-- Free-form event log shown in the UI (logins, new devices, decisions, orders).
CREATE TABLE events (
    id         INTEGER PRIMARY KEY,
    at         TEXT NOT NULL,
    type       TEXT NOT NULL,
    actor      TEXT NOT NULL,
    summary    TEXT NOT NULL,
    data       TEXT
);
CREATE INDEX events_at ON events(at);
