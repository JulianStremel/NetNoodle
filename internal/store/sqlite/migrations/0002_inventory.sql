-- Programs that talk to the server: sources, agents, actors.
CREATE TABLE peers (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    role       TEXT NOT NULL CHECK (role IN ('source', 'agent', 'actor')),
    token_hash BLOB NOT NULL UNIQUE,
    disabled   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_seen  TEXT
);

CREATE TABLE join_tokens (
    id         INTEGER PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    role       TEXT NOT NULL CHECK (role IN ('source', 'agent', 'actor')),
    name       TEXT NOT NULL DEFAULT '', -- fixed peer name; empty = the peer gives its name
    uses_left  INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Raw observations, kept for a limited time.
CREATE TABLE observations (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    received_at TEXT NOT NULL,
    payload     BLOB NOT NULL
);
CREATE INDEX observations_received ON observations(received_at);

CREATE TABLE devices (
    id         INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    parent_id  INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    attributes TEXT NOT NULL DEFAULT '{}',
    interfaces TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
CREATE INDEX devices_parent ON devices(parent_id);

-- One identifier belongs to one device at a time.
CREATE TABLE device_ids (
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    strength   TEXT NOT NULL CHECK (strength IN ('strong', 'weak')),
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source     TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (kind, value)
);
CREATE INDEX device_ids_device ON device_ids(device_id);

CREATE TABLE components (
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    purl       TEXT NOT NULL,
    source     TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    confidence TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (device_id, purl, source)
);
CREATE INDEX components_purl ON components(purl);

CREATE TABLE services (
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    proto      TEXT NOT NULL,
    port       INTEGER NOT NULL,
    source     TEXT NOT NULL,
    address    TEXT NOT NULL DEFAULT '',
    product    TEXT NOT NULL DEFAULT '',
    version    TEXT NOT NULL DEFAULT '',
    process    TEXT NOT NULL DEFAULT '',
    component  TEXT NOT NULL DEFAULT '',
    banner     TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (device_id, proto, port, source)
);
