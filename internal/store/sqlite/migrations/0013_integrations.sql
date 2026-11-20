CREATE TABLE integrations (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL DEFAULT 'source',
    type TEXT NOT NULL,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    settings_json TEXT NOT NULL DEFAULT '{}',
    secrets_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_ok_at TEXT,
    last_error TEXT NOT NULL DEFAULT ''
);

-- In-process and enrolled sources share the inventory identity namespace.
CREATE TRIGGER integration_peer_insert BEFORE INSERT ON integrations
WHEN EXISTS (SELECT 1 FROM peers WHERE lower(name)=lower(NEW.name))
BEGIN SELECT RAISE(ABORT, 'UNIQUE source name'); END;
CREATE TRIGGER integration_peer_update BEFORE UPDATE OF name ON integrations
WHEN EXISTS (SELECT 1 FROM peers WHERE lower(name)=lower(NEW.name))
BEGIN SELECT RAISE(ABORT, 'UNIQUE source name'); END;
CREATE TRIGGER peer_integration_insert BEFORE INSERT ON peers
WHEN EXISTS (SELECT 1 FROM integrations WHERE name=NEW.name COLLATE NOCASE)
BEGIN SELECT RAISE(ABORT, 'UNIQUE source name'); END;
