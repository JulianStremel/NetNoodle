-- Vulnerabilities known to the server (from matchers, enriched with KEV/EPSS).
CREATE TABLE vulns (
    id         TEXT PRIMARY KEY,
    aliases    TEXT NOT NULL DEFAULT '[]',
    summary    TEXT NOT NULL DEFAULT '',
    score      REAL NOT NULL DEFAULT 0,
    vector     TEXT NOT NULL DEFAULT '',
    kev        INTEGER NOT NULL DEFAULT 0,
    epss       REAL NOT NULL DEFAULT 0,
    epss_pct   REAL NOT NULL DEFAULT 0,
    published  TEXT NOT NULL DEFAULT '',
    modified   TEXT NOT NULL DEFAULT '',
    refs       TEXT NOT NULL DEFAULT '[]',
    facts      TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
);

-- One vulnerability in one component of one device, as found by one matcher.
CREATE TABLE findings (
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    purl        TEXT NOT NULL,
    vuln_id     TEXT NOT NULL,
    source      TEXT NOT NULL,
    fixed       TEXT NOT NULL DEFAULT '',
    confidence  TEXT NOT NULL,
    state       TEXT NOT NULL,          -- open | resolved
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    resolved_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, purl, vuln_id, source)
);
CREATE INDEX findings_state ON findings(state, device_id);
CREATE INDEX findings_vuln ON findings(vuln_id);
