-- Which source saw which device, and when.
CREATE TABLE device_sources (
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source     TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (device_id, source)
);
