ALTER TABLE proposals ADD COLUMN target_reported_elsewhere TEXT NOT NULL DEFAULT '{}';
ALTER TABLE proposals ADD COLUMN override_agent_only INTEGER NOT NULL DEFAULT 0;

-- Keep every reporter, even when a subsequent report updates device_ids.source.
-- Identifiers move with their provenance; deleting an identifier deletes its sources.
CREATE TABLE device_id_sources (
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (kind, value, source),
    FOREIGN KEY (kind, value) REFERENCES device_ids(kind, value) ON DELETE CASCADE
);
INSERT INTO device_id_sources SELECT kind,value,source FROM device_ids;
CREATE INDEX events_claims ON events(type,at);

-- Old unexecuted approvals did not pin source evidence. Require review once;
-- signed orders and their recovery remain intact.
UPDATE proposals SET state='pending',tier='approve',merge_key=id,
    target_snapshot='[]',decided_user='',decided_at='',
    reason='target provenance changed; approve again',
    expires_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','+7 days')
WHERE state IN ('approved','auto','no-actor')
    AND NOT EXISTS(SELECT 1 FROM orders WHERE proposal_id=proposals.id AND revert=0 AND state<>'cancelled');
