DROP INDEX proposals_open;
-- Retain the latest mutable row, including notifications and closed findings.
DELETE FROM proposals WHERE state NOT IN ('approved','rejected') AND id NOT IN (
 SELECT id FROM (
  SELECT id, ROW_NUMBER() OVER (
   PARTITION BY device_id,vuln_id,action ORDER BY updated_at DESC,id DESC
  ) AS rank FROM proposals WHERE state NOT IN ('approved','rejected')
 ) WHERE rank=1
);
CREATE UNIQUE INDEX proposals_mutable ON proposals(device_id,vuln_id,action)
 WHERE state NOT IN ('approved','rejected');
