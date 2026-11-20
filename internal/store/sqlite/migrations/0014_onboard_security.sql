ALTER TABLE peers ADD COLUMN provisional INTEGER NOT NULL DEFAULT 0 CHECK (provisional IN (0,1));
UPDATE peers SET provisional=1 WHERE id IN (SELECT peer_id FROM onboarding WHERE state<>'done');
-- Move previously public webhook endpoints to write-only storage.
UPDATE integrations SET secrets_json=json_set(secrets_json,'$.url',json_extract(settings_json,'$.url')),
 settings_json=json_remove(settings_json,'$.url')
 WHERE kind='notify' AND type='webhook' AND json_type(settings_json,'$.url')='text';
