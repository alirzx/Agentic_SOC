-- 055_alerts_not_null_defaults_for_fusion_sink.sql
--
-- Whack-a-mole after 052–054: every ORM create_all NOT NULL column without a
-- server default blocks AlertSink (which only writes the fusion subset).
-- Observed failures in order: iocs → priority → ai_recommendations.
-- Set safe defaults for the remaining JSONB / scalar NOT NULL columns the
-- sink omits so a running fusion image can persist without a rebuild.

BEGIN;

ALTER TABLE alerts ALTER COLUMN priority SET DEFAULT 50;
ALTER TABLE alerts ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN first_seen SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN last_seen SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN event_time SET DEFAULT NOW();

ALTER TABLE alerts ALTER COLUMN mitre_tactics SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN mitre_techniques SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN source_event_ids SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN ai_recommendations SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN affected_ips SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN affected_hosts SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN affected_users SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN affected_assets SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN child_alert_ids SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN enrichment_data SET DEFAULT '{}'::jsonb;
ALTER TABLE alerts ALTER COLUMN tags SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN raw_event SET DEFAULT '{}'::jsonb;
ALTER TABLE alerts ALTER COLUMN iocs SET DEFAULT '[]'::jsonb;
ALTER TABLE alerts ALTER COLUMN entities SET DEFAULT '[]'::jsonb;

ALTER TABLE alerts ALTER COLUMN is_merged SET DEFAULT FALSE;
ALTER TABLE alerts ALTER COLUMN status SET DEFAULT 'new';

COMMIT;
