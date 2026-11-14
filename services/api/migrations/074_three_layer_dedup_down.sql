-- Rollback for 074_three_layer_dedup.sql (non-destructive where possible).
-- Does NOT restore renamed legacy_dup:* hashes to their original values
-- (original truncated). Re-run reconciliation is not automatic.

BEGIN;

DROP INDEX IF EXISTS uq_alerts_tenant_dedup_hash;
DROP INDEX IF EXISTS ix_alerts_tenant_alert_dedup_key;
DROP INDEX IF EXISTS ix_alerts_canonical_alert;
DROP INDEX IF EXISTS ix_alert_occurrences_tenant_alert;
DROP INDEX IF EXISTS ix_alert_occurrences_source_alert;

DROP TABLE IF EXISTS alert_occurrences;

ALTER TABLE alerts DROP COLUMN IF EXISTS alert_dedup_key;
ALTER TABLE alerts DROP COLUMN IF EXISTS canonical_alert_id;
ALTER TABLE alerts DROP COLUMN IF EXISTS alert_category;
ALTER TABLE alerts DROP COLUMN IF EXISTS alert_category_meta;

ALTER TABLE fusion_incidents DROP COLUMN IF EXISTS incident_category;
ALTER TABLE fusion_incidents DROP COLUMN IF EXISTS incident_category_meta;
ALTER TABLE fusion_incidents DROP COLUMN IF EXISTS correlation_score;
ALTER TABLE fusion_incidents DROP COLUMN IF EXISTS correlation_reasons;
ALTER TABLE fusion_incidents DROP COLUMN IF EXISTS correlation_version;
ALTER TABLE fusion_incidents DROP COLUMN IF EXISTS membership_history;
ALTER TABLE fusion_incidents DROP COLUMN IF EXISTS lifecycle_status;

ALTER TABLE fusion_incidents DROP CONSTRAINT IF EXISTS fusion_incidents_status_chk;
ALTER TABLE fusion_incidents
  ADD CONSTRAINT fusion_incidents_status_chk
  CHECK (status IN ('open', 'capped', 'closed', 'merged'));

COMMIT;
