-- 074_three_layer_dedup.sql
-- Layer 1 UNIQUE(tenant_id, dedup_hash), Layer 2 occurrences + alert_dedup_key,
-- Layer 3 correlation metadata, categorization columns.
-- Non-destructive: duplicate hashes are renamed, never deleted.

BEGIN;

-- ---------------------------------------------------------------------------
-- Layer 1: reconcile duplicate (tenant_id, dedup_hash) then UNIQUE index
-- ---------------------------------------------------------------------------
-- Keep the oldest row's hash; rename losers so concurrent inserts cannot twin.
WITH ranked AS (
  SELECT id,
         tenant_id,
         dedup_hash,
         ROW_NUMBER() OVER (
           PARTITION BY tenant_id, dedup_hash
           ORDER BY created_at ASC NULLS LAST, id ASC
         ) AS rn
    FROM alerts
   WHERE dedup_hash IS NOT NULL
     AND btrim(dedup_hash) <> ''
)
UPDATE alerts a
   SET dedup_hash = 'legacy_dup:' || left(a.dedup_hash, 40) || ':' || a.id::text,
       updated_at = NOW()
  FROM ranked r
 WHERE a.id = r.id
   AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_tenant_dedup_hash
  ON alerts (tenant_id, dedup_hash)
  WHERE dedup_hash IS NOT NULL
    AND dedup_hash !~ '^legacy_dup:';

COMMENT ON INDEX uq_alerts_tenant_dedup_hash IS
  'Layer-1 event/fingerprint uniqueness; legacy_dup:* excluded after reconciliation.';

-- ---------------------------------------------------------------------------
-- Layer 2: logical alert key + occurrence preservation
-- ---------------------------------------------------------------------------
ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS alert_dedup_key TEXT,
  ADD COLUMN IF NOT EXISTS canonical_alert_id UUID;

CREATE INDEX IF NOT EXISTS ix_alerts_tenant_alert_dedup_key
  ON alerts (tenant_id, alert_dedup_key)
  WHERE alert_dedup_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_alerts_canonical_alert
  ON alerts (tenant_id, canonical_alert_id)
  WHERE canonical_alert_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS alert_occurrences (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  alert_id          UUID NOT NULL,
  source_alert_id   UUID,
  source_event_ids  JSONB NOT NULL DEFAULT '[]'::jsonb,
  seen_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event_time        TIMESTAMPTZ,
  entities          JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence          JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurrence_meta   JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_alert_occurrences_tenant_alert
  ON alert_occurrences (tenant_id, alert_id, seen_at DESC);

CREATE INDEX IF NOT EXISTS ix_alert_occurrences_source_alert
  ON alert_occurrences (tenant_id, source_alert_id)
  WHERE source_alert_id IS NOT NULL;

COMMENT ON TABLE alert_occurrences IS
  'Layer-2 preserved occurrences for a canonical alert; never delete for dedupe.';

-- ---------------------------------------------------------------------------
-- Categorization (alert-level; incident-level on fusion_incidents)
-- ---------------------------------------------------------------------------
ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS alert_category TEXT,
  ADD COLUMN IF NOT EXISTS alert_category_meta JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE fusion_incidents
  ADD COLUMN IF NOT EXISTS incident_category TEXT,
  ADD COLUMN IF NOT EXISTS incident_category_meta JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS correlation_score DOUBLE PRECISION,
  ADD COLUMN IF NOT EXISTS correlation_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS correlation_version TEXT,
  ADD COLUMN IF NOT EXISTS membership_history JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS lifecycle_status VARCHAR(32);

-- Extend status check to include investigating / resolved (keep legacy values).
ALTER TABLE fusion_incidents DROP CONSTRAINT IF EXISTS fusion_incidents_status_chk;
ALTER TABLE fusion_incidents
  ADD CONSTRAINT fusion_incidents_status_chk
  CHECK (status IN (
    'open', 'capped', 'closed', 'merged',
    'investigating', 'resolved'
  ));

COMMENT ON COLUMN alerts.alert_dedup_key IS
  'Layer-2 entity-aware logical alert fingerprint (alert:v1:…).';
COMMENT ON COLUMN alerts.canonical_alert_id IS
  'When this row is an occurrence duplicate, points at the canonical alert.';
COMMENT ON COLUMN alerts.alert_category IS
  'Primary alert category id (endpoint_security, network_security, …, unknown).';

COMMIT;
