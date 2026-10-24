-- 058_fusion_incidents.sql
--
-- Durable Fusion correlation incidents. Redis remains the hot-path cache;
-- this table survives Redis TTL / worker restart and carries optional case_id
-- linkage so Case promotion can reuse an open Case for the same incident.

BEGIN;

CREATE TABLE IF NOT EXISTS fusion_incidents (
    id                UUID PRIMARY KEY,
    tenant_id         UUID NOT NULL,
    correlation_key   TEXT NOT NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'open',
    title             TEXT NOT NULL DEFAULT '',
    severity          VARCHAR(16) NOT NULL DEFAULT 'medium',
    alert_count       INTEGER NOT NULL DEFAULT 1,
    alert_ids         UUID[] NOT NULL DEFAULT '{}',
    case_id           UUID NULL,
    first_seen        TIMESTAMPTZ,
    last_seen         TIMESTAMPTZ,
    mitre_techniques  JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fusion_incidents_status_chk
      CHECK (status IN ('open', 'capped', 'closed', 'merged'))
);

CREATE INDEX IF NOT EXISTS ix_fusion_incidents_tenant_corr_open
  ON fusion_incidents (tenant_id, correlation_key, last_seen DESC)
  WHERE status = 'open';

CREATE INDEX IF NOT EXISTS ix_fusion_incidents_tenant_case
  ON fusion_incidents (tenant_id, case_id)
  WHERE case_id IS NOT NULL;

ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS fusion_incident_id UUID;

CREATE INDEX IF NOT EXISTS ix_alerts_tenant_fusion_incident
  ON alerts (tenant_id, fusion_incident_id)
  WHERE fusion_incident_id IS NOT NULL;

COMMENT ON TABLE fusion_incidents IS
  'Durable Fusion correlation groups; Redis cache is ephemeral overlay.';
COMMENT ON COLUMN alerts.fusion_incident_id IS
  'FK-like reference to fusion_incidents.id (no hard FK: fusion may write first).';

COMMIT;
