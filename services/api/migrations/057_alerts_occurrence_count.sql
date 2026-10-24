-- 057_alerts_occurrence_count.sql
--
-- Track how many times an exact fingerprint replayed against a durable alert
-- row. Fusion AlertSink bumps this (+ last_seen) on DUPLICATE persists so
-- analysts see recurrence without minting unlimited rows.

BEGIN;

ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1;

COMMENT ON COLUMN alerts.occurrence_count IS
  'Number of exact fingerprint observations for this alert group (starts at 1).';

COMMIT;
