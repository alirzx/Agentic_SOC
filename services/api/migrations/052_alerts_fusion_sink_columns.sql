-- 052_alerts_fusion_sink_columns.sql
--
-- Fusion AlertSink INSERT (services/fusion/app/services/alert_sink.py) writes
-- iocs / entities / dedup_hash / anomaly_score. Those columns exist in
-- 001_init.sql, but environments that bootstrapped via SQLAlchemy create_all
-- from the ORM (which never mapped them) never got the columns. Result:
-- every promoted Splunk notable hits persist_failed with
--   column "iocs" of relation "alerts" does not exist
-- and /alerts stays empty despite events_ingested >> 0.
--
-- Idempotent ADD COLUMN so partial / create_all / 001_init lineages all converge.

BEGIN;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS iocs          JSONB DEFAULT '[]'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS entities      JSONB DEFAULT '[]'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dedup_hash    VARCHAR(64);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS anomaly_score DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts (dedup_hash);

COMMIT;
