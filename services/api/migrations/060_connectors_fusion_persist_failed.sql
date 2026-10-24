-- 060_connectors_fusion_persist_failed.sql
--
-- Tracks how many fused alerts the fusion sink (services/fusion) failed
-- to persist into Postgres per connector.  The counter is incremented
-- directly by AlertSink when asyncpg raises an exception during INSERT,
-- giving the UI a way to surface downstream persistence failures that are
-- invisible to the connector-side error_count (which only covers poll-level
-- failures such as network errors and auth failures).
--
-- The column follows the same lifetime-cumulative semantics as
-- events_ingested and error_count: never reset, incremented on every
-- FAILED persist attempt regardless of cause.

BEGIN;

ALTER TABLE connectors ADD COLUMN IF NOT EXISTS fusion_persist_failed INTEGER NOT NULL DEFAULT 0;

COMMIT;
