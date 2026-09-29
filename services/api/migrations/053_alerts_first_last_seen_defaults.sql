-- 053_alerts_first_last_seen_defaults.sql
--
-- ORM create_all marked first_seen / last_seen NOT NULL without a server
-- default. Fusion AlertSink historically omitted those columns (001_init
-- had DEFAULT NOW()). Result after 052 fixed iocs: every INSERT fails with
--   null value in column "first_seen" violates not-null constraint
-- Idempotent: set DEFAULT NOW() so any writer that omits the columns still
-- succeeds; sink also writes them explicitly from event_time.

BEGIN;

ALTER TABLE alerts ALTER COLUMN first_seen SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN last_seen SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN event_time SET DEFAULT NOW();

COMMIT;
