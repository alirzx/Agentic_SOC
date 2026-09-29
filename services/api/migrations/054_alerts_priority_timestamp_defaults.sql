-- 054_alerts_priority_timestamp_defaults.sql
--
-- After 052/053, fusion still hit:
--   null value in column "priority" of relation "alerts" violates not-null
-- ORM create_all left priority / created_at / updated_at NOT NULL without
-- server defaults. Sink historically omitted them (001_init had DEFAULT 50 /
-- NOW()). Set defaults so the running fusion image can INSERT without a
-- rebuild; sink also writes priority + timestamps explicitly.

BEGIN;

ALTER TABLE alerts ALTER COLUMN priority SET DEFAULT 50;
ALTER TABLE alerts ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN first_seen SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN last_seen SET DEFAULT NOW();
ALTER TABLE alerts ALTER COLUMN event_time SET DEFAULT NOW();

COMMIT;
