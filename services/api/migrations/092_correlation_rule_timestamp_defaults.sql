-- 092_correlation_rule_timestamp_defaults.sql
-- Repair the timestamp defaults of the correlation rule registry tables.
--
-- The API runs ``Base.metadata.create_all`` before the SQL migrations, so on a
-- fresh database these two tables can be created from ORM metadata without the
-- defaults declared in 090 / 091. 090 then failed its seed INSERT on the
-- NOT NULL ``created_at`` column, and 091 recorded itself as applied while the
-- audit table kept a defaultless ``created_at`` — which made
-- ``audit_rule_resolution`` drop every row silently (it only logs a warning).
--
-- 090 / 091 now set the defaults themselves, but a database that already
-- recorded either migration against a ``create_all``-built table keeps the
-- broken columns. This migration repairs those databases; it is idempotent and
-- leaves tables alone that do not exist yet.

BEGIN;

ALTER TABLE IF EXISTS correlation_rule_identity_maps
    ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE IF EXISTS correlation_rule_identity_maps
    ALTER COLUMN updated_at SET DEFAULT now();
ALTER TABLE IF EXISTS correlation_rule_resolution_audits
    ALTER COLUMN created_at SET DEFAULT now();

COMMIT;
