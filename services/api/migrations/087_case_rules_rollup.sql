-- 084_case_rules_rollup.sql
--
-- `Case.rules` existed on the ORM model with no column in the migration
-- lineage, so a database bootstrapped from migrations had nowhere to keep the
-- rule roll-up — the schema-drift gate (#492) failed, and any ORM flush of a
-- Case would have referenced a column that does not exist.
--
-- The API serves the field as a rule name → member-alert-count map
-- (`dict[str, int]`, e.g. `{"ESCU - Windows Backup Services Stop": 6}`), never
-- as a bare list, so the column is JSONB defaulting to an empty object. The
-- console reads it the same way ("N rules" + the Rules tab roll-up).
--
-- Idempotent: re-running is a no-op.

BEGIN;

-- Two tables carry case rows in this codebase: `cases` (the ORM model, and the
-- table the drift gate tracks) and `aisoc_cases` (what the case endpoints
-- query today). Both get the column so neither lineage references a field the
-- other one lacks.
ALTER TABLE IF EXISTS aisoc_cases
    ADD COLUMN IF NOT EXISTS rules JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE cases
    ADD COLUMN IF NOT EXISTS rules JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMIT;
