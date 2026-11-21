-- 083_fix_kpi_fk_to_aisoc_cases.sql
--
-- Migration 078 may have executed before this fix was applied, creating
-- case_evaluations and false_alert_records with FK → cases(id) (the ORM
-- stub table). The authoritative case table is aisoc_cases (migration 012).
--
-- This migration is idempotent: DROP CONSTRAINT IF EXISTS is a no-op when
-- the constraint doesn't exist (e.g. fresh install where migration 078's
-- ALTER TABLE already set the correct FK).

BEGIN;

ALTER TABLE case_evaluations
    DROP CONSTRAINT IF EXISTS case_evaluations_case_id_fkey;
ALTER TABLE case_evaluations
    ADD CONSTRAINT case_evaluations_case_id_fkey
    FOREIGN KEY (case_id) REFERENCES aisoc_cases(id) ON DELETE CASCADE;

ALTER TABLE false_alert_records
    DROP CONSTRAINT IF EXISTS false_alert_records_case_id_fkey;
ALTER TABLE false_alert_records
    ADD CONSTRAINT false_alert_records_case_id_fkey
    FOREIGN KEY (case_id) REFERENCES aisoc_cases(id) ON DELETE CASCADE;

COMMIT;
