-- 071_runbook_confidence_and_defaults.sql
--
-- Backfill the runbook schema to match the model/tests: confidence captured at
-- submission time for calibration loops, and a default actor for rows created by
-- the system without an explicit analyst id.
--
-- Idempotent: safe to re-run.

ALTER TABLE runbook_tasks
    ADD COLUMN IF NOT EXISTS confidence_at_submission DOUBLE PRECISION;

UPDATE runbook_tasks
SET created_by = 'system'
WHERE created_by IS NULL OR created_by = '';

ALTER TABLE runbook_tasks
    ALTER COLUMN created_by SET DEFAULT 'system';

COMMENT ON COLUMN runbook_tasks.confidence_at_submission IS
    'Confidence score captured when the task was created; used for calibration monitoring and operational dashboards.';
