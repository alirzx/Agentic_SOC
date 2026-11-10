-- 073_alerts_rule_evaluation.sql
--
-- Queue marker for creation-time automation-rule evaluation.
--
-- Why this exists
-- ---------------
-- Automation rules were only evaluated from the alert API: ``POST /api/v1/alerts``
-- and ``PATCH /api/v1/alerts/{id}``. Every alert that arrives from a connector is
-- inserted by fusion's ``AlertSink`` with its own SQL, so it never passed through
-- either endpoint and a rule could never fire on real telemetry — only on alerts a
-- human or the demo seeder submitted by hand.
--
-- ``app/workers/rule_evaluator.py`` claims rows where this column is NULL and runs
-- the ``alert.created`` rules for them. The column is set at *claim* time, so each
-- alert is evaluated at most once even with several API replicas.
--
-- Existing rows are stamped as already evaluated
-- ----------------------------------------------
-- Without the backfill, the first worker start would replay every historical alert
-- through the rule engine. A containment rule (``isolate_host``) firing on a
-- month-old alert is not a backfill, it is an incident. Operators who deliberately
-- want to re-evaluate one alert can clear the marker for that row:
--
--     UPDATE alerts SET automation_rules_evaluated_at = NULL WHERE id = '<alert>';
--
-- Idempotent: safe to re-run.

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS automation_rules_evaluated_at TIMESTAMPTZ;

-- Stamp the existing backlog exactly once. New rows (fusion, the API, the demo
-- seeder) leave the column NULL and enter the queue.
UPDATE alerts
   SET automation_rules_evaluated_at = now()
 WHERE automation_rules_evaluated_at IS NULL;

-- Partial index: only unprocessed rows are indexed, so this stays small no matter
-- how large ``alerts`` grows. It serves the claim query's ORDER BY created_at.
CREATE INDEX IF NOT EXISTS idx_alerts_rule_eval_pending
    ON alerts (created_at)
    WHERE automation_rules_evaluated_at IS NULL;

COMMENT ON COLUMN alerts.automation_rules_evaluated_at IS
    'When creation-time automation rules were evaluated (or claimed for evaluation). NULL = queued for the rule evaluator worker.';
