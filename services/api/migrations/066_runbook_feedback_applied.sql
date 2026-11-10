-- 066_runbook_feedback_applied.sql
--
-- Records the *outcome* of analyst feedback, not just that it was submitted.
--
-- `runbook_tasks.feedback_to_llm` says the analyst graded the model; it does not
-- say the grade reached outcome memory. The API forwards the grade to the agents
-- service, which answers 200 with `updated: true/false` depending on whether a
-- prior existed for that evidence signature. Before this column the only record
-- of that answer was a log line, so "the loop is closed" was an assumption.
--
-- Semantics
--   TRUE  — outcome memory confirmed a prior was updated
--   FALSE — feedback was submitted but no prior was updated (no prior for the
--           signature, transport failure, or the agents service is not wired up)
--   NULL  — no feedback was submitted, or the row predates this column
--
-- Idempotent: safe to re-run.

ALTER TABLE runbook_tasks
    ADD COLUMN IF NOT EXISTS feedback_applied BOOLEAN;

COMMENT ON COLUMN runbook_tasks.feedback_applied IS
    'TRUE when outcome memory confirmed a prior update for this task''s '
    'signature; FALSE when feedback was submitted but no prior changed; '
    'NULL when no feedback was submitted (or the row predates this column).';

-- The metric endpoint aggregates per tenant, so a narrow partial index keeps it
-- cheap without paying for the billions of pending rows that carry no feedback.
CREATE INDEX IF NOT EXISTS idx_runbook_tasks_feedback_applied
    ON runbook_tasks (tenant_id, feedback_applied)
    WHERE feedback_to_llm IS NOT NULL;
