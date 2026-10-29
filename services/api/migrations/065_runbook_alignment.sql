/**
 * Runbook alignment: task signature, approval-gate idempotency, RLS parity,
 * and removal of the retired visual-editor template store.
 *
 * 1. `runbook_tasks.signature`
 *    The agents service computes an evidence fingerprint at triage time
 *    (`CostGovernor.evidence_fingerprint`) and keeps it only in Redis/outcome
 *    memory. Analyst feedback has to address the *same* prior, so the task
 *    carries the fingerprint it was created for.
 *
 * 2. `uq_runbook_tasks_open_gate`
 *    A blocked governed action must produce exactly one pending approval task,
 *    even when the same alert is re-evaluated on every update. A partial unique
 *    index makes that a database guarantee instead of a read-then-write race.
 *
 * 3. RLS parity with `runbook_events` (migration 062). Query-layer tenant
 *    filtering remains the primary gate; this is defence-in-depth.
 *
 * 4. `runbook_templates` was the backing store for the Runbook visual editor,
 *    which is out of scope (PLAN-20261028-1710). No API or UI ever referenced
 *    it, so the table is dropped to avoid leaving a schema that implies a
 *    feature which does not exist.
 */

ALTER TABLE runbook_tasks
    ADD COLUMN IF NOT EXISTS signature VARCHAR(200);

COMMENT ON COLUMN runbook_tasks.signature IS
    'Evidence fingerprint the task was raised for; keys the outcome prior that analyst feedback updates.';

CREATE INDEX IF NOT EXISTS idx_runbook_tasks_signature
    ON runbook_tasks(signature) WHERE signature IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_runbook_tasks_open_gate
    ON runbook_tasks (tenant_id, alert_id, title)
    WHERE task_type = 'approval_gate' AND status <> 'completed';

ALTER TABLE runbook_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE runbook_tasks FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS runbook_tasks_tenant_isolation ON runbook_tasks;
CREATE POLICY runbook_tasks_tenant_isolation ON runbook_tasks
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP TABLE IF EXISTS runbook_templates;
