-- 067_playbook_runs.sql
--
-- Resumable playbook runs + the RBAC permission that releases an approval gate.
--
-- Phase 11 made the playbook engine *fail closed*: a run that reaches an
-- `approval` step parks (`pending_approval`) instead of walking past the gate.
-- That left parked runs as dead ends — they lived in the agents process's
-- in-memory `_runs` dict, so a restart forgot them, and nothing could release
-- one. This migration gives a run a durable row so an approval can be resumed
-- hours later, from the step *after* the gate, against the playbook definition
-- the analyst actually approved.
--
-- Contents
--   1. playbook_runs table (+ RLS)
--   2. runbook_tasks.playbook_run_id / resume_applied (+ unique open gate)
--   3. permissions row `playbooks:approve` and its role grants
--
-- Idempotent: safe to re-run.

-- ============================================================
-- 1. playbook_runs
-- ============================================================
CREATE TABLE IF NOT EXISTS playbook_runs (
    id                UUID PRIMARY KEY,                   -- == engine run_id
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_id       TEXT NOT NULL,
    playbook_name     TEXT NOT NULL,
    -- Frozen definition captured while the run was live. Resume executes this,
    -- not the current edit of the playbook: an analyst approves a specific set
    -- of steps, and an edit made while the run waited must not ride along.
    playbook_snapshot JSONB NOT NULL,
    status            TEXT NOT NULL,                      -- pending|running|pending_approval|
                                                          -- completed|failed|cancelled
    trigger_context   JSONB NOT NULL DEFAULT '{}'::jsonb,
    context           JSONB NOT NULL DEFAULT '{}'::jsonb, -- accumulated run context
    step_results      JSONB NOT NULL DEFAULT '[]'::jsonb,
    next_step_index   INTEGER,                            -- resume index (after the gate)
    gate_step_id      TEXT,
    gate_step_name    TEXT,
    actor             TEXT,                               -- decider (email or user id)
    decided_at        TIMESTAMPTZ,
    error             TEXT,
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ,
    -- Set when the heavy payloads (context/step_results/snapshot) are pruned by
    -- the retention job. The row — status, who decided, when — is kept forever
    -- for audit; the blobs are not worth 90 days.
    payloads_pruned_at TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbook_runs_tenant_created
    ON playbook_runs (tenant_id, created_at DESC);

-- The operator view that matters: parked runs nobody has decided yet.
CREATE INDEX IF NOT EXISTS idx_playbook_runs_pending
    ON playbook_runs (tenant_id)
    WHERE status = 'pending_approval';

-- Retention sweep: terminal rows whose blobs are older than the window.
CREATE INDEX IF NOT EXISTS idx_playbook_runs_prune
    ON playbook_runs (created_at)
    WHERE payloads_pruned_at IS NULL;

ALTER TABLE playbook_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_runs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS playbook_runs_tenant_isolation ON playbook_runs;
CREATE POLICY playbook_runs_tenant_isolation ON playbook_runs
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

COMMENT ON COLUMN playbook_runs.playbook_snapshot IS
    'Frozen playbook definition at gate time. Resume executes this, never the live document.';
COMMENT ON COLUMN playbook_runs.next_step_index IS
    'Index of the first step to execute on resume (the step after the approval gate).';

-- ============================================================
-- 2. runbook_tasks ↔ playbook_runs
-- ============================================================
ALTER TABLE runbook_tasks
    ADD COLUMN IF NOT EXISTS playbook_run_id UUID;

-- Mirrors `feedback_applied` (migration 066):
--   TRUE  — the agents service confirmed the run continued past the gate
--   FALSE — the decision was recorded but the run did not move
--   NULL  — not an approval task, or no resume was attempted
ALTER TABLE runbook_tasks
    ADD COLUMN IF NOT EXISTS resume_applied BOOLEAN;

COMMENT ON COLUMN runbook_tasks.resume_applied IS
    'TRUE when the playbook run actually resumed after approval; FALSE when the '
    'decision was recorded but the run did not move; NULL when not applicable.';

-- One *open* task per run, so re-entering the same gate cannot fan out into
-- duplicate approvals. Completed rows are kept for history.
CREATE UNIQUE INDEX IF NOT EXISTS uq_runbook_tasks_playbook_run
    ON runbook_tasks (playbook_run_id)
    WHERE playbook_run_id IS NOT NULL AND status <> 'completed';

CREATE INDEX IF NOT EXISTS idx_runbook_tasks_playbook_run
    ON runbook_tasks (playbook_run_id)
    WHERE playbook_run_id IS NOT NULL;

-- ============================================================
-- 3. permissions: playbooks:approve
-- ============================================================
INSERT INTO permissions (name, description, category) VALUES
    ('playbooks:approve', 'Approve or reject playbook approval gates', 'playbooks')
ON CONFLICT (name) DO NOTHING;

-- Grants mirror services/api/app/core/security.py: role leads and tenant admins
-- may clear a gate; tier-1 analysts (who only hold playbooks:execute) may not.
-- System role names vary across installs ('tenant_admin' from the static map,
-- 'admin' from create_default_roles, 'soc_lead' / 'lead' in seeded tenants), so
-- grant to every role name that represents a lead-level owner.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON p.name = 'playbooks:approve'
 WHERE r.name IN ('admin', 'tenant_admin', 'soc_lead', 'lead')
ON CONFLICT DO NOTHING;

-- create_default_roles() grants admin every permission dynamically, so a tenant
-- created after this migration gets playbooks:approve without a backfill.
