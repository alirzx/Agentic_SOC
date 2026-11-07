-- 072_playbook_approvals.sql
--
-- Governance-aware playbook step approval tracking.
--
-- Phase 3: Playbook steps that perform containment actions (isolate_host,
-- block_ip, create_ticket) now consult the autonomy policy before execution.
-- If L2/L3 approval is required, the engine injects an `approval_gate` step
-- and parks the run (`pending_approval` status). This table tracks the approval
-- record independently, allowing analysts to review, approve, or reject each
-- step before the playbook resumes.
--
-- Relationship to playbook_runs:
--   playbook_runs.playbook_run_id  — FK to the run being paused
--   playbook_runs.gate_step_id     — which step triggered the gate
--   playbook_runs.status           — pending_approval
--
-- This table adds the governance *reason* (action_slug, governance_level) so
-- the API and UI can show "Approving: isolate_host (L2)" rather than just
-- "Run is pending_approval".
--
-- Contents:
--   1. playbook_approvals table (tracks governance-aware approvals)
--   2. Indexes for efficient queries by alert and run
--
-- Idempotent: safe to re-run.

-- ============================================================
-- 1. playbook_approvals
-- ============================================================
CREATE TABLE IF NOT EXISTS playbook_approvals (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_run_id        UUID NOT NULL REFERENCES playbook_runs(id) ON DELETE CASCADE,
    alert_id               UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    
    -- The playbook step that requires approval
    step_id                TEXT NOT NULL,        -- e.g. "step-block-ip"
    step_name              TEXT,                 -- e.g. "Block Source IP"
    
    -- Governance context
    action_slug            TEXT NOT NULL,        -- e.g. "isolate_host", "block_ip"
    governance_level       TEXT NOT NULL,        -- L2 | L3 | L4
                                                 -- CHECK (governance_level IN ('L2', 'L3', 'L4'))
    
    -- Analyst decision
    status                 TEXT NOT NULL,        -- pending_approval | approved | rejected
                                                 -- CHECK (status IN ('pending_approval', 'approved', 'rejected'))
    analyst_email          TEXT,                 -- who approved/rejected
    decision_at            TIMESTAMPTZ,          -- when the decision was made
    decision_reason        TEXT,                 -- optional analyst note
    
    -- Audit trail
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant isolation via RLS
ALTER TABLE playbook_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_approvals FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS playbook_approvals_tenant_isolation ON playbook_approvals;
CREATE POLICY playbook_approvals_tenant_isolation ON playbook_approvals
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_playbook_approvals_run_id
    ON playbook_approvals (playbook_run_id);

CREATE INDEX IF NOT EXISTS idx_playbook_approvals_alert_id
    ON playbook_approvals (alert_id);

CREATE INDEX IF NOT EXISTS idx_playbook_approvals_status
    ON playbook_approvals (tenant_id, status, created_at DESC)
    WHERE status = 'pending_approval';  -- Operator dashboard: "Pending approvals"

CREATE INDEX IF NOT EXISTS idx_playbook_approvals_analyst
    ON playbook_approvals (analyst_email, decision_at DESC)
    WHERE decision_at IS NOT NULL;  -- Analyst audit trail

-- Unique constraint: one *open* approval per run+step (no duplicate gates)
CREATE UNIQUE INDEX IF NOT EXISTS uq_playbook_approvals_run_step
    ON playbook_approvals (playbook_run_id, step_id)
    WHERE status = 'pending_approval';

COMMENT ON TABLE playbook_approvals IS
    'Governance-aware approval gates for playbook steps. Tracks which action requires '
    'L2/L3/L4 approval, who approved/rejected, and when.';

COMMENT ON COLUMN playbook_approvals.governance_level IS
    'Autonomy policy level required for this step: L2 (review), L3 (escalation), L4 (critical).';

COMMENT ON COLUMN playbook_approvals.action_slug IS
    'The action this step maps to (e.g., "isolate_host"). Used to query the governance policy.';

-- ============================================================
-- 2. Link playbook_runs to playbook_approvals (for ledger)
-- ============================================================
-- When a playbook step is approved, we want to record the analyst's decision
-- in the alert ledger. The ledger entry references the approval record ID.
-- No schema changes needed; the API will handle the foreign key management.
