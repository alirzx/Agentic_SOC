/**
 * Runbook Control Plane: Manual task tracking for exceptions and HITL workflows
 *
 * Phase 1 of Runbook-as-Control-Plane system. Creates table for manual tasks that
 * analysts must complete when auto-triage encounters:
 *   - Confidence threshold violations (needs_review verdict)
 *   - Governance approval gates (L2/L3 autonomy levels)
 *   - LLM circuit-breaker fallbacks
 *   - MSSP SLA obligations
 */

CREATE TABLE IF NOT EXISTS runbook_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    alert_id UUID,
    case_id UUID,

    -- Task type: determines which Runbook tab displays it and what actions are required
    task_type VARCHAR(50) NOT NULL,  -- 'manual_review', 'approval_gate', 'mssp_sla_check'
    
    -- Display metadata
    title VARCHAR(255) NOT NULL,     -- "Review low-confidence phishing alert" or similar
    description TEXT,                 -- Full context: alert fingerprint, LLM reasoning, SLA link, etc
    
    -- Assignment & deadline
    assigned_to UUID,
    due_at TIMESTAMPTZ,              -- SLA deadline for MSSP tasks
    
    -- Status tracking
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'in_progress', 'completed'
    completed_at TIMESTAMPTZ,
    completed_by UUID,
    
    -- Analyst findings & feedback
    resolution TEXT,                 -- Analyst's findings/decision (audit trail)
    feedback_to_llm VARCHAR(20),     -- 'good' = confidence increase, 'poor' = decrease
    
    -- Audit & system metadata
    created_by VARCHAR(50) NOT NULL,  -- 'system' or user_id
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Foreign key constraints are intentionally kept in the canonical tenant
-- table name used across the app: ``tenants.id``.
-- If a manual FK is needed, use:
-- ALTER TABLE runbook_tasks ADD CONSTRAINT fk_runbook_tasks_tenant
--     FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_runbook_tasks_tenant
    ON runbook_tasks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_runbook_tasks_alert
    ON runbook_tasks(alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_runbook_tasks_status
    ON runbook_tasks(status);
CREATE INDEX IF NOT EXISTS idx_runbook_tasks_type
    ON runbook_tasks(task_type);
CREATE INDEX IF NOT EXISTS idx_runbook_tasks_tenant_status
    ON runbook_tasks(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_runbook_tasks_due_at
    ON runbook_tasks(due_at) WHERE due_at IS NOT NULL AND status != 'completed';
