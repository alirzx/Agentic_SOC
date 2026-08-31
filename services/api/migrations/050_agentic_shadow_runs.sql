-- Phase 7 Agentic SOC shadow runs. Independent of Case lifecycle.
-- Rollback is AGENTIC_SOC_ENABLED=false; this table may remain unused.

CREATE TABLE IF NOT EXISTS agentic_shadow_runs (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id             VARCHAR(200) NOT NULL,
    case_id              VARCHAR(200) NOT NULL DEFAULT '',
    status               VARCHAR(20)  NOT NULL DEFAULT 'created',
    agent_version        VARCHAR(80)  NOT NULL DEFAULT 'runtime/v1.0',
    workflow_version     VARCHAR(80)  NOT NULL DEFAULT 'agentic-shadow-v1',
    prompt_version       VARCHAR(80)  NOT NULL DEFAULT 'agentic-soc-runtime/v1',
    started_at           TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ,
    duration_ms          INTEGER      NOT NULL DEFAULT 0,
    risk_score           DOUBLE PRECISION NOT NULL DEFAULT 0,
    confidence           DOUBLE PRECISION NOT NULL DEFAULT 0,
    decision             TEXT         NOT NULL DEFAULT '',
    recommended_actions  JSONB        NOT NULL DEFAULT '[]'::jsonb,
    tool_call_count      INTEGER      NOT NULL DEFAULT 0,
    input_tokens         INTEGER      NOT NULL DEFAULT 0,
    output_tokens        INTEGER      NOT NULL DEFAULT 0,
    estimated_cost       NUMERIC(12, 6) NOT NULL DEFAULT 0,
    error                TEXT,
    evidence             JSONB        NOT NULL DEFAULT '[]'::jsonb,
    comparison           JSONB        NOT NULL DEFAULT '{}'::jsonb,
    result               JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agentic_shadow_tenant_alert
    ON agentic_shadow_runs (tenant_id, alert_id);
CREATE INDEX IF NOT EXISTS idx_agentic_shadow_tenant_created
    ON agentic_shadow_runs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentic_shadow_status
    ON agentic_shadow_runs (status);

ALTER TABLE agentic_shadow_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentic_shadow_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agentic_shadow_tenant ON agentic_shadow_runs;
CREATE POLICY agentic_shadow_tenant ON agentic_shadow_runs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);
