-- Phase 8 Agentic SOC evaluation runs. Evaluation-only; no production mutation.

CREATE TABLE IF NOT EXISTS agentic_evaluation_runs (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id            UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    dataset_id           VARCHAR(120) NOT NULL,
    dataset_version      VARCHAR(40)  NOT NULL DEFAULT '1.0',
    agent_version        VARCHAR(80)  NOT NULL DEFAULT 'runtime/v1.0',
    workflow_version     VARCHAR(80)  NOT NULL DEFAULT 'agentic-eval-v1',
    prompt_version       VARCHAR(80)  NOT NULL DEFAULT 'agentic-soc-runtime/v1',
    tool_version         VARCHAR(80)  NOT NULL DEFAULT 'soc-tools/v1',
    model                VARCHAR(120) NOT NULL DEFAULT 'deterministic',
    status               VARCHAR(20)  NOT NULL DEFAULT 'created',
    total_cases          INTEGER      NOT NULL DEFAULT 0,
    completed_cases      INTEGER      NOT NULL DEFAULT 0,
    failed_cases         INTEGER      NOT NULL DEFAULT 0,
    started_at           TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ,
    total_duration_ms    INTEGER      NOT NULL DEFAULT 0,
    input_tokens         INTEGER      NOT NULL DEFAULT 0,
    output_tokens        INTEGER      NOT NULL DEFAULT 0,
    estimated_cost       NUMERIC(12, 6) NOT NULL DEFAULT 0,
    aggregate_metrics    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    comparison_summary   JSONB        NOT NULL DEFAULT '{}'::jsonb,
    quality_gates        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    production_readiness JSONB        NOT NULL DEFAULT '{}'::jsonb,
    pipeline_status      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    report               JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agentic_case_evaluations (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    evaluation_run_id    UUID         NOT NULL REFERENCES agentic_evaluation_runs(id) ON DELETE CASCADE,
    tenant_id            UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id              VARCHAR(200) NOT NULL,
    existing_result      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    agentic_result       JSONB        NOT NULL DEFAULT '{}'::jsonb,
    ground_truth         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    classification_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    severity_score       DOUBLE PRECISION NOT NULL DEFAULT 0,
    risk_score_metric    DOUBLE PRECISION NOT NULL DEFAULT 0,
    mitre_score          DOUBLE PRECISION NOT NULL DEFAULT 0,
    ioc_score            DOUBLE PRECISION NOT NULL DEFAULT 0,
    correlation_score    DOUBLE PRECISION NOT NULL DEFAULT 0,
    evidence_score       DOUBLE PRECISION NOT NULL DEFAULT 0,
    investigation_score  DOUBLE PRECISION NOT NULL DEFAULT 0,
    hallucination_score  DOUBLE PRECISION NOT NULL DEFAULT 0,
    action_score         DOUBLE PRECISION NOT NULL DEFAULT 0,
    overall_score        DOUBLE PRECISION NOT NULL DEFAULT 0,
    analyst_review_required BOOLEAN    NOT NULL DEFAULT false,
    metric_details       JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agentic_eval_runs_tenant_created
    ON agentic_evaluation_runs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agentic_case_eval_run
    ON agentic_case_evaluations (evaluation_run_id);

ALTER TABLE agentic_evaluation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentic_evaluation_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agentic_eval_runs_tenant ON agentic_evaluation_runs;
CREATE POLICY agentic_eval_runs_tenant ON agentic_evaluation_runs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE agentic_case_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agentic_case_evaluations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agentic_case_eval_tenant ON agentic_case_evaluations;
CREATE POLICY agentic_case_eval_tenant ON agentic_case_evaluations
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);
