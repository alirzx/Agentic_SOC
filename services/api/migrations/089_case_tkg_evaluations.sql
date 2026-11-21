-- 086_case_tkg_evaluations.sql
--
-- Second-opinion evaluations of a case against the Soorin TKG knowledge graph.
--
-- The LLM verdict is *evidence*, not authority: the row keeps the frozen input
-- payload (so a later reviewer can see exactly what the model saw), the
-- per-alert attribution envelope (which TKG entity/facts backed each alert) and
-- the merged verdict with its reason codes. The correlation engine's verdict is
-- never overwritten — this table records agreement or disagreement only.
--
-- status values:
--   ok                 verdict produced
--   ineligible         precheck refused the run (rubric explains why)
--   unavailable        TKG not configured / unreachable (readiness says why)
--   partial            some alerts could not be resolved inside the budget
--   cached             request served from a previous row (same fingerprint)
--
-- Nothing here is updated in place: one row per run, newest first, so the audit
-- trail keeps earlier opinions instead of losing them to a rotation policy.

CREATE TABLE IF NOT EXISTS case_tkg_evaluations (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id UUID NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    requested_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,

    status VARCHAR(16) NOT NULL,
    reason_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
    detail TEXT NULL,

    -- Engine verdict at evaluation time (frozen for comparison).
    engine_verdict VARCHAR(32) NULL,
    -- Merged verdict produced by this evaluation.
    verdict VARCHAR(32) NULL,
    confidence INTEGER NULL,
    passes VARCHAR(16) NULL,
    agree BOOLEAN NULL,

    payload_fingerprint VARCHAR(64) NULL,
    input_payload JSONB NULL,
    attribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,

    kb_id VARCHAR(64) NULL,
    profile VARCHAR(64) NULL,
    alert_count INTEGER NOT NULL DEFAULT 0,
    resolved_count INTEGER NOT NULL DEFAULT 0,

    duration_ms INTEGER NULL,
    tokens_in INTEGER NULL,
    tokens_out INTEGER NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS ix_case_tkg_evaluations_case
    ON case_tkg_evaluations (case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_case_tkg_evaluations_tenant
    ON case_tkg_evaluations (tenant_id, created_at DESC);
