-- 062_runbook.sql
--
-- Runbook Phase 0 — the governed action ledger.
--
-- WHY A NEW TABLE (and why it does not duplicate investigation_events)
-- ------------------------------------------------------------------
-- ``investigation_events`` (008) is already an append-only, tenant-scoped,
-- per-``run`` decision ledger. It answers "what did the *agent* do inside one
-- investigation run". ``runbook_events`` answers a different question:
-- "what happened to this *subject* (alert / case / incident), by whom, under
-- which policy, and with what result" — including steps that are not agent
-- steps at all: the connector's query mode, an analyst disposition, a funnel
-- stage change, an ITSM push, an approval decision.
--
-- ``investigation_events`` cannot hold those: its ``run_id`` is NOT NULL and
-- FK-bound to ``investigation_runs``. So this table is the subject-scoped
-- spine, and each row may *point at* a run (``run_id``) rather than copy that
-- run's steps. Expansion of an investigation stays in the existing ledger UI;
-- the Runbook row is the one-line "Investigations run #abc" entry.
--
-- WHAT ELSE THIS MIGRATION DOES
-- -----------------------------
-- The tenant override layer for action policy already exists
-- (``aisoc_autonomy_thresholds``, migrations 020 + 021) and is already
-- exposed by ``GET/PUT/DELETE /api/v1/autonomy-policy``. Rather than build a
-- parallel ``tenant_action_overrides`` table (which would give operators two
-- places to disagree with each other), this migration extends that table with
-- the two fields the Runbook gate needs:
--
--   enabled         — TenantActionOptIn: can this tenant run this action at all?
--   autonomy_level  — the tenant's L0–L4 ceiling for this action (NULL = no cap)
--
-- Both are additive with defaults, so every existing row keeps its behaviour
-- and pre-062 readers keep working (the gate falls back to the legacy column
-- set when these are absent).

BEGIN;

-- ============================================================
-- 1. Tenant action opt-in / autonomy ceiling
-- ============================================================
ALTER TABLE aisoc_autonomy_thresholds
    ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS autonomy_level TEXT;

ALTER TABLE aisoc_autonomy_thresholds
    DROP CONSTRAINT IF EXISTS aisoc_autonomy_thresholds_level_chk;
ALTER TABLE aisoc_autonomy_thresholds
    ADD CONSTRAINT aisoc_autonomy_thresholds_level_chk
    CHECK (autonomy_level IS NULL OR autonomy_level IN ('L0', 'L1', 'L2', 'L3', 'L4'));

COMMENT ON COLUMN aisoc_autonomy_thresholds.enabled IS
    'TenantActionOptIn (migration 062): FALSE stops the Runbook gate from letting this action run for this tenant, regardless of confidence.';
COMMENT ON COLUMN aisoc_autonomy_thresholds.autonomy_level IS
    'L0-L4 ceiling the Runbook gate may grant for this action (migration 062). NULL means no tenant-specific cap — the blast-radius default applies.';

-- ============================================================
-- 2. runbook_events — append-only governed action ledger
-- ============================================================
CREATE TABLE IF NOT EXISTS runbook_events (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID         NOT NULL,
    subject_type     VARCHAR(16)  NOT NULL,          -- alert | case | incident
    subject_id       UUID         NOT NULL,
    seq              BIGINT       NOT NULL,          -- monotonic per (tenant, subject)
    occurred_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    stage            VARCHAR(32)  NOT NULL,          -- ingest|enrich|triage|investigate|funnel|respond|itsm|close
    kind             VARCHAR(32)  NOT NULL,          -- query_mode|llm_payload|enrichment|triage|investigation|finding|policy|approval|action|state_change
    action_name      VARCHAR(64),                    -- catalog slug (app/services/runbook/action_catalog.py)
    actor_type       VARCHAR(16)  NOT NULL,          -- system|agent|analyst|connector
    actor_id         TEXT,
    actor_label      TEXT,                           -- display name: "TriageAgent", "analyst@corp"
    summary          TEXT         NOT NULL,          -- the "What we did" line
    detail           TEXT,                           -- expanded body
    status           VARCHAR(16)  NOT NULL,          -- recorded|allowed|denied|executed|simulated|failed|skipped
    policy           JSONB,                          -- {decision, autonomy_level, layer, thresholds, reason}
    approval_id      UUID,                           -- soft ref to agent_approvals.id
    run_id           UUID,                           -- soft ref to investigation_runs.id (detail lives there)
    input            JSONB,
    output           JSONB,
    cost             JSONB,                          -- {usd, tokens, model}
    error            TEXT,                           -- sanitised before write (no newlines)
    duration_ms      INTEGER,
    audit_log_id     UUID,                           -- soft ref to audit_log.id when AuditContract requested it
    idempotency_key  VARCHAR(128),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT runbook_events_subject_type_chk
        CHECK (subject_type IN ('alert', 'case', 'incident')),
    CONSTRAINT runbook_events_actor_type_chk
        CHECK (actor_type IN ('system', 'agent', 'analyst', 'connector')),
    CONSTRAINT runbook_events_status_chk
        CHECK (status IN ('recorded', 'allowed', 'denied', 'executed', 'simulated', 'failed', 'skipped')),
    CONSTRAINT runbook_events_seq_positive_chk
        CHECK (seq > 0),
    CONSTRAINT runbook_events_subject_seq_uniq
        UNIQUE (tenant_id, subject_type, subject_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_runbook_events_subject
    ON runbook_events (tenant_id, subject_type, subject_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_runbook_events_stage
    ON runbook_events (tenant_id, stage, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_runbook_events_action
    ON runbook_events (tenant_id, action_name, created_at DESC)
    WHERE action_name IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_runbook_events_run
    ON runbook_events (run_id)
    WHERE run_id IS NOT NULL;

-- Idempotency: a retried writer must resolve to the existing row instead of
-- appending a duplicate step. Scoped per tenant, like alerts.idempotency_key.
CREATE UNIQUE INDEX IF NOT EXISTS runbook_events_idempotency_uniq
    ON runbook_events (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Append-only: deny UPDATE and DELETE. Same mechanism as audit_log (004) and
-- investigation_events (008) so the guarantee lives in the database, not in
-- the discipline of each writer.
CREATE OR REPLACE FUNCTION runbook_events_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'runbook_events rows are immutable (attempted %)', TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS trg_runbook_events_immutable ON runbook_events;
CREATE TRIGGER trg_runbook_events_immutable
    BEFORE UPDATE OR DELETE ON runbook_events
    FOR EACH ROW EXECUTE FUNCTION runbook_events_immutable();

-- Tenant isolation, defence-in-depth behind the query-layer WHERE tenant_id.
-- ``current_tenant_id()`` returns NULL for service-to-service writers that do
-- not set the GUC (fusion, agents), and the policy deliberately allows that
-- case — the query layer remains the primary gate.
ALTER TABLE runbook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE runbook_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runbook_events_tenant ON runbook_events;
CREATE POLICY runbook_events_tenant ON runbook_events
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

COMMENT ON TABLE runbook_events IS
    'Append-only governed action ledger (migration 062): what happened to an alert/case/incident, by whom, under which policy, with which result.';
COMMENT ON COLUMN runbook_events.summary IS
    'One-line analyst-facing description — the "What we did" entry. Never fabricated: a subject with no rows renders an explicit empty state.';
COMMENT ON COLUMN runbook_events.policy IS
    'Snapshot of the gate decision that allowed/denied the step, so "why was this allowed" is answerable years later without replaying the policy.';
COMMENT ON COLUMN runbook_events.run_id IS
    'Soft reference to investigation_runs.id. Step-level detail stays in investigation_events; this row is the Runbook one-liner.';

COMMIT;
