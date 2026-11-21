-- 076_semi_automatic_case.sql
--
-- Support for semi-automatic case creation:
--   1. case_alert_dismissals: Track dismissed suggestions
--   2. attached_via: Track how alert got linked to case
--   3. Extended creation_method with graph_correlation_manual
--
-- Date: 2026-11-10

BEGIN;

-- ── 1. Track alert-to-case attachment source ──────────────────────────────
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS attached_via TEXT;

COMMENT ON COLUMN alerts.attached_via IS
    'How alert was linked to case: engine | suggestion | manual. Null if not linked.';

-- ── 2. Dismissed suggestions (analyst said "no") ──────────────────────────
CREATE TABLE IF NOT EXISTS case_alert_dismissals (
    tenant_id    UUID        NOT NULL,
    case_id      UUID        NOT NULL REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    alert_id     UUID        NOT NULL,
    dismissed_by UUID        REFERENCES users(id),
    reason       TEXT,  -- "false_positive" | "out_of_scope" | "manual"
    dismissed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, case_id, alert_id)
);

CREATE INDEX IF NOT EXISTS ix_case_alert_dismissals_case 
    ON case_alert_dismissals (tenant_id, case_id);

COMMENT ON TABLE case_alert_dismissals IS
    'Record of suggestions dismissed by analysts per case.';

-- ── 3. Dismissed candidates (analyst said "no" to candidate) ──────────────
CREATE TABLE IF NOT EXISTS case_candidate_dismissals (
    tenant_id       UUID        NOT NULL,
    candidate_key   TEXT        NOT NULL,
    dismissed_by    UUID        REFERENCES users(id),
    dismissed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, candidate_key)
);

CREATE INDEX IF NOT EXISTS ix_candidate_dismissals_tenant
    ON case_candidate_dismissals (tenant_id);

COMMENT ON TABLE case_candidate_dismissals IS
    'Record of candidates dismissed by analysts. Used for snooze/ignore logic.';

-- ── 4. Extend creation_method vocabulary ──────────────────────────────────
-- Previous constraint only allowed: graph_correlation | agentic_funnel | manual | system
-- Now we add: graph_correlation_manual (analyst used candidate but modified it significantly)

ALTER TABLE aisoc_cases DROP CONSTRAINT IF EXISTS ck_aisoc_cases_creation_method;
ALTER TABLE aisoc_cases ADD CONSTRAINT ck_aisoc_cases_creation_method
    CHECK (creation_method IN (
        'graph_correlation',
        'graph_correlation_manual',
        'agentic_funnel',
        'manual',
        'system'
    ));

COMMENT ON CONSTRAINT ck_aisoc_cases_creation_method ON aisoc_cases IS
    'Origin of case: graph_correlation (engine-created candidate),
     graph_correlation_manual (analyst used candidate but modified),
     agentic_funnel (legacy promoter), manual (analyst from scratch),
     system (seed/default).';

COMMIT;
