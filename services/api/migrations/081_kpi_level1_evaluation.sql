-- 078_kpi_level1_evaluation.sql
--
-- Phase 3: Case Evaluation and KPI Metrics Tables
--
-- This migration adds:
--   1. case_evaluations — ground-truth evaluations of case correctness
--   2. false_alert_records — tracks which specific alerts are irrelevant in a case
--   3. kpi_metrics — stores calculated KPI snapshots (daily/weekly/monthly)
--
-- Note: FKs reference aisoc_cases (migration 012), not the ORM-managed `cases`
-- table. metric_date is VARCHAR(10) (YYYY-MM-DD string) to match the ORM model.
--
-- Date: 2026-11-09

BEGIN;

-- ── 1. Create case_evaluations table ──────────────────────────────────────
-- Analyst marks cases as correct or incorrect for training data.
CREATE TABLE IF NOT EXISTS case_evaluations (
    id                UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id         UUID        NOT NULL,
    case_id           UUID        NOT NULL,
    evaluator_id      UUID        NOT NULL,
    is_correct        BOOLEAN     NOT NULL,
    confidence_score  INTEGER     NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 100),
    notes             TEXT,
    evaluated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, evaluator_id)
);

CREATE INDEX IF NOT EXISTS ix_evaluations_tenant 
    ON case_evaluations (tenant_id);

CREATE INDEX IF NOT EXISTS ix_evaluations_case 
    ON case_evaluations (case_id);

CREATE INDEX IF NOT EXISTS ix_evaluations_evaluator 
    ON case_evaluations (evaluator_id);

CREATE INDEX IF NOT EXISTS ix_evaluations_evaluated_at 
    ON case_evaluations (evaluated_at);

COMMENT ON TABLE case_evaluations IS
    'Ground-truth evaluation of case correctness. Enables KPI calculation and model improvement.';

COMMENT ON COLUMN case_evaluations.is_correct IS
    'TRUE = valid case, FALSE = false correlation';

COMMENT ON COLUMN case_evaluations.confidence_score IS
    'Evaluator confidence level (0-100).';


-- ── 2. Create false_alert_records table ──────────────────────────────────
-- Track which specific alerts don't belong in a case.
CREATE TABLE IF NOT EXISTS false_alert_records (
    id           UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id    UUID        NOT NULL,
    case_id      UUID        NOT NULL,
    alert_id     UUID        NOT NULL,
    evaluator_id UUID        NOT NULL,
    reason       VARCHAR(255),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, alert_id, evaluator_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_false_alerts_tenant 
    ON false_alert_records (tenant_id);

CREATE INDEX IF NOT EXISTS ix_false_alerts_case 
    ON false_alert_records (case_id);

CREATE INDEX IF NOT EXISTS ix_false_alerts_alert 
    ON false_alert_records (alert_id);

CREATE INDEX IF NOT EXISTS ix_false_alerts_evaluator 
    ON false_alert_records (evaluator_id);

COMMENT ON TABLE false_alert_records IS
    'Marks specific alerts as irrelevant in a case. Affects cluster_purity KPI.';

COMMENT ON COLUMN false_alert_records.reason IS
    'Why this alert does not belong in the case.';


-- ── 3. Create kpi_metrics table ──────────────────────────────────────────
-- Store calculated KPI snapshots for trend tracking and dashboards.
CREATE TABLE IF NOT EXISTS kpi_metrics (
    id                                 UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id                          UUID        NOT NULL,
    metric_date                        VARCHAR(10)   NOT NULL,
    metric_period                      VARCHAR(20) NOT NULL,
    alert_reduction_rate               NUMERIC(5, 4) NOT NULL,
    precision                          NUMERIC(5, 4) NOT NULL,
    cluster_purity                     NUMERIC(5, 4) NOT NULL,
    false_correlation_rate             NUMERIC(5, 4) NOT NULL,
    sample_size                        INTEGER     NOT NULL,
    raw_alerts_count                   INTEGER     NOT NULL,
    created_cases_count                INTEGER     NOT NULL,
    evaluated_cases_count              INTEGER     NOT NULL,
    correct_cases_count                INTEGER     NOT NULL,
    cases_with_false_alerts_count      INTEGER     NOT NULL,
    calculated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at                         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, metric_date, metric_period),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_kpi_tenant 
    ON kpi_metrics (tenant_id);

CREATE INDEX IF NOT EXISTS ix_kpi_metric_date 
    ON kpi_metrics (metric_date);

CREATE INDEX IF NOT EXISTS ix_kpi_period 
    ON kpi_metrics (metric_period);

COMMENT ON TABLE kpi_metrics IS
    'Stores calculated KPI snapshots (daily/weekly/monthly). Used for trends and dashboards.';

COMMENT ON COLUMN kpi_metrics.alert_reduction_rate IS
    '(raw_alerts - created_cases) / raw_alerts. Target > 0.90 (90%).';

COMMENT ON COLUMN kpi_metrics.precision IS
    'correct_cases / evaluated_cases. Target > 0.75 (75%).';

COMMENT ON COLUMN kpi_metrics.cluster_purity IS
    'avg(correct_alerts / total_alerts_per_case). Target > 0.85 (85%).';

COMMENT ON COLUMN kpi_metrics.false_correlation_rate IS
    'cases_with_false_alerts / evaluated_cases. Target < 0.05 (5%).';


-- ── 4. Add FK constraints pointing to aisoc_cases and tenants ──────────────
-- Done as ALTER TABLE so this runs correctly whether the tables were
-- created by this migration or by an earlier Base.metadata.create_all call
-- (which omits the FK because aisoc_cases is not an ORM-managed table).

-- case_evaluations FKs
ALTER TABLE case_evaluations DROP CONSTRAINT IF EXISTS case_evaluations_case_id_fkey CASCADE;
ALTER TABLE case_evaluations ADD CONSTRAINT case_evaluations_case_id_fkey 
    FOREIGN KEY (case_id) REFERENCES aisoc_cases(id) ON DELETE CASCADE;

ALTER TABLE case_evaluations DROP CONSTRAINT IF EXISTS case_evaluations_tenant_id_fkey CASCADE;
ALTER TABLE case_evaluations ADD CONSTRAINT case_evaluations_tenant_id_fkey 
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- false_alert_records FKs
ALTER TABLE false_alert_records DROP CONSTRAINT IF EXISTS false_alert_records_case_id_fkey CASCADE;
ALTER TABLE false_alert_records ADD CONSTRAINT false_alert_records_case_id_fkey 
    FOREIGN KEY (case_id) REFERENCES aisoc_cases(id) ON DELETE CASCADE;

ALTER TABLE false_alert_records DROP CONSTRAINT IF EXISTS false_alert_records_tenant_id_fkey CASCADE;
ALTER TABLE false_alert_records ADD CONSTRAINT false_alert_records_tenant_id_fkey 
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

COMMIT;
