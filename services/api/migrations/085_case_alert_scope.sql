-- 082_case_alert_scope.sql
--
-- Per-case alert scope for the correlation view.
--
-- A case's correlation graph is derived from its member alerts. Real evidence
-- carries noise — a scheduled scan that fires beside a credential-theft burst,
-- a vulnerability alert that shares a host but not the intrusion — and the
-- analyst has to be able to say "not this one", persist that decision, and have
-- every later reader of the case (the graph, the timeline, the AI brief) see the
-- same reduced evidence set.
--
-- Two mechanisms, one row per case:
--
--   * excluded_alert_ids — hard, per-alert exclusions (JSON array of alert ids).
--     The alert stays in the case's evidence (it was ingested evidence; deleting
--     it would rewrite history) but is dropped from the correlation analysis.
--
--   * filters — pattern-level rules evaluated against the alert's
--     `llm_payload` only, stored as JSON array of "field|op|value|mode".
--     `mode=include` keeps only matching alerts, `mode=exclude` drops matches.
--     `llm_payload` is the engine's actual input; the denormalised
--     `alerts.affected_*` columns are deliberately not addressable here, so the
--     filter can never disagree with the keys the graph was built from.
--
-- Idempotent: re-running is a no-op.

BEGIN;

CREATE TABLE IF NOT EXISTS case_alert_scopes (
    case_id            UUID        NOT NULL PRIMARY KEY,
    tenant_id          UUID        NOT NULL,
    excluded_alert_ids JSONB       NOT NULL DEFAULT '[]'::jsonb,
    filters            JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (case_id) REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_case_alert_scopes_tenant
    ON case_alert_scopes (tenant_id);

COMMENT ON TABLE case_alert_scopes IS
    'Analyst alert scope (exclusions + llm_payload filters) applied to a case correlation view.';

COMMENT ON COLUMN case_alert_scopes.excluded_alert_ids IS
    'Alert ids excluded from the case correlation analysis (evidence is retained).';

COMMENT ON COLUMN case_alert_scopes.filters IS
    'Scope filters as JSON array of "llm_payload.<path>|op|value|include|exclude".';

COMMIT;
