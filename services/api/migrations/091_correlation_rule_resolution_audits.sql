-- 091_correlation_rule_resolution_audits.sql
-- Audit trail for canonical identity resolution in graph correlation.
-- Records exact/pattern/generic/fallback mapping decisions and filtered values.

BEGIN;

CREATE TABLE IF NOT EXISTS correlation_rule_resolution_audits (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id UUID NOT NULL,
    rule_name VARCHAR(500) NOT NULL,
    map_id UUID NULL REFERENCES correlation_rule_identity_maps(id) ON DELETE SET NULL,
    matched_source VARCHAR(16) NOT NULL,
    resolved_host_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    resolved_user_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    resolved_ip_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    missing_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    filtered_values JSONB NOT NULL DEFAULT '{}'::jsonb,
    normalizer_version VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT correlation_rule_resolution_audits_source_check
        CHECK (matched_source IN ('exact','tenant_pattern','global_pattern','generic_fallback','missing'))
);

-- Same boot order as 090: ``create_all`` may create this table first, without
-- the default, and the audit INSERT in ``rule_registry.audit_rule_resolution``
-- does not send created_at. Re-assert the default for both creation paths.
ALTER TABLE correlation_rule_resolution_audits
    ALTER COLUMN created_at SET DEFAULT now();

CREATE INDEX IF NOT EXISTS ix_correlation_rule_resolution_audits_tenant_alert
    ON correlation_rule_resolution_audits (tenant_id, alert_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_correlation_rule_resolution_audits_rule
    ON correlation_rule_resolution_audits (tenant_id, rule_name, created_at DESC);

COMMENT ON TABLE correlation_rule_resolution_audits IS
    'Audit of rule-specific llm_payload identity field resolution and filtered values.';

ALTER TABLE correlation_rule_resolution_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_rule_resolution_audits FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS correlation_rule_resolution_audits_tenant ON correlation_rule_resolution_audits;
CREATE POLICY correlation_rule_resolution_audits_tenant ON correlation_rule_resolution_audits
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

COMMIT;
