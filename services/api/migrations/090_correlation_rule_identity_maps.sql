-- 090_correlation_rule_identity_maps.sql
-- Rule-specific llm_payload field mappings for the graph correlation normalizer.
-- Tenant-specific rows override global defaults. No fallback guess is allowed by
-- the engine when both exact and pattern matching miss a rule.

BEGIN;

CREATE TABLE IF NOT EXISTS correlation_rule_identity_maps (
    id UUID PRIMARY KEY,
    tenant_id UUID NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_name VARCHAR(500) NOT NULL,
    rule_name_pattern TEXT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    host_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    user_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    ip_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    domain_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    hash_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    process_guid_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    excluded_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    field_kind_overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
    notes TEXT NULL,
    source VARCHAR(32) NOT NULL DEFAULT 'operator',
    created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT correlation_rule_identity_maps_rule_check
        CHECK (rule_name_pattern IS NULL OR btrim(rule_name_pattern) <> '')
);

-- The API boots ORM metadata first (``Base.metadata.create_all``) and applies
-- these migrations afterwards, so the table can already exist without the
-- timestamp defaults declared above. Re-assert them before the seed, which does
-- not send created_at / updated_at: without a default that INSERT dies on the
-- NOT NULL constraint. Idempotent, and harmless when this migration created the
-- table itself.
ALTER TABLE correlation_rule_identity_maps
    ALTER COLUMN created_at SET DEFAULT now(),
    ALTER COLUMN updated_at SET DEFAULT now();

CREATE UNIQUE INDEX IF NOT EXISTS uq_correlation_rule_identity_global_exact
    ON correlation_rule_identity_maps (rule_name)
    WHERE tenant_id IS NULL AND rule_name_pattern IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_correlation_rule_identity_tenant_exact
    ON correlation_rule_identity_maps (tenant_id, rule_name)
    WHERE tenant_id IS NOT NULL AND rule_name_pattern IS NULL;

CREATE INDEX IF NOT EXISTS ix_correlation_rule_identity_tenant_active
    ON correlation_rule_identity_maps (tenant_id, is_active, rule_name);

CREATE INDEX IF NOT EXISTS ix_correlation_rule_identity_pattern
    ON correlation_rule_identity_maps (tenant_id, rule_name_pattern)
    WHERE rule_name_pattern IS NOT NULL;

COMMENT ON TABLE correlation_rule_identity_maps IS
    'Rule-specific llm_payload identity-field mappings used by the graph correlation normalizer.';

-- Evidence-seeded global mappings: 664 llm_payload records on 2026-11-21.
-- Tenant rows always override these exact and pattern mappings.
INSERT INTO correlation_rule_identity_maps (
    id, tenant_id, rule_name, rule_name_pattern, is_active,
    host_fields, user_fields, ip_fields, domain_fields, hash_fields,
    process_guid_fields, excluded_fields, field_kind_overrides,
    notes, source
) VALUES
    (
        '00000000-0000-0000-0000-000000009001', NULL,
        'ESCU - Windows Mimikatz Crypto Export File Extensions - Rule', NULL, TRUE,
        '["dest","dvc","Computer","hostname","host_name"]',
        '["user","src_user","target_user","Caller_User_Name"]',
        '["src","dest","src_ip","dest_ip","daddr","saddr"]',
        '["domain","query","url","dest_domain"]',
        '["file_hash","process_hash","hash","sha1","sha256","md5","imphash"]',
        '["process_guid","SourceProcessGUID","TargetProcessGUID","parent_process_guid"]',
        '["host","splunk_server","splunk_host","splunk_indexer","indexer","server","index"]',
        '{"dest":"host","dvc":"host","Computer":"host","hostname":"host","host_name":"host","src":"ip","src_ip":"ip","dest_ip":"ip","user":"user","src_user":"user","Caller_User_Name":"user","process_guid":"process_guid","SourceProcessGUID":"process_guid","TargetProcessGUID":"process_guid","file_hash":"hash","process_hash":"hash"}',
        'Seeded from the 188-record Mimikatz crypto-export corpus slice.',
        'corpus-20261121'
    ),
    (
        '00000000-0000-0000-0000-000000009002', NULL,
        'ESCU - HTTP C2 Framework User Agent - Rule', NULL, TRUE,
        '["dest","dvc","Computer","hostname","host_name"]',
        '["user","src_user","target_user","Caller_User_Name"]',
        '["src","dest","src_ip","dest_ip","daddr","saddr"]',
        '["domain","query","url","dest_domain"]',
        '["file_hash","process_hash","hash","sha1","sha256","md5","imphash"]',
        '["process_guid","SourceProcessGUID","TargetProcessGUID","parent_process_guid"]',
        '["host","splunk_server","splunk_host","splunk_indexer","indexer","server","index"]',
        '{"dest":"host","dvc":"host","Computer":"host","hostname":"host","host_name":"host","src":"ip","src_ip":"ip","dest_ip":"ip","user":"user","src_user":"user","Caller_User_Name":"user","process_guid":"process_guid","SourceProcessGUID":"process_guid","TargetProcessGUID":"process_guid","file_hash":"hash","process_hash":"hash"}',
        'Seeded from the 161-record HTTP C2 framework user-agent corpus slice.',
        'corpus-20261121'
    ),
    (
        '00000000-0000-0000-0000-000000009003', NULL,
        'ESCU - Windows Non-System Account Targeting Lsass - Rule', NULL, TRUE,
        '["dest","dvc","Computer","hostname","host_name"]',
        '["user","src_user","target_user","Caller_User_Name"]',
        '["src","dest","src_ip","dest_ip","daddr","saddr"]',
        '["domain","query","url","dest_domain"]',
        '["file_hash","process_hash","hash","sha1","sha256","md5","imphash"]',
        '["process_guid","SourceProcessGUID","TargetProcessGUID","parent_process_guid"]',
        '["host","splunk_server","splunk_host","splunk_indexer","indexer","server","index"]',
        '{"dest":"host","dvc":"host","Computer":"host","hostname":"host","host_name":"host","src":"ip","src_ip":"ip","dest_ip":"ip","user":"user","src_user":"user","Caller_User_Name":"user","process_guid":"process_guid","SourceProcessGUID":"process_guid","TargetProcessGUID":"process_guid","file_hash":"hash","process_hash":"hash"}',
        'Seeded from the 65-record LSASS account-targeting corpus slice.',
        'corpus-20261121'
    ),
    (
        '00000000-0000-0000-0000-000000009004', NULL,
        'ESCU - Windows Possible Credential Dumping - Rule', NULL, TRUE,
        '["dest","dvc","Computer","hostname","host_name"]',
        '["user","src_user","target_user","Caller_User_Name"]',
        '["src","dest","src_ip","dest_ip","daddr","saddr"]',
        '["domain","query","url","dest_domain"]',
        '["file_hash","process_hash","hash","sha1","sha256","md5","imphash"]',
        '["process_guid","SourceProcessGUID","TargetProcessGUID","parent_process_guid"]',
        '["host","splunk_server","splunk_host","splunk_indexer","indexer","server","index"]',
        '{"dest":"host","dvc":"host","Computer":"host","hostname":"host","host_name":"host","src":"ip","src_ip":"ip","dest_ip":"ip","user":"user","src_user":"user","Caller_User_Name":"user","process_guid":"process_guid","SourceProcessGUID":"process_guid","TargetProcessGUID":"process_guid","file_hash":"hash","process_hash":"hash"}',
        'Seeded from the 61-record possible credential-dumping corpus slice.',
        'corpus-20261121'
    ),
    (
        '00000000-0000-0000-0000-000000009005', NULL,
        'ESCU - *', 'ESCU - *', TRUE,
        '["dest","dvc","Computer","hostname","host_name","orig_host"]',
        '["user","username","src_user","srcuser","target_user","Caller_User_Name","subjectUserName","TargetUserName"]',
        '["src","dest","src_ip","dst_ip","dest_ip","daddr","saddr","source_ip","destination_ip"]',
        '["domain","query","url","dest_domain","fqdn"]',
        '["file_hash","process_hash","hash","sha1","sha256","md5","imphash"]',
        '["process_guid","SourceProcessGUID","TargetProcessGUID","ParentProcessGuid","parent_process_guid"]',
        '["host","splunk_server","splunk_host","splunk_indexer","indexer","server","index"]',
        '{"dest":"host","dvc":"host","Computer":"host","hostname":"host","host_name":"host","orig_host":"host","src":"ip","src_ip":"ip","dst_ip":"ip","dest_ip":"ip","user":"user","username":"user","src_user":"user","Caller_User_Name":"user","subjectUserName":"user","TargetUserName":"user","process_guid":"process_guid","SourceProcessGUID":"process_guid","TargetProcessGUID":"process_guid","ParentProcessGuid":"process_guid","file_hash":"hash","process_hash":"hash","sha256":"hash","md5":"hash","imphash":"hash"}',
        'Global endpoint/network/process/domain fallback for ESCU Splunk saved searches.',
        'corpus-20261121'
    )
ON CONFLICT DO NOTHING;

-- Row-level security is enabled *after* the seed on purpose. The policy's
-- WITH CHECK accepts only rows owned by the session tenant, so a global row
-- (tenant_id IS NULL) cannot be inserted once FORCE RLS is on — the seed would
-- fail for any migration role that is not a superuser / BYPASSRLS role. This
-- matches the ordering used by 003_rbac.sql.
ALTER TABLE correlation_rule_identity_maps ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_rule_identity_maps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS correlation_rule_identity_maps_tenant ON correlation_rule_identity_maps;
CREATE POLICY correlation_rule_identity_maps_tenant ON correlation_rule_identity_maps
    FOR ALL
    USING (
        tenant_id = current_tenant_id()
        OR tenant_id IS NULL
    )
    WITH CHECK (tenant_id = current_tenant_id());

COMMIT;
