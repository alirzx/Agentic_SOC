BEGIN;

-- A KB and a source have one owning workspace within a TKG installation.
-- Credential references are deployment secret file names derived from UUIDs.
CREATE UNIQUE INDEX IF NOT EXISTS connectors_tkg_owner ON connectors(tenant_id,id);
CREATE TABLE workspace_tkg_bindings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    instance text NOT NULL CHECK (instance ~ '^[a-z][a-z0-9_]{0,31}$'),
    tkg_tenant text NOT NULL CHECK (btrim(tkg_tenant) <> ''),
    kb_id uuid NOT NULL, source_id uuid NOT NULL,
    source_system text NOT NULL CHECK (btrim(source_system) <> ''),
    source_instance text NOT NULL CHECK (btrim(source_instance) <> ''),
    connector_id uuid,
    enabled boolean NOT NULL DEFAULT false,
    auto_ingest boolean NOT NULL DEFAULT false,
    evaluation boolean NOT NULL DEFAULT false,
    evaluation_identity text NOT NULL DEFAULT 'security_alert'
        CHECK (evaluation_identity IN ('security_alert','legacy_notable')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (instance,kb_id), UNIQUE (instance,source_id),
    UNIQUE (instance,tkg_tenant,source_system,source_instance),
    UNIQUE (tenant_id,id,kb_id,source_id),
    FOREIGN KEY (tenant_id,connector_id) REFERENCES connectors(tenant_id,id),
    CHECK (NOT auto_ingest OR connector_id IS NOT NULL)
);
CREATE UNIQUE INDEX tkg_case_binding ON workspace_tkg_bindings(tenant_id)
    WHERE enabled AND evaluation;
CREATE FUNCTION tkg_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id,NEW.tenant_id,NEW.instance,NEW.kb_id,NEW.source_id,NEW.tkg_tenant,
        NEW.source_system,NEW.source_instance,NEW.connector_id) IS DISTINCT FROM
       (OLD.id,OLD.tenant_id,OLD.instance,OLD.kb_id,OLD.source_id,OLD.tkg_tenant,
        OLD.source_system,OLD.source_instance,OLD.connector_id) THEN
        RAISE EXCEPTION 'immutable TKG binding';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END $$;
CREATE TRIGGER tkg_binding_update BEFORE UPDATE ON workspace_tkg_bindings
    FOR EACH ROW EXECUTE FUNCTION tkg_binding_guard();

CREATE TABLE tkg_alert_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL, alert_row_id uuid NOT NULL, binding_id uuid NOT NULL,
    kb_id uuid NOT NULL, source_id uuid NOT NULL,
    profile text NOT NULL DEFAULT 'agentic-soc.splunk-curated.v1',
    snapshot jsonb, payload bytea, payload_hash text,
    state text NOT NULL DEFAULT 'not_submitted' CHECK (state IN
        ('not_submitted','submitting','retry_scheduled','pending_materialization','bound','quarantined')),
    receipt_id uuid, receipt_status text, receipt_delivery_state text, attempts int NOT NULL DEFAULT 0,
    next_attempt timestamptz NOT NULL DEFAULT now(), error_code text,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(binding_id,alert_row_id),
    FOREIGN KEY (tenant_id,binding_id,kb_id,source_id)
        REFERENCES workspace_tkg_bindings(tenant_id,id,kb_id,source_id)
);
CREATE INDEX tkg_due ON tkg_alert_deliveries(next_attempt,id)
    WHERE state IN ('not_submitted','submitting','retry_scheduled');

ALTER TABLE workspace_tkg_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tkg_alert_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY tkg_binding_workspace ON workspace_tkg_bindings
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
CREATE POLICY tkg_delivery_workspace ON tkg_alert_deliveries
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
REVOKE ALL ON workspace_tkg_bindings, tkg_alert_deliveries FROM aisoc_app;
GRANT SELECT ON workspace_tkg_bindings TO aisoc_app;
-- INSERT's unique conflict check takes SELECT privilege on its target columns.
GRANT INSERT, SELECT ON tkg_alert_deliveries TO aisoc_app;

CREATE FUNCTION tkg_enqueue(a alerts, b workspace_tkg_bindings) RETURNS void
LANGUAGE sql AS $$
    INSERT INTO tkg_alert_deliveries
      (tenant_id,alert_row_id,binding_id,kb_id,source_id,snapshot)
    SELECT a.tenant_id,a.id,b.id,b.kb_id,b.source_id,jsonb_build_object(
      'id',a.id,'title',a.title,'connector_id',a.connector_id,'connector_type',a.connector_type,
      'llm_payload',a.llm_payload,'source_event_ids',a.source_event_ids,
      'raw_event',a.raw_event,'rule_id',a.rule_id,'rule_name',a.rule_name,
      'ocsf_class_uid',a.ocsf_class_uid)
    WHERE b.enabled AND a.tenant_id=b.tenant_id AND a.connector_id=b.connector_id
    ON CONFLICT (binding_id,alert_row_id) DO NOTHING
$$;
CREATE FUNCTION tkg_after_alert_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE previous_tenant text := current_setting('app.current_tenant_id', true);
BEGIN
    -- Internal writers may have no request context. Scope the outbox insert
    -- to the same tenant as the durable row and restore the caller's context.
    PERFORM set_config('app.current_tenant_id', NEW.tenant_id::text, true);
    PERFORM tkg_enqueue(NEW,b) FROM workspace_tkg_bindings b
     WHERE b.enabled AND b.auto_ingest AND b.tenant_id=NEW.tenant_id
       AND b.connector_id=NEW.connector_id;
    PERFORM set_config('app.current_tenant_id', COALESCE(previous_tenant, ''), true);
    RETURN NEW;
END $$;
CREATE TRIGGER tkg_durable_alert AFTER INSERT ON alerts
    FOR EACH ROW EXECUTE FUNCTION tkg_after_alert_insert();
COMMIT;
