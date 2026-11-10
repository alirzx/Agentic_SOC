-- Migration 063: Automation Rules + Runbook Templates (v2 features)
--
-- automation_rules: lightweight trigger→conditions→action rules.
--   Each rule fires when its trigger_type matches, evaluates its conditions
--   against the subject, goes through the gate, and records in runbook_events.
--   Default posture: dry_run=true, enabled=true.
--
-- runbook_templates: visual multi-step workflow definitions.
--   Stores @xyflow/react node/edge JSON so the editor can round-trip the canvas.
--   Templates are applied to a subject via POST /runbook/templates/{id}/apply.

-- ── automation_rules ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS automation_rules (
    id              uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid            NOT NULL,
    name            varchar(256)    NOT NULL,
    description     text,

    -- When this rule fires
    trigger_type    varchar(64)     NOT NULL,   -- alert.created | alert.updated | case.created | manual

    -- Conditions: [{field, op, value}, ...]  — evaluated by condition_eval.py
    -- All conditions must pass (AND logic). Empty array = always match.
    conditions      jsonb           NOT NULL DEFAULT '[]'::jsonb,

    -- What to do when it fires
    action_slug     varchar(64)     NOT NULL,   -- catalog slug
    action_params   jsonb           NOT NULL DEFAULT '{}'::jsonb,

    -- Autonomy ceiling — the gate's effective level is min(rule, tenant override)
    autonomy_level  varchar(4)      NOT NULL DEFAULT 'L2',

    dry_run         boolean         NOT NULL DEFAULT true,
    enabled         boolean         NOT NULL DEFAULT true,
    priority        int             NOT NULL DEFAULT 100,   -- lower = evaluated first

    created_by      uuid,
    created_at      timestamptz     NOT NULL DEFAULT now(),
    updated_at      timestamptz     NOT NULL DEFAULT now(),
    last_triggered_at timestamptz,
    trigger_count   int             NOT NULL DEFAULT 0,

    CONSTRAINT automation_rules_tenant_name_uniq UNIQUE (tenant_id, name),
    CONSTRAINT automation_rules_trigger_type_chk CHECK (
        trigger_type IN ('alert.created', 'alert.updated', 'case.created', 'manual')
    ),
    CONSTRAINT automation_rules_autonomy_level_chk CHECK (
        autonomy_level IN ('L0', 'L1', 'L2', 'L3', 'L4')
    )
);

CREATE INDEX IF NOT EXISTS automation_rules_tenant_enabled_idx
    ON automation_rules (tenant_id, enabled, priority)
    WHERE enabled = true;

ALTER TABLE automation_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY automation_rules_tenant_isolation ON automation_rules
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- ── runbook_templates ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS runbook_templates (
    id              uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid            NOT NULL,
    name            varchar(256)    NOT NULL,
    description     text,

    subject_type    varchar(16)     NOT NULL DEFAULT 'alert',  -- alert | case | incident

    -- @xyflow/react canvas state (round-tripped from the visual editor)
    nodes           jsonb           NOT NULL DEFAULT '[]'::jsonb,
    edges           jsonb           NOT NULL DEFAULT '[]'::jsonb,

    version         int             NOT NULL DEFAULT 1,
    is_published    boolean         NOT NULL DEFAULT false,

    created_by      uuid,
    created_at      timestamptz     NOT NULL DEFAULT now(),
    updated_at      timestamptz     NOT NULL DEFAULT now(),

    CONSTRAINT runbook_templates_tenant_name_uniq UNIQUE (tenant_id, name),
    CONSTRAINT runbook_templates_subject_type_chk CHECK (
        subject_type IN ('alert', 'case', 'incident')
    )
);

CREATE INDEX IF NOT EXISTS runbook_templates_tenant_idx
    ON runbook_templates (tenant_id, subject_type, is_published);

ALTER TABLE runbook_templates ENABLE ROW LEVEL SECURITY;

CREATE POLICY runbook_templates_tenant_isolation ON runbook_templates
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
