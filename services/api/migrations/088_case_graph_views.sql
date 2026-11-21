-- 085_case_graph_views.sql
--
-- Graph view state snapshots for case correlation workbench.
--
-- When an analyst opens a case's correlation graph, they may:
--   1. Pan/zoom the camera to focus on a region
--   2. Hide or focus certain nodes (observation, host, user, etc.)
--   3. Collapse or expand node clusters
--   4. Apply temporary highlighting or grouping
--
-- This table stores named snapshots of that view state so the analyst can
-- restore it later (e.g., "evidence_layout_clean", "attacker_timeline").
--
-- Each snapshot is scoped to a case + analyst. The view_type mirrors
-- saved_views.view_type but is stored separately here because:
--   - saved_views is for list-page presets (alerts, cases, investigations, playbooks)
--   - case_graph_views is for correlation graph state snapshots per case
--   - They have different schemas and different use cases
--
-- Idempotent: re-running is a no-op.

BEGIN;

CREATE TABLE IF NOT EXISTS case_graph_views (
    id                UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    case_id           UUID        NOT NULL,
    tenant_id         UUID        NOT NULL,
    user_id           UUID        NOT NULL,
    name              TEXT        NOT NULL,
    view_state        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (case_id) REFERENCES aisoc_cases(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT case_graph_views_name_unique
        UNIQUE (case_id, user_id, name)
);

CREATE INDEX IF NOT EXISTS ix_case_graph_views_case
    ON case_graph_views (case_id);

CREATE INDEX IF NOT EXISTS ix_case_graph_views_user
    ON case_graph_views (user_id);

CREATE INDEX IF NOT EXISTS ix_case_graph_views_tenant
    ON case_graph_views (tenant_id);

COMMENT ON TABLE case_graph_views IS
    'Named snapshots of correlation graph view state (camera, focus, hidden nodes, collapsed clusters).';

COMMENT ON COLUMN case_graph_views.view_state IS
    'Opaque JSON: { camera: {x, y, zoom}, focused_nodes: [...], hidden_nodes: [...], collapsed_clusters: [...], ...}';

-- Row-Level Security: analysts can only see their own saved views
ALTER TABLE case_graph_views ENABLE ROW LEVEL SECURITY;

CREATE POLICY case_graph_views_tenant_isolation ON case_graph_views
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

CREATE POLICY case_graph_views_user_access ON case_graph_views
    USING (user_id = current_setting('app.current_user_id')::uuid);

COMMIT;
