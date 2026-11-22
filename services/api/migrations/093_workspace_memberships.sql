-- 093_workspace_memberships.sql
-- Multi-workspace: a user may belong to many tenants (product "workspaces").
-- User.tenant_id remains the home/default workspace for backwards compatibility.
--
-- Backfill: every existing user gets an owner membership on their home tenant.

BEGIN;

CREATE TABLE IF NOT EXISTS workspace_memberships (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'member',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT workspace_memberships_role_check
        CHECK (role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text])),
    CONSTRAINT workspace_memberships_user_tenant_uq UNIQUE (user_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_memberships_user
    ON workspace_memberships (user_id);
CREATE INDEX IF NOT EXISTS idx_workspace_memberships_tenant
    ON workspace_memberships (tenant_id);

INSERT INTO workspace_memberships (user_id, tenant_id, role)
SELECT u.id, u.tenant_id, 'owner'
  FROM users u
 WHERE u.tenant_id IS NOT NULL
ON CONFLICT (user_id, tenant_id) DO NOTHING;

COMMIT;
