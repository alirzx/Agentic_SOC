# Workspaces

AiSOC **workspaces** are the product name for tenant isolation units.

## Model

- Storage table: `tenants`
- Membership table: `workspace_memberships` (`user_id`, `tenant_id`, `role`)
- `users.tenant_id` remains the **home** workspace for backwards compatibility

Connectors, alerts, cases, and ingest events are scoped by `tenant_id`. Data created in one workspace is never visible in another.

## Auth flow

1. `POST /api/v1/auth/login` — JWT with `workspace_selected=false`
2. Console redirects to `/workspaces`
3. `POST /api/v1/auth/select-workspace` — membership check, re-issues JWT with `workspace_selected=true` and the chosen `tenant_id`
4. `get_current_user` honours JWT `tenant_id` only when membership is valid

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/workspaces` | List memberships |
| POST | `/api/v1/workspaces` | Create workspace (caller becomes owner) |
| GET | `/api/v1/workspaces/me` | Active workspace from token |
| POST | `/api/v1/auth/select-workspace` | Bind session to a workspace |

## UI

- Post-login picker: `/workspaces`
- Top bar switcher rebinds JWT and reloads
- Logout clears `aisoc.activeTenantId`
