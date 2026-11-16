# Campaign Correlation v2 — Git / Deploy / Live Validation

**Final status:** `DEPLOYMENT_BLOCKED`

## Completed
- Branch: `feat/campaign-correlation-v2`
- Commit: `e269a8df5fafc8a53cb83d0c68b8104645717770`
- Pushed to: `origin/feat/campaign-correlation-v2`
- PR URL: https://github.com/SoorinSecurity/Agentic_SOC/pull/new/feat/campaign-correlation-v2
- Local regression: **200 passed**
- Import/route checks: audit + reconcile registered; `dry_run` default `True`

## Blocked
- `fly` / `gh` CLIs not installed; `FLY_API_TOKEN` unset → no deploy
- `api.tryaisoc.com/health` → HTTP 301 → GitHub (API not reachable)
- Live Audit / Dry-Run / Staging migration+EXPLAIN → not executed

## Production safety
NONE of: Production write, real reconcile, prod migration, backfill, auto-response, unauthorized deploy
