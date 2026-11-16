# Campaign Correlation v2 — Production Readiness (2026-11-16)

**Final status:** `IMPLEMENTED_WITH_ENVIRONMENT_LIMITATIONS`

## Environment blockers (live validation)
- `https://api.tryaisoc.com/.../correlation-audit` → HTTP 301 to GitHub (not API)
- `https://aisoc-demo-api.fly.dev` → DNS unresolved from this host
- No `FLY_API_TOKEN` / DB credentials in environment
- `campaign_correlation.py` / `campaign_reconcile.py` are **untracked local files** — not on remote `main` (`a2c38cf`) → **not deployed**

## Fixes this pass
1. `reconcile_campaign_case(dry_run=True)` default (was False) — safer accidental apply
2. `host_centric_discovery_params` now binds **normalized** hosts (was raw casing/trailing-dot miss)
3. Ops readiness tests + staging EXPLAIN script

## Tests executed
`200 passed` (ops readiness + full prior campaign/funnel/pipeline suite)

## Production safety
No Production write, reconcile apply, migration, backfill, deploy, or restart.
