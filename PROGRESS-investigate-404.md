# Investigate 404 fix (2026-11-17)

## Problem
`GET /api/v1/agents/investigations/{run_id}` returned **404** after Start AI Investigation.
Poll state lived only in an in-process `_runs` dict — any agents restart (or OOM) wiped it.
A secondary bug: failed background runs referenced undefined `tenant_owner`, so failure
status was never persisted cleanly.

## Fix
- `services/agents/app/api/investigation_run_store.py` — Redis + memory poll store
- Alert + case investigate paths write/read through that store
- Alert investigate passes the poll `run_id` into `InvestigatorOrchestrator` so the
  ledger row matches; GET hydrates from ledger if Redis/memory miss
- Fixed `tenant_owner` NameError in alert investigate failure path

## Deploy (server)
```bash
cd /path/to/Agentic_SOC   # repo root used as compose project-directory
git pull
docker compose -f infra/compose/docker-compose.demo.yml \
  --project-directory . \
  up -d --build --force-recreate agents
docker logs aisoc-demo-agents --tail 80
```

Then Start AI Investigation again (old run ids from before the rebuild stay 404).

## Verify
1. POST investigate returns `status=running` + `id`
2. Poll GET `/api/v1/agents/investigations/{id}` returns 200 while running
3. `docker restart aisoc-demo-agents` mid-run → poll still 200 (Redis hydrate)
