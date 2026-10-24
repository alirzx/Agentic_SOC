# Phase 2.1 — Production Readiness Validation

## Audit findings (2026-10-14)

- Wave-1 + Phase-2 code is present on `main` (migrations 057/058, IncidentStore,
  correlator durable restore, shadow comparison side-effect contract, asset
  enrich, unified risk, graph budgets, near-dup helper).
- Near-duplicate is **not** imported by `FusionEngine` (fingerprint remains
  authoritative). Confirmed via source inspection tests.
- Shadow runtime (`shadow_service.py`) does **not** call `promote_to_case`,
  `PlaybookEngine`, or BC suppress writers. Confirmed via source inspection.
- Local environment for this validation pass: **no Docker**, **no reachable
  Postgres** on localhost:5432. Real PG integration tests are gated and skip.

## How to run Postgres integration (staging / CI with DB)

```bash
export AISOC_RUN_INTEGRATION=1
export DATABASE_URL=postgresql://aisoc:aisoc@localhost:5432/aisoc
# apply migrations including 057 + 058 first
cd services/fusion
pytest -m integration tests/test_fusion_incidents_integration.py -q
```

## Migration deploy / rollback

### Deploy

1. Apply `057_alerts_occurrence_count.sql` (if not already).
2. Apply `058_fusion_incidents.sql` (`IF NOT EXISTS` / idempotent).
3. Redeploy `fusion` then `agents` (then `api` for ORM column visibility).

### Rollback

1. Redeploy previous service images (safe: IncidentStore fail-soft if table missing).
2. Optional: `ALTER TABLE alerts DROP COLUMN IF EXISTS fusion_incident_id;`
3. Optional: `DROP TABLE IF EXISTS fusion_incidents;`
4. Do **not** drop if production Cases already depend on `fusion_incidents.case_id`
   linkage without a data-migration plan.

## Safe defaults

| Variable | Safe default | Notes |
|---|---|---|
| `AGENTIC_SOC_ENABLED` | `false` | Do not enable in prod without ops approval |
| `AISOC_NEAR_DUP_SHADOW` | `0` | Shadow-only similarity |
| `AISOC_ASSET_ENRICH_ENABLED` | `1` | Fail-soft; disable if CMDB noisy |
| Case gates | unchanged | Risk does not authorize Cases |

## Go / No-Go for controlled staging

See final Persian report in the Phase 2.1 delivery. Conditionally **GO for
staging** after migration 058 apply + focused suite green; **NO-GO for
production** until real Postgres integration + shadow dry-run are observed.
