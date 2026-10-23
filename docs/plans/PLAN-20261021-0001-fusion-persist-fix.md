## Goal
Diagnose the real failure boundary between connector ingest and alert persistence, fix the actual sink bug, close the observability gap, and surface per-connector error and dropped counts in the web UI alongside the existing events-ingested counter.

## Files / Services Discovered
- services/connectors/app/connectors/splunk.py
- services/connectors/app/scheduler.py
- services/connectors/app/db/connector_repo.py
- services/fusion/app/services/promoter.py
- services/fusion/app/services/alert_sink.py
- services/fusion/app/workers/consumer.py
- services/fusion/app/models/alert.py
- services/agents/app/agents/auto_triage_agent.py
- services/agents/app/runtime/llm_agents/triage.py
- services/agents/tests/test_auto_triage_dispositions.py
- services/api/app/api/v1/endpoints/connectors.py
- apps/web/src/lib/api.ts
- apps/web/src/components/connectors/ConnectorInstanceList.tsx
- apps/web/src/components/connectors/ConnectorsView.tsx

## Root Cause Summary
The final failure was not in Splunk extraction, not in Kafka, and not in the LLM layer.

The live issue was in the fusion persistence layer:
- The event reached promotion successfully.
- The fused alert was built and had a valid id.
- The insert into Postgres failed in `AlertSink.persist()` because the SQL reused the same parameter in two incompatible ways.
- PostgreSQL returned the exact error:
  - `inconsistent types deduced for parameter $5`
  - `DETAIL: text versus character varying`

This is why the row never existed in the alerts table even though the connector and ingestion path looked healthy.

### Why the error occurs
The `_INSERT_SQL` uses `$5` (the severity value) in two positions:
1. As the value for the `severity` column, declared `VARCHAR(20)` — PostgreSQL infers `$5 = character varying`
2. As the CASE scrutinee `CASE $5 WHEN 'critical' THEN 95 ...` — PostgreSQL infers `$5 = text`

`character varying` (OID 1043) and `text` (OID 25) are different type OIDs. When asyncpg prepares the statement, PostgreSQL's parameter-type deduction algorithm encounters both inferences simultaneously and fails with "inconsistent types deduced for parameter $5 (text vs character varying)". This causes every INSERT to raise an exception that the fail-soft handler swallows silently, making the alerts table permanently empty from fusion's perspective.

A second, separate observability issue then surfaced: connector `events_dropped` and `error_count` represent connector-side failures only. They do not count fusion sink failures because those happen after the connector poll has already succeeded. That was why the connector page looked clean while the row still never landed in Postgres.

A third issue was that the web UI only showed "Events ingested" and "Last sync" on each connector card — the `error_count` (connector-side poll failures) and `events_dropped` (filter-dropped events) fields were present in the backend response but not mapped or rendered in the UI.

## Fix Applied

### 1. SQL type mismatch fix — `services/fusion/app/services/alert_sink.py`
Fixed the SELECT list by making $5's type unambiguous everywhere:
- `$5` → `$5::text` in the SELECT column position (severity insert value)
- `CASE $5` → `CASE $5::text` in the priority CASE expression

Both casts pin the parameter to the PostgreSQL `text` OID, which is compatible with `character varying` at the storage layer. asyncpg now unambiguously infers `$5 = text` and prepare succeeds.

### 2. Wire `error_count` to the web UI — `apps/web/src/lib/api.ts`
- Added `errorCount?: number` to the `Connector` TypeScript interface.
- Added `events_dropped?: number | null` to `BackendConnectorResponse` (it was already in the API response but missing from the frontend type).
- Mapped `error_count` → `errorCount` and `events_dropped` → `eventsDropped` in `mapBackendConnector`.

### 3. Expose `total_error_count` in the health endpoint
**`services/api/app/api/v1/endpoints/connectors.py`:**
- Added `total_error_count: int` to the `ConnectorHealthSummary` Pydantic model.
- Added accumulation of `error_count` per connector in the `connector_health_summary` endpoint.
- Added `total_error_count` to the return value.

**`apps/web/src/lib/api.ts`:**
- Added `totalErrorCount: number` to the `ConnectorHealthSummary` TypeScript interface.
- Added `total_error_count` to the raw health response type inside `connectorsApi.health()`.
- Mapped `raw.total_error_count` → `totalErrorCount` in the health mapping.

### 4. Show errored + dropped in the connector card — `apps/web/src/components/connectors/ConnectorInstanceList.tsx`
Expanded the 2-cell stats grid (Events ingested / Last sync) to a 4-cell grid:
- **Events ingested** (existing) — lifetime cumulative counter from `events_ingested`
- **Last sync** (existing)
- **Errored** (new) — connector-side poll failure count from `error_count`; turns red when > 0
- **Dropped** (new) — pre-ingest filter drops from `events_dropped`; turns brand-color when > 0

The "Dropped" badge that previously only appeared when > 0 is preserved; the grid cell ensures the value is always visible (showing 0 when clean).

### 5. Add `totalErrorCount` to the header strip — `apps/web/src/components/connectors/ConnectorsView.tsx`
- Added `totalErrorCount` accumulation to `localStats`.
- Added `totalErrorCount` from `healthSummary` when available.
- Added "Poll Errors" stat tile to the header strip (visible only when > 0).
- Updated the responsive grid column count condition to include `totalErrorCount > 0`.

## Correct Observability Model
- **Connector-side counters** — connector scheduler and pre-ingest health (stored in `connectors` table, lifetime totals)
  - `events_ingested` — events accepted by the ingest service
  - `events_dropped` — events filtered out by pre-ingest pipeline rules
  - `error_count` (UI: **Poll errors**) — connector-side poll failures; incremented by `record_poll_failure()` when the connector service cannot reach the source at all (network down, bad credentials, vault decrypt failure, `fetch_alerts()` exception). `events_ingested` does NOT increment when this fires — data never left the source.
- **Fusion-side counters** — alert persistence health (stored in `connectors` table, written by the fusion service)
  - `fusion_persist_failed` (UI: **Persist failed**) — incremented by `AlertSink._bump_persist_failed()` when the event was successfully pulled from the source and processed through the full fusion pipeline but the final `INSERT INTO alerts` failed (NOT NULL violation, type mismatch, FK violation on unknown tenant, etc.). `events_ingested` DOES increment when this fires — data left the source but never landed in the alerts store. This was the root cause of the original issue: 636 events_ingested, 0 rows in alerts.
- **Fusion envelope fields** — alert persistence health carried on the Kafka fused envelope (not stored in the connectors table)
  - `alert_row_id` — canonical Postgres row id if persisted
  - `persist_outcome` — `inserted | duplicate | unavailable | failed`

### Why both Poll errors and Persist failed are needed

| Scenario | Poll errors | Persist failed | Diagnosis |
|---|---|---|---|
| Source unreachable (Splunk down, bad API key) | > 0 | 0 | Connector-layer problem |
| Source OK, schema/DB issue in fusion | 0 | > 0 | Fusion-layer problem (this issue) |
| Both healthy | 0 | 0 | Clean |
| Both broken simultaneously | > 0 | > 0 | Two independent failures |

Without separating these two counters, a `persist_failed` situation looks identical to a healthy connector (both show `error_count = 0`), making the failure invisible in the UI.

## Step-by-Step Plan
| File / Service | Task | Status |
|---|---|---|
| services/connectors/app/connectors/splunk.py | Confirm extracted fields and provenance survive event normalization | [x] done |
| services/connectors/app/scheduler.py | Confirm connector errors are counted only for connector-side failures | [x] done |
| services/connectors/app/db/connector_repo.py | Verify connector health counters remain connector-scoped and valid | [x] done |
| services/fusion/app/services/promoter.py | Validate promotion policy and data conversion paths | [x] done |
| services/fusion/app/services/alert_sink.py | Fix the live Postgres insert type mismatch ($5::text everywhere) | [x] done |
| services/fusion/app/workers/consumer.py | Emit fused-event persistence outcome and alert row id for downstream observability | [x] done |
| services/fusion/app/models/alert.py | Verify dedup + ID logic for alert persistence | [x] done |
| services/agents/app/runtime/llm_agents/triage.py | Align triage path with same contract | [x] done |
| services/agents/tests/test_auto_triage_dispositions.py | Validate auto-close behavior and prompt-shape invariants | [x] done |
| services/api/app/api/v1/endpoints/connectors.py | Add total_error_count to ConnectorHealthSummary model and endpoint | [x] done |
| apps/web/src/lib/api.ts | Add errorCount to Connector interface, map error_count, add totalErrorCount to health | [x] done |
| apps/web/src/components/connectors/ConnectorInstanceList.tsx | Expand 2-cell grid to 4-cell (ingested / last sync / errored / dropped) | [x] done |
| apps/web/src/components/connectors/ConnectorsView.tsx | Add totalErrorCount to localStats and header strip | [x] done |

## Modified Files Log
- `services/fusion/app/services/alert_sink.py` — fixed the Postgres parameter-type mismatch ($5::text) that blocked all INSERT writes; added `_bump_persist_failed()` to increment `connectors.fusion_persist_failed` on every FAILED persist outcome; fixed a missing newline in `lookup_dedup` that caused a `SyntaxError` at import time.
- `services/fusion/app/workers/consumer.py` — preserved fused-event persistence outcome and row id for observability (no change needed; already correct).
- `services/connectors/app/scheduler.py` — confirmed connector counters remain connector-scoped.
- `services/connectors/app/db/connector_repo.py` — validated the connector counter model and isolation.
- `services/api/app/api/v1/endpoints/connectors.py` — added `total_error_count` to `ConnectorHealthSummary` model and `connector_health_summary` endpoint.
- `apps/web/src/lib/api.ts` — added `errorCount` to `Connector` interface, wired `error_count` from `BackendConnectorResponse`, added `totalErrorCount` to `ConnectorHealthSummary` interface and `connectorsApi.health()` mapping.
- `apps/web/src/components/connectors/ConnectorInstanceList.tsx` — expanded connector card stats grid from 2 cells to 4 (ingested / last sync / errored / dropped).
- `apps/web/src/components/connectors/ConnectorsView.tsx` — added `totalErrorCount` to `localStats` and header strip; "Poll Errors" stat tile appears when > 0.

## Risks & Dependencies
- Remote Postgres/Kafka/ClickHouse endpoints are real and not localhost-bound.
- The `$5::text` fix requires Postgres ≥ 9.6 (all supported versions); no migration needed.
- `total_error_count` in the health endpoint is backward-compatible — old clients ignore the new field.
- Fusion DB writes are fail-soft; the `persist_outcome` in the Kafka envelope is the authoritative signal for fusion-side failures.
- Connector counters must stay connector-scoped; fusion persistence failures must NOT be attributed to `error_count` (that field represents poll-level connector failures only).
