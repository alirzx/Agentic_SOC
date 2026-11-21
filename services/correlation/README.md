# AiSOC Correlation Engine (v2.0)

The canonical automatic case-creation path. It correlates raw alerts on
`alerts.llm_payload` alone — the immutable payload written by the Splunk
connector — and creates campaign cases through the API. The legacy producers
(agentic funnel, Tier-2 pivot / case policy, agent case promoter, fusion
incident correlator) stay in the tree behind retirement gates for rollback only;
this engine is the single writer, and the case kinds it deliberately does **not**
reproduce are listed under [Case kinds](#case-kinds-produced-vs-deliberately-retired).

Reference (pipeline, keys, scoring, ownership, measured results):
[`docs/architecture/correlation-engine.md`](../../docs/architecture/correlation-engine.md).
Approved design: [`docs/plans/case/2.0.md`](../../docs/plans/case/2.0.md).

## Pipeline

```
alerts.llm_payload
   │  extract_keys()            pure, no I/O, provenance + weights
   ▼
weighted keys  (host / user / ip / domain / hash / process_guid)
   │  observation_signature()   graph-based dedup, not dedup_hash
   ▼
Observation                    LSASS pair · SMB user+minute+target · file hash · entity set
   │  L1 + L2 + L3  ≥ θ=3
   ▼
connected component            union-find over passing pairs
   │  canonicalise              soft-dedup losers → their winner
   ▼
POST /api/v1/cases/from-correlation
```

## Why it does not reuse `dedup_hash`

`dedup_hash` answers "is this the same alert content?". Campaign correlation
asks a different question: "are these different alerts the same *action*?".
The engine therefore groups on the topology of the action (which process
accessed which target, which user wrote which file) and treats the funnel's
`funnel_stage='deduplicated'` rows as evidence, never as case members.

## Case kinds: produced vs. deliberately retired

An alert can belong to **one** case only. Running the retired producers in
parallel with this engine meant two engines could claim the same alert and put
it in two cases, so the retired shapes were switched off on purpose instead of
being ported. They delivered little value on their own, and the single-writer
invariant (atomic claim on `alerts.correlation_owner`) is worth more than
keeping them.

| Case kind | Legacy producer | Produced now? | Where it stands |
|---|---|---|---|
| Multi-alert campaign from shared entities (host / user / IP / domain / hash / process GUID) | `services/api/app/services/agentic_funnel.py` (`creation_method='agentic_funnel'`) | **Yes** | This engine: weighted keys → observations → L1/L2/L3 ≥ θ, connected components, `creation_method='correlation-engine'` |
| Single-alert "incident" case for one eligible seed | `agentic_funnel.run_backfill` (`case_kind='incident'`) | **No, by design** | `case_skip_reason()` returns `below_min_case_alerts` (`AISOC_CORRELATION_MIN_CASE_ALERTS=2`) |
| Investigation checklist / Splunk SPL pivot tasks (`aisoc_case_tasks`) | `agentic_funnel._tasks_for` and `services/agents/app/workers/case_promoter.py` | **No** | `POST /cases/from-correlation` writes one system timeline comment (`services/api/app/services/emitters.py`) and no task rows |
| Escalated-true-positive case from triage | `services/agents/app/workers/case_promoter.py` | **No** | Triage no longer opens cases; evidence that overlaps still clusters here on its own keys |
| Tier-2 "IP pivot" campaign + runbook `case_created` | `services/api/app/services/tier2_ip_pivot.py` | **Partially** | An IP is a weighted key (private `2`, public `3`), so IP-sharing bundles still cluster; there is no pivot-specific runbook step |
| Tier-2 adaptive `create` / `extend` | `services/api/app/services/tier2_adaptive/case_policy.py` | **Partially** | Creation belongs to this engine; extension happens in `/cases/from-correlation` by `tags->>'campaign_key'` |
| Campaign megacase repair | `services/api/app/services/campaign_reconcile.py` | n/a | Manual analyst action only (`POST /cases/{id}/reconcile-correlation`, `dry_run=true` by default) |
| Exact duplicate case merge | `services/api/app/services/exact_dedupe.py` | n/a | Retired mutation; alert soft-dedup remains, and this engine treats dedup losers as evidence |
| Fusion incidents | `services/fusion/app/services/correlator.py`, `incident_store.py` | n/a | Never wrote `aisoc_cases`; gated by `AISOC_LEGACY_FUSION_CORRELATOR` |

### Linkage rules, legacy vs. this engine

Both generations require **shared entity evidence**; neither opens a case from a
rule name / `search_name` alone.

| Signal | Legacy `score_campaign_link` | This engine |
|---|---|---|
| Threshold | `0.55` same family, `0.70` cross-family | `θ = AISOC_CORRELATION_THETA` (default `3`) |
| Shared host | `0.35` + temporal ≤ `0.15` + family `0.15` (≈ `0.56`, links) | weight `2`, plus L2 story/chain `+1` or L3 graph `+1` |
| Shared user | `0.25` | weight `2` |
| Shared private IP | `0.28` same family, `0.20` next to a host/user | weight `2` (needs L2 or L3 to reach θ) |
| Shared public IP | same ladder | weight `3` |
| Shared hash / process GUID | not a key | weight `3` |
| Same detection family | booster `+0.15` | no direct equivalent; a shared analytic story or kill-chain drives L2 |
| Rule name / `search_name` | booster context only | identity-map lookup + role/theme only, never an edge |
| Membership | pairwise against the seed, no transitive | connected components (transitive) |

Two consequences are intentional:

* A campaign needs **two or more** canonical alerts; a lone true positive stays
  an alert. Set `AISOC_CORRELATION_MIN_CASE_ALERTS=1` only if that trade is
  wanted.
* Risk-threshold alerts are no longer forced into "supporting only": they carry
  the `general-intrusion` theme and take part like any other evidence.

Adding one of these shapes back belongs in **this** engine, behind the same
claim lock — not in a re-enabled legacy producer.

## Running

```bash
# full stack
docker compose up -d correlation

# local, against the dev database
cd services/correlation
python -m pytest                     # pure tests, no services required
python -m app.worker                 # background loop

# + the 3 DB-backed engine tests (ledger upsert union, case-link reconcile, and
# a full cycle that publishes the ambient report). They clone the deployed
# tables into a throwaway `correlation_test_*` schema with
# CREATE TABLE ... (LIKE ... INCLUDING ALL) and drop it again, so the SQL runs
# against the real column/constraint shapes and no row outside that schema is
# touched. They skip when no DSN is set.
export CORRELATION_TEST_DSN="$DATABASE_URL"   # the dev script exports the Docker Postgres
python -m pytest tests/test_engine_db.py
```

The service needs `DATABASE_URL` and `API_SERVICE_URL`. `AISOC_CORRELATION_API_TOKEN`
must hold an API key with the `cases:write:correlation` scope in anything other
than development (where the API's dev-mode auth resolves the demo tenant).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AISOC_CORRELATION_OWNER` | `graph_engine` | Value written to `alerts.correlation_owner` |
| `AISOC_CORRELATION_THETA` | `3` | Minimum score to link two observations |
| `AISOC_CORRELATION_LOOKBACK_HOURS` | `72` | Context window |
| `AISOC_CORRELATION_MIN_CASE_ALERTS` | `2` | Distinct canonical alerts needed to open a case (1 lets one repeated detection become a "campaign") |
| `AISOC_CORRELATION_POLL_SECONDS` | `60` | Worker cadence |
| `AISOC_CORRELATION_CLAIM_TTL_MINUTES` | `60` | Stale-claim recovery window |
| `AISOC_GRAPH_ENABLED` | `true` | Project observations into Neo4j |
| `AISOC_CORRELATION_KAFKA_ENABLED` | `false` | Use Kafka as a wake-up hint only |

## Operational endpoints

| Route | Purpose |
|---|---|
| `GET /healthz` | Liveness |
| `GET /readyz` | DB + tenant count + graph state |
| `GET /metrics` | Prometheus |
| `POST /v1/run` | Run one cycle for every tenant in the window |
| `POST /v1/run/{tenant_id}` | Run one cycle for a single tenant (backfill / verification) |
| `GET /v1/diagnostics/{tenant_id}` | Ambient keys and the pairs they vetoed in that tenant's **last cycle in this process** (404 until a cycle runs; not persisted history) |

`POST /v1/*` is guarded by `AISOC_INTERNAL_TOKEN`; in production an unset token
returns 503 rather than opening the endpoint.
