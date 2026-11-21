# Correlation Engine: Canonical Case Writer and Rule Identity Registry

> **This is the only plan file for the correlation work.** It absorbed
> `PLAN-20261121-correlation-rule-identity.md` and the correlation part of
> `PLAN-20261121-1322-case-review-main-migration.md`; both files were deleted so
> the design, the migration record and the case-kind map live in one place.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `services/correlation` the sole automatic case-creation correlator and add a tenant-aware rule-to-identity-field registry that makes `llm_payload` field names explicit and stable.

**Architecture:** Keep `llm_payload` as the immutable evidence source. Add a database registry mapping each Splunk rule name or normalized rule pattern to canonical identity paths. The correlation normalizer resolves identities only through that registry plus a strict generic fallback; legacy fusion/agent/Tier-2 writers stop creating automatic cases and become read-only compatibility paths.

**Tech Stack:** Python 3.11, FastAPI, asyncpg, PostgreSQL, Pydantic, Neo4j, pytest, the existing correlation engine package.

**Spec:** The repository evidence corpus at `C:\Users\ali\Desktop\neo4j-test` and `docs/plans/case/all-in-one-2` shows 664 payload records, inconsistent field use across rules, public IPs in destination fields, and host/index metadata drift. This plan replaces name/column guessing with explicit rule registry mappings.

## Global Constraints

- `llm_payload` is the only correlation source of truth.
- No legacy agent/fusion service may create or extend `aisoc_cases` automatically after cutover.
- Legacy code must not be behavior-refactored or rewritten in place. Add a short English header comment explaining retirement/delegation and disable or feature-gate automatic case creation.
- Real implementation work belongs in `services/correlation/`, the rule registry/API, and connector identity normalization only.
- Manual API case creation remains a human/user operation.
- Public IP values must not become victim hosts.
- Splunk `host` and `splunk_server` are index/search-head metadata, not victim hosts.
- Identity extraction must be tenant-aware and source-field-aware.
- A rule mapping miss is observable and auditable; it must not silently guess a dangerous field.
- Existing migrations are renumbered through `089_case_tkg_evaluations.sql`; add registry migrations only after `089`, as `090` and `091`.
- No commit/push/branch deletion occurs until explicit user approval.

## Baseline Evidence

- External corpus: 664 payload records.
- Current field presence:
  - `dest`: 644
  - `src`: 187
  - `dvc`: 7
  - `Computer`: 5
  - `src_ip`: 5
  - `dest_ip`: 3
  - `host` / `hostname`: 0 in corpus alert_fields
- External test engine: 14 clusters → 4 cases, 3 watch groups, 7 noise groups.
- 10 external pure-Python tests pass.
- Current correlation normalizer already distinguishes Splunk indexer metadata, but rule-specific field meanings are not registered.

## Files / Services Discovered

### Canonical correlation service
- `services/correlation/app/normalizer/extract_keys.py`
- `services/correlation/app/services/engine.py`
- `services/correlation/app/services/case_client.py`
- `services/correlation/app/services/observations.py`
- `services/correlation/app/services/scoring.py`
- `services/correlation/app/services/frequency.py`
- `services/correlation/app/services/graph.py`
- `services/correlation/app/core/config.py`
- `services/correlation/tests/`

### Legacy producers to retire or gate
- `services/agents/app/workers/case_promoter.py`
- `services/agents/app/workers/fused_alert_consumer.py`
- `services/api/app/services/agentic_funnel.py`
- `services/api/app/services/campaign_correlation.py`
- `services/api/app/services/campaign_reconcile.py`
- `services/api/app/services/tier2_adaptive/case_policy.py`
- `services/api/app/services/tier2_adaptive/correlation.py`
- `services/api/app/services/tier2_ip_pivot.py`
- `services/fusion/app/services/correlator.py`
- `services/fusion/app/services/fusion_engine.py`
- `services/fusion/app/services/incident_store.py`

### Canonical API persistence boundary
- `services/api/app/api/v1/endpoints/cases.py`
- `services/api/app/services/case_fanout.py`
- `services/api/app/api/v1/deps.py`
- `services/api/app/models/aisoc_case.py`
- `services/api/app/models/alert.py`

### Connector source
- `services/connectors/app/connectors/splunk.py`
- `services/connectors/tests/test_splunk_simple_mode.py`
- `services/connectors/tests/test_splunk_connector.py`

### Evidence corpus
- `C:\Users\ali\Desktop\neo4j-test\case_engine.py`
- `C:\Users\ali\Desktop\neo4j-test\tests\test_case_engine.py`
- `docs/plans/case/all-in-one-2/llm_payload_only.json`
- `docs/plans/case/all-in-one-2/filter_presets.json`
- `docs/plans/case/all-in-one-2/REPORT-20261118-graph-engine-review-fa.md`
- `docs/plans/case/all-in-one-2/REPORT-20261118-neo4j-impact-fa.md`

## Proposed Database Design

### Rule registry table

```sql
CREATE TABLE correlation_rule_identity_maps (
    id UUID PRIMARY KEY,
    tenant_id UUID NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_name VARCHAR(500) NOT NULL,
    rule_name_pattern TEXT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    host_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    user_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    ip_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    domain_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    hash_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    process_guid_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    excluded_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    field_kind_overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
    notes TEXT NULL,
    source VARCHAR(32) NOT NULL DEFAULT 'operator',
    created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Rules with `tenant_id = NULL` are global defaults. Tenant-specific rows override the matching global row. Match order:

1. exact `rule_name`
2. exact tenant rule pattern
3. global rule pattern
4. generic fallback

### Registry resolution audit table

```sql
CREATE TABLE correlation_rule_resolution_audits (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id UUID NOT NULL,
    rule_name VARCHAR(500) NOT NULL,
    map_id UUID NULL REFERENCES correlation_rule_identity_maps(id) ON DELETE SET NULL,
    matched_source VARCHAR(16) NOT NULL,
    resolved_host_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    resolved_user_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    resolved_ip_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    missing_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    filtered_values JSONB NOT NULL DEFAULT '{}'::jsonb,
    normalizer_version VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### API endpoints

- `GET /api/v1/correlation/rules` — list mappings for tenant/global scope.
- `POST /api/v1/correlation/rules` — create mapping.
- `PATCH /api/v1/correlation/rules/{id}` — update mapping.
- `GET /api/v1/correlation/rules/{id}/resolution/{alert_id}` — explain resolved fields.

Every endpoint is tenant-scoped and permission-gated.

## Canonical Identity Contract

The normalizer will accept only one canonical identity contract:

```json
{
  "hosts": ["win-dc-01.attackrange.local"],
  "users": ["administrator"],
  "ips": ["10.0.0.15"],
  "domains": ["attackrange.local"],
  "hashes": ["012345..."],
  "process_guids": ["{...}"],
  "provenance": {
    "host": ["llm_payload.alert_fields.dest"],
    "ip": ["llm_payload.alert_fields.src"],
    "user": ["llm_payload.alert_fields.user"]
  }
}
```

Rules:

- public IP never becomes a victim host;
- private IP may be a destination or source entity;
- `host` / `splunk_server` / `index` only identify the Splunk indexer and are excluded for Splunk payloads;
- `dest`, `dvc`, `Computer`, and `hostname` are event-host candidates;
- `src` is IP-or-host based on value shape, not field name alone;
- `user`, `src_user`, `Caller_User_Name` are candidate user fields;
- rule mapping narrows ambiguous fields to prevent arbitrary fallback noise;
- all extracted values keep dotted provenance paths.

## Producers to Disable or Re-route

| Producer | Required action | Success guard |
|---|---|---|
| `services/agents/app/workers/case_promoter.py` | Retain current code only behind `AISOC_AGENT_AUTO_CASE=0` with a retirement header comment | no runtime direct `INSERT aisoc_cases` |
| `services/agents/app/workers/fused_alert_consumer.py` | Feature-gate or comment out `promote_to_case()` call with a retirement header | consumer no longer creates cases |
| `services/api/app/services/agentic_funnel.py` | Comment or feature-gate automatic backfill case insertions; leave read/compatibility logic untouched | no runtime `INSERT aisoc_cases` for uncorrelated alerts |
| `services/api/app/services/campaign_correlation.py` | Retirement header plus disabled legacy writer entry point | no independent campaign key writer |
| `services/api/app/services/campaign_reconcile.py` | Retirement header plus mutation disabled; correlation engine owns membership | no direct alert/case membership rewrite |
| `services/api/app/services/tier2_adaptive/case_policy.py` | Add retirement header and keep recommendation-only gate | create/extend decisions become correlation candidate bundles |
| `services/api/app/services/tier2_ip_pivot.py` | Add retirement header and disable direct case creation | no direct case insert/extend |
| `services/fusion/app/services/correlator.py` | Add retirement header and production feature gate; do not rewrite legacy grouping implementation | fusion no longer creates incidents/cases outside correlation engine |
| `services/fusion/app/services/incident_store.py` | Legacy incident cache only; add retirement header | no automatic `aisoc_cases` writes |
| `POST /api/v1/cases/from-correlation` | Keep as only external case writer | all correlation claims pass through API |
| `POST /api/v1/cases` | Manual case creation only | no automatic alert pipeline uses it |

## Case Kinds: Legacy Producers vs. the Canonical Engine

Automatic case creation has one owner. An alert belongs to at most one case, so
re-enabling a retired producer would let two engines claim the same alert and
put it in two cases. The retired shapes are therefore **not ported**. They stay
off deliberately and are deleted in a later plan once this engine is fully
validated.

| Case kind | Legacy producer | Produced by `services/correlation`? | Why disabled | Notes |
|---|---|---|---|---|
| Multi-alert campaign from shared entities (host / user / IP / domain / hash / process GUID) | `services/api/app/services/agentic_funnel.py` | **Yes** | Not disabled — the one shape the engine reimplements | Weighted keys + L1/L2/L3 ≥ θ, connected components, `creation_method='correlation-engine'` |
| Single-alert "incident" case for one eligible seed | `agentic_funnel.run_backfill` (`case_kind='incident'`) | **No, by design** | Below the minimum evidence for a campaign: one alert proves no linkage, and it is usually a member of a real campaign the engine builds later, so the same alert would be double-homed | `case_skip_reason()` → `below_min_case_alerts` (`AISOC_CORRELATION_MIN_CASE_ALERTS=2`) |
| Investigation checklist / SPL pivot tasks (`aisoc_case_tasks`) | `agentic_funnel._tasks_for`, `services/agents/app/workers/case_promoter.py` | **No** | Outside the linkage scope: the tasks were derived from the legacy scorer's candidate list and runbook mapping, which no longer exist on this path | `/cases/from-correlation` writes one timeline comment only |
| Escalated true-positive case from triage | `services/agents/app/workers/case_promoter.py` | **No** | Triage-driven rather than entity-driven: a verdict opened the case, so the same alerts could also be claimed by the campaign engine — two writers, two cases | Triage no longer opens cases; overlapping evidence clusters here on its own keys |
| Tier-2 "IP pivot" campaign + runbook `case_created` | `services/api/app/services/tier2_ip_pivot.py` | **Partially** | Separate heuristic (src/dest IP siblings within 24h) that duplicates the IP key the engine already scores, and it emitted its own runbook step | IP is a weighted key (private `2`, public `3`); no pivot-specific runbook step |
| Tier-2 adaptive `create` / `extend` | `services/api/app/services/tier2_adaptive/case_policy.py` | **Partially** | Entity + temporal decisions duplicated the engine's linking; kept as recommendation-only so a single owner decides membership | Creation here; extension via `tags->>'campaign_key'` in `/cases/from-correlation` |
| Campaign megacase repair | `services/api/app/services/campaign_reconcile.py` | n/a | Never a case kind: it rewrites membership of cases the retired loose `OR(host\|ip\|user)` gate produced, so it stays a manual analyst repair instead of an automatic writer | Manual analyst action, `dry_run=true` by default |
| Exact duplicate case merge | `services/api/app/services/exact_dedupe.py` | n/a | A mutation, not a creator: a second mutator could rewrite a case the engine owns and drop its evidence; duplicates are handled by alert-level soft-dedup plus the ownership claim | Retired mutation; alert soft-dedup remains, losers become evidence |
| Fusion incidents | `services/fusion/app/services/correlator.py`, `incident_store.py` | n/a | Never wrote `aisoc_cases`; a second grouping of the same alerts would compete with the engine's components | `AISOC_LEGACY_FUSION_CORRELATOR` opt-in |

### Linkage rules

Neither generation opens a case from a rule name / `search_name` alone; shared
entity evidence is mandatory in both.

| Signal | Legacy `score_campaign_link` | Canonical engine |
|---|---|---|
| Threshold | `0.55` same family, `0.70` cross-family | `θ = AISOC_CORRELATION_THETA` (default `3`) |
| Shared host | `0.35` + temporal ≤ `0.15` + family `0.15` | weight `2` + L2 story/chain `+1` or L3 graph `+1` |
| Shared user | `0.25` | weight `2` |
| Shared private IP | `0.28` same family, `0.20` with a host/user | weight `2` (needs L2/L3 to reach θ) |
| Shared public IP | same ladder | weight `3` |
| Shared hash / process GUID | not a key | weight `3` |
| Same detection family | booster `+0.15` | no direct equivalent; shared story / kill-chain drives L2 |
| Rule name / `search_name` | booster context only | identity-map + role/theme only, never an edge |
| Membership | pairwise against the seed, no transitive | connected components (transitive) |

### Non-goals (do not re-enable a legacy producer for these)

- Single-alert incident cases: `AISOC_CORRELATION_MIN_CASE_ALERTS` stays `2`
  unless a promotion rule is added **inside** this engine.
- Task checklists / SPL pivots: belong in the `/cases/from-correlation` payload
  if ever wanted, not in the retired writers.
- Risk-threshold "supporting only" handling: risk alerts currently take part as
  ordinary evidence (`general-intrusion` theme).

## Migration Tasks

### Task 1: Add rule identity registry schema

**Files:**
- Create migration `090_correlation_rule_identity_maps.sql`
- Create migration `091_correlation_rule_resolution_audits.sql`
- Modify `services/correlation/app/normalizer/extract_keys.py`
- Modify `services/correlation/app/services/engine.py`

**Interfaces:**
- Registry lookup by `tenant_id + rule_name + pattern`.
- Return canonical field paths and field-kind overrides.
- Resolution audit persists every miss/mapping for 30 days.

- [ ] Write failing tests for exact/global/fallback rule mapping.
- [ ] Add SQL migrations `090` and `091`.
- [ ] Implement Pydantic/model structs for mappings and audit rows.
- [ ] Run focused migration and normalizer tests.

### Task 2: Normalize Splunk payload identity before correlation

**Files:**
- Modify `services/connectors/app/connectors/splunk.py`
- Modify `services/correlation/app/normalizer/extract_keys.py`
- Modify `services/correlation/app/services/observations.py`
- Modify `services/correlation/tests/`

- [ ] Generate `identity` object in `llm_payload` from `alert_fields`.
- [ ] Separate `event_host`, `indexer_host`, `src_ips`, `dst_ips`, `users`, `domains`, `hashes`, `process_guids`.
- [ ] Reject public IP as victim host.
- [ ] Add field provenance to every key.
- [ ] Run corpus test over 664 payloads and assert no indexer host becomes an identity.

### Task 3: Rebuild rule registry seeding

**Files:**
- Create `services/api/app/services/correlation_rule_registry.py`
- Create `services/api/app/api/v1/endpoints/correlation_rules.py`
- Modify `services/api/app/api/v1/router.py`
- Create migration seed data for currently known strong-rule mappings.

- [ ] Seed exact mappings for the 4 corpus cases.
- [ ] Seed generic mappings for endpoint, identity, network, process, hash, and domain rules.
- [ ] Add tenant CRUD and audit endpoints.
- [ ] Run API tenant-isolation tests.

### Task 4: Disable legacy case producers

**Files:**
- `services/agents/app/workers/case_promoter.py`
- `services/agents/app/workers/fused_alert_consumer.py`
- `services/api/app/services/agentic_funnel.py`
- `services/api/app/services/campaign_correlation.py`
- `services/api/app/services/campaign_reconcile.py`
- `services/api/app/services/tier2_adaptive/case_policy.py`
- `services/api/app/services/tier2_ip_pivot.py`
- `services/fusion/app/services/correlator.py`
- `services/fusion/app/services/fusion_engine.py`

- [ ] Add one canonical env gate `AISOC_CORRELATION_CASE_WRITER_ONLY=1` default for production.
- [ ] Add a short English retirement header above each legacy writer explaining why it is disabled and which correlation service owns creation.
- [ ] Feature-gate legacy code rather than rewriting it; retain its code for rollback/reference.
- [ ] Make legacy writers emit deprecation metrics but no `aisoc_cases` insert/update.
- [ ] Remove legacy `correlation_owner='legacy'` claim logic.
- [ ] Route agent/Tier-2 recommendations through candidate discovery only.
- [ ] Run producer-grep gate: no automatic direct SQL insert remains outside correlation endpoint.

### Task 5: Make the correlation engine the sole writer

**Files:**
- `services/correlation/app/services/engine.py`
- `services/correlation/app/services/case_client.py`
- `services/api/app/api/v1/endpoints/cases.py`
- `services/api/app/api/v1/deps.py`

- [ ] Require `cases:write:correlation` API key scope for `/from-correlation`.
- [ ] Remove all direct `aisoc_cases` writes outside this API endpoint.
- [ ] Use canonical identity payload from registry to build case description/title/entity matches.
- [ ] Reconcile `alerts.case_id`, `aisoc_cases.alert_ids`, correlation state, and dedup losers in one transaction.
- [ ] Run 5 engine DB tests and 5 API from-correlation tests.

### Task 6: Remove or isolate fusion incident correlator

**Files:**
- `services/fusion/app/services/correlator.py`
- `services/fusion/app/services/fusion_engine.py`
- `services/fusion/app/services/incident_store.py`

- [ ] Disable legacy incident grouping by default.
- [ ] Keep it behind an explicit `AISOC_LEGACY_FUSION_CORRELATOR=1` opt-in.
- [ ] Ensure it never writes `aisoc_cases` or rewrites `correlation_owner`.
- [ ] Add tests asserting default off and canonical correlation path only.

### Task 7: Corpus and live validation

**Evidence:**
- `C:\Users\ali\Desktop\neo4j-test\llm_payload_only.json`
- `docs/plans/case/all-in-one-2/filter_presets.json`
- `docs/plans/case/all-in-one-2/llm_payload_only.json`

- [ ] Run 664 payload records through registry-aware normalizer.
- [ ] Assert public IPs never become hosts.
- [ ] Assert `host`/`splunk_server` never become victim identities.
- [ ] Assert private src/dest/IP extraction works without false host aliases.
- [ ] Run exact 4-case corpus presets and record measured components.
- [ ] Run the Neo4j live test with the new registry keys.

### Task 8: Migration validation and cutover

**Files:** all modified correlation/API/agent/fusion files.

- [ ] Apply migrations `090` and `091` plus existing `077`-`089` in a test database.
- [ ] Run API and correlation pytest suites.
- [ ] Run all Splunk connector tests.
- [ ] Run `pnpm type-check` for the web/API contracts.
- [ ] Start `-All -SkipCorrelation` and verify no legacy case writer fires.
- [ ] Start correlation engine and verify exactly one case writer path.
- [ ] Verify live `/cases/{id}/correlation` with real payload data.
- [ ] No commit/push until final review.

## Stop Conditions

- Any direct `INSERT INTO aisoc_cases` outside the correlation API endpoint.
- Any public IP emitted as a host entity.
- Any Splunk indexer/search-head value emitted as a victim host.
- Any rule match without an explicit or audited generic fallback.
- Any legacy and graph engine both creating cases for the same alert.
- Any migration test, tenant-isolation test, or 664-payload corpus test fails.

## Rollback

- Keep the correlation service behind `AISOC_CORRELATION_ENABLED=0` until validation passes.
- Preserve the legacy writers behind a rollback flag until the first live cycle proves one-writer behavior.
- Do not delete old migrations or existing case rows.
- This plan is the source of truth until cutover approval.

## Risks & Dependencies

- **Migration ordering:** `090` / `091` must run after `089`. Inside `090` the
  seed has to be inserted **before** RLS is enabled on the table (the pattern of
  `003_rbac.sql`); enabling RLS first makes the seed fail on its own policy.
- **RLS and the engine:** reads and audit writes under RLS need
  `app.current_tenant_id` set on the connection, which is why
  `tenant_connection()` exists. A missing GUC is a silent empty result, not an
  error, so any new query on a guarded table must go through it.
- **jsonb from asyncpg:** asyncpg returns `jsonb` columns as `str`. Any reader of
  the registry must decode before indexing; a raw `str` previously crashed
  `load_rule_identity_maps` on every cycle.
- **Resolver precedence:** exact tenant → exact global → tenant pattern → global
  pattern → generic fallback. Patterns must never shadow an exact match, and a
  miss must be audited instead of guessing a dangerous field.
- **Fail soft:** a registry/audit failure degrades to the generic fallback and
  must not block the correlation cycle.
- **Gates default off:** every legacy producer stays behind
  `AISOC_CORRELATION_CASE_WRITER_ONLY=1`, and the fusion correlator behind
  `AISOC_LEGACY_FUSION_CORRELATOR`. Enabling them restores two writers for one
  alert, which is exactly what this work removes.
- **`llm_payload` is immutable:** only field-selection metadata may be persisted;
  the registry never rewrites evidence.
- **Wide-blast files:** `CaseWorkspace.tsx`, `CasesView.tsx`, `api.ts` and
  `cases.py` carry both main and branch changes; theme/layout regressions and
  migration numbering are the known high-risk areas.
- **Residual:** the fusion metric labelled `new_incidents` still counts
  `NEW_ALERT` alerts; the label, not the counter, is misleading.
- **Residual:** `/correlation/rules` has no endpoint-level test for tenant
  isolation yet; isolation was proven only through the DB role test.

## Provenance: how this work reached `main`

The code arrived by porting the `case_review` branch onto `origin/main`
(`72db8102`), not by merging it. Recorded state of that port:

- The migration worktree and the `case_review` / `migration/case-review-to-main`
  branches were removed after the port; the working tree is `main` with these
  changes unsaved.
- `services/correlation/` was copied byte-identical (49 source files).
- Case-related SQL migrations were renumbered to `077`–`089`; the registry adds
  `090` and `091` after them.
- Focused results at port time: `CaseWorkspace.test.tsx` 7/7, 55 candidate/
  alert/TKG API tests, 38 correlation/dedup/KPI/TKG tests (11 skipped), 54 Splunk
  connector tests, focused Ruff clean.
- Not ported: diagnostic scratch scripts, generated scratch plans and
  `test_from_ubuntu.txt`.
- Known gaps at port time: live PostgreSQL replay and browser E2E for `/cases`
  were not executed, `apps/web` `/coverage-advisor` referenced a missing
  `CoverageAdvisorView` (pre-existing), `packages/ui` type-check failed on a
  Windows shell assumption, and eight operational scripts stayed out of the port.
- Nothing was committed; the whole port is still working-tree state.
