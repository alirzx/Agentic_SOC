# Correlation engine

The graph correlation engine (`services/correlation`) turns a stream of
individual alerts into campaign cases. It is the second case-creation path: the
legacy agentic-funnel promoter still exists and both run in parallel, with an
atomic owner column deciding which one gets an alert.

This file is the reference for the engine. The case object itself (lifecycle,
state machine, promotion gates) is in
[case-lifecycle.md](case-lifecycle.md); the analyst-facing surface is described
in [the console docs](../../apps/docs/docs/concepts/cases.md).

| Concern | File |
| --- | --- |
| Key extraction (pure, no I/O) | [`services/correlation/app/normalizer/extract_keys.py`](../../services/correlation/app/normalizer/extract_keys.py) |
| Action signatures and roles | [`observations.py`](../../services/correlation/app/services/observations.py), [`normalizer/roles.py`](../../services/correlation/app/normalizer/roles.py) |
| Scoring, components | [`scoring.py`](../../services/correlation/app/services/scoring.py) |
| Claim, cycle, case creation | [`engine.py`](../../services/correlation/app/services/engine.py) |
| Frequency baselines | [`frequency.py`](../../services/correlation/app/services/frequency.py) |
| Cycle diagnostics | [`diagnostics.py`](../../services/correlation/app/services/diagnostics.py) |
| Read-side projection | [`services/api/app/services/candidate_discovery.py`](../../services/api/app/services/candidate_discovery.py) |

## 1. Why a second engine

The legacy promoter decides from **one alert's** triage verdict and links
siblings by host/IP/user inside a 48-hour window. That is a reasonable triage
shortcut and a poor campaign detector: the alert that trips it is not
necessarily the one that describes the intrusion, and soft-dedup losers either
flood the case or get dropped.

The graph engine asks a different question from a different input:

- **Dedup** answers *"is this the same alert content?"* (`dedup_hash` in Fusion).
- **Correlation** answers *"are these different alerts the same attacker
  action, and is this action one campaign?"*

So the engine ignores `dedup_hash` entirely. It reads `alerts.llm_payload` — the
immutable payload the connector wrote — extracts entities and the shape of each
action, and groups actions by the topology of what they touched.

## 2. Pipeline

```
alerts.llm_payload
  │  extract_keys()          pure: value-shaped typing, provenance, weights, time_quality
  ▼
weighted keys                host · user · ip · domain · hash · process_guid
  │  observation_signature() graph-based dedup (not dedup_hash)
  ▼
(:Observation)               LSASS pair · SMB user+minute+target · file hash · entity set
  │  L1 + L2 + L3 ≥ θ=3      pairwise scoring
  ▼
connected component          union-find over passing pairs
  │  canonicalise           soft-dedup losers → their winner
  ▼
POST /api/v1/cases/from-correlation
```

Postgres is the source of record: the engine claims rows from `alerts`,
resolves each to its `llm_payload`, and keeps a durable
`correlation_observations` ledger. Kafka (`AISOC_CORRELATION_KAFKA_ENABLED`) is
only a wake-up hint, so the engine runs without a broker and every test is
deterministic. Neo4j holds the queryable `(:Observation)` layer; a graph outage
degrades to Postgres and is logged — it is never reported as "correlated in the
graph".

## 3. What is read from the payload

`extract_keys()` consumes `llm_payload` only, never the denormalised
`alerts.hostname` / `src_ip` columns — those are connector projections, and for
a Splunk notable the `host` column is index metadata.

| Payload path | Used as |
| --- | --- |
| `event_time`, `alert_time`, `event_time_source` | time quality (`first_event` vs `alert_time_fallback`) |
| `rule_name`, `severity` | observation metadata; role assignment runs on the rule name |
| `annotations.mitre_attack` / `.analytic_story` / `.kill_chain_phases` | L2 only — techniques never become entity keys |
| `entity` + `entity_type`, `risk_object` + `risk_object_type` | typed entity |
| `alert_fields.*` | entity keys — every string field is walked; the value shape decides, the field name is a tie-breaker |
| `alert_fields.dest` / `dvc` / `dest_nt_host` / `Computer` / `hostname` | event host (highest-priority victim identity) |
| `alert_fields.SourceProcessGUID` / `TargetProcessGUID` | `process_guid`, scoped to the host |
| `alert_fields.process_hash` / `sha256` / `md5` | `hash` |
| `alert_fields.RelativeTargetName` / `ShareName` | SMB signature input, not a key |
| `rule.title` / `description` / `spl` / `macro_definitions` | skipped free text |

**The `host` trap.** For Splunk-shaped payloads (`_is_splunk_payload`: at least
four of `alert_time`, `date_context`, `time_window`, `annotations`,
`alert_fields`, `rule_name`) the bare `host` field and
`_meta.indexer_host` are dropped, and so is any `entity` / `risk_object` equal
to them. Indexer identity is identical on every alert; treating it as the victim
merges unrelated incidents.

`time_quality` gates context: with `alert_time_fallback` the alert cannot seed a
new candidate and earns no L2/L3.

## 4. Node vocabulary

The vocabulary is **closed and value-shaped**, not field-shaped. A Splunk rule
may emit any fields it likes; those fields never become node kinds, their values
are classified into six buckets, and anything that is not one of those shapes is
deliberately not a node.

| Node kind | Source shape | Edge to the observation | Weight |
| --- | --- | --- | --- |
| `observation` | one deduplicated attacker action | — | — |
| `host` | event host | `OBSERVED_ON` | 2 (1 for a hub) |
| `user` | account, SID | `INVOLVES_USER` | 2 (1 for SYSTEM SIDs, machine and ambient accounts) |
| `ip` | IPv4/IPv6, `::ffff:` folded | `USES_IP` | 3 public / 2 private / 0 CDN or tunnel |
| `domain` | FQDN, URL host | `QUERIED_DOMAIN` | 3 threat-intel / 2 unknown / 1 well-known or ambient / 0 tunnel prefixes |
| `hash` | MD5/SHA1/SHA256 | `MATCHES_HASH` | 3 rare / 2 common |
| `process_guid` | Sysmon `ProcessGuid` and friends | `INVOKES_PROCESS` | 3, always |
| `key` (fallback) | a kind this build does not know | `CONTRIBUTES_KEY` | as scored |

Classification runs **shape before field name**: skip fields → GUID → SID → IP
→ bare hex hash → URL/FQDN → path (no key) → field hint. Values are normalised
first (lowercase, GUID braces stripped, `::ffff:` stripped, trailing DNS dot
removed); an FQDN host also emits its short name as an alias capped at weight 2,
so the short form can never outweigh the full one.

Nothing else can be a node: paths and executables, share/file artifacts, free
text and bulk columns (`_raw`, `spl`, `commandLine`, `title`, …), numbers,
placeholders, loopback and unroutable addresses, system SIDs, CDN ranges,
`isatap.` / `teredo.` tunnels, and the documented `SYSTEM_PROCESSES` list.
Mining those is how a keyword collision becomes a phantom entity.

`process_guid` is **host-scoped** (`process_guid:<host>|<guid>`): a Sysmon GUID
is unique only inside one machine, and the lab corpus reuses one GUID across
every domain controller. Unscoped, it merged five unrelated DCs into one case.

### Adding a kind

A new kind must be added everywhere or the console and the engine disagree:

1. `extract_keys.py` — `KINDS`, `_classify`, `_weight`, and its hint set.
2. `observations.py` — is it a signature input or a scoring key?
3. `candidate_discovery._build_graph` — the token → (node kind, edge kind) entry.
4. `CandidateGraphView.KIND_META` — label, colour, canvas shape, size, hint
   (the legend chip and the canvas both read this table).
5. Docs and tests (`tests/test_extract_keys.py`; frontend tests if the legend
   moves).

Stored tokens keep their old kind, so a rollout affects only newly extracted
keys. Back-filling is a re-normalisation of `llm_payload`, not a migration.

## 5. Graph-based deduplication

`observation_signature()` groups alerts into one `(:Observation)` by the
topology of the action, not by a content hash:

| Action | Signature |
| --- | --- |
| LSASS access | `lsass \| host \| SourceProcessGUID \| TargetProcessGUID \| technique` |
| SMB admin write | `smb \| host \| src_user \| event-minute \| RelativeTargetName \| ShareName` |
| 3CX / signed app | `file \| host \| process_hash` |
| anything else | `entity \| technique \| sha1(strong non-GUID keys)` |
| no entities | `alert \| <alert_id>` (never merges) |

Signatures are bounded to 512 characters (`bounded_key()`): a Splunk
`process_hash` can carry a multi-line blob of every hash of a file, and an
unbounded key made the whole case bundle fail validation with
`payload_too_large`. Over-long keys keep a readable prefix plus a stable
`|#<sha256 prefix>`, so two alerts still share an observation exactly when they
did before.

Roles (`normalizer/roles.py`) label an observation (`credential_access:*`,
`lateral_movement:*`, `general:intrusion`, …) and provide one hard veto: two
distinct C2 frameworks never merge, whatever the score.

## 6. Scoring

```
score = min(Σ weight(shared keys), 18)        L1
      + 1 if a story / kill-chain / technique test passes, and L1 ≥ 2   L2
      + 1 if a real 3-hop path exists, and L1 ≥ 2                       L3
pair is linked when score ≥ θ = 3
```

- **L3 is a real 3-hop path** (`A–K1–C–K2–B` through a *third* observation, two
  distinct keys). Firing on any shared key would be a constant `+1` for every
  pair with L1 ≥ 2, i.e. θ = 2 — the value measured as almost always a false
  positive.
- **L2 uses analytic story, phase progression and technique difference**, never
  wall-clock proximity, and only when both sides carry rule event times.

**Ambient values are not evidence on their own.** A key is ambient when it is
weak *and* its kind is a name-space kind (`host`, `user`, `domain`); IPs, hashes
and host-scoped GUIDs are never ambient. Ambient detection is absolute
(`H_HUB=500`, `T_USER_COMMON=50`, `T_COMMON_DOMAIN=100` per 30 days) **and**
relative — a `domain` on ≥ 25 % of the window's alerts (from 8 alerts up) is
tenant-wide even when it sits far below the absolute bar. Hosts keep only the
absolute bar: the victim of a single-host campaign legitimately appears on every
alert.

Ambient keys are suppressed from L1 (kept on the pair at weight 0, so the
inspector still explains the link), and a pair whose shared keys are **all**
ambient is vetoed (`ambient_keys_only`). Without that rule three weak ambient
values sum to exactly θ = 3, and a tenant-wide AD domain plus two hub hosts
correlated unrelated activity with itself. Measured on the 166-notable corpus:
injecting the tenant's domain into every payload leaves the run identical while
vetoing the 1 487 pairs that share only it
(`test_a_tenant_wide_domain_changes_nothing`).

Every cycle can be explained: `GET /v1/diagnostics/{tenant_id}` returns the
ambient keys with their frequency, share and the rule that flagged them, plus
the vetoed pairs with both roles. It describes the tenant's **last cycle in the
process** (404 until one runs) and is not persisted history.

## 7. Owned alerts and case creation

The engine claims an alert atomically (`correlation_owner` = its
`AISOC_CORRELATION_OWNER`, default `graph_engine`) with `FOR UPDATE SKIP LOCKED`,
so one alert can never land in two cases. Rows claimed by the retired promoter
still carry `legacy`; both values are honoured when ownership is checked.

Stale claims are retried after `AISOC_CORRELATION_CLAIM_TTL_MINUTES`;
`correlation_state='error'` is retried on the next cycle.

`_claim` never resurrects consumed work: `funnel_stage='deduplicated'` and the
terminal `cased` / `deduplicated_into_case` states are skipped, so a
shelled-out claim cannot re-offer an already-cased campaign as a new candidate.

`POST /api/v1/cases/from-correlation` is the write path. It is tenant-scoped and
guarded by a dedicated API-key scope, `cases:write:correlation`.

| Guarantee | Behaviour |
| --- | --- |
| Unknown / foreign alert id | `422 unknown_or_foreign_alert_ids` |
| Only soft-dedup losers | `422 no_eligible_alerts` |
| Alert already owned elsewhere | dropped from membership, counted in `alerts_ignored`; `422 alerts_already_cased` when nothing is claimable |
| New case with fewer than 2 claimable alerts | `422 single_alert_campaign` (extending an existing case by one alert is allowed) |
| Same open campaign key | `201` with `created: false`, same case id, alert linked |
| New campaign | `201` with `created: true`, `aisoc_cases` row + UUID `alerts.case_id` |

**Deduplicated alerts are evidence, not members.** The engine groups on them
(they are how a repeated action is detected) but canonicalises each loser to its
`deduplicated_into:<id>` winner before submitting. That is what stops a case
from listing seventy identical notables while still scoring the repetition.

A soft-dedup winner can represent losers in several components. Components are
processed strongest-first and a winner is assigned to the first component that
needs it, so the same two alerts cannot be written into two cases.

Every case records which writer produced it (`aisoc_cases.creation_method`,
migration 075): `correlation-engine` for this engine, `manual` for cases an
analyst opens through `POST /api/v1/cases`, and `agentic_funnel` on the cases
left behind by the retired backfill.

### Case kinds this engine produces

Automatic case creation has a single owner, so the retired producers stay
switched off rather than running in parallel: an alert claimed by two engines is
an alert in two cases. What this engine reproduces, and what it deliberately
does not, is fixed:

| Case kind | Legacy producer | Produced now? |
| --- | --- | --- |
| Multi-alert campaign from shared entities (host / user / IP / domain / hash / process GUID) | agentic funnel | **Yes** — this engine, `creation_method='correlation-engine'` |
| Single-alert "incident" case | agentic funnel (`case_kind='incident'`) | **No** — `AISOC_CORRELATION_MIN_CASE_ALERTS=2` |
| Investigation checklist / Splunk SPL pivot tasks (`aisoc_case_tasks`) | agentic funnel, agent case promoter | **No** — one system timeline comment only |
| Escalated-true-positive case from triage | agent case promoter | **No** |
| Tier-2 "IP pivot" campaign + runbook `case_created` | `tier2_ip_pivot` | **Partially** — an IP is a weighted key, but there is no pivot-specific runbook step |
| Tier-2 adaptive `create` / `extend` | `tier2_adaptive.case_policy` | **Partially** — creation here, extension through `tags->>'campaign_key'` |
| Campaign repair, duplicate case merge, fusion incidents | `campaign_reconcile`, `exact_dedupe`, fusion correlator | n/a — none of them created a case through this engine |

The 0.55 / 0.70 legacy thresholds versus θ and the key weights, plus the
per-producer retirement notes, live in
[`services/correlation/README.md`](../../services/correlation/README.md#case-kinds-produced-vs-deliberately-retired).

### Coverage repair

The case view rebuilds observations from the ledger, and `_load_context` skips
cased alerts — so a ledger row rewritten under a different key could leave a
cased alert with a `case_id` and no observation, and the case graph silently
lost evidence. `_repair_case_coverage()` re-observes cased alerts that no row
lists, restoring "every alert with a payload belongs to one observation".

## 8. Read-side projection

Candidates and graph-engine cases are the same object at different workflow
stages, so they are explained by one component fed by two endpoints that return
identical payloads:

| Surface | Endpoint |
| --- | --- |
| Candidate | `GET /cases/candidates/{candidate_key}` |
| Case | `GET /cases/{case_id}/correlation` |
| Saved scope | `PUT /cases/{case_id}/correlation/scope` (`case_alert_scopes`) |

`CandidateDiscovery.describe_alert_set()` and `_assemble_component` are shared
with discovery, so the two surfaces cannot drift.

The candidate list re-implements the engine's arithmetic, not an approximation:
L1 sums the per-key weights the engine persisted (`token_weights`, migration
080), capped at 18; L2 applies the same three ordered tests and is gated on
L1 ≥ 2; L3 reads the persisted tokens (migration 079) and needs a distinct-key
3-hop path; `roles_conflict()` drops vetoed pairs. The old version scored
3/3/2/1 per entity *kind* and used temporal proximity for L2, so `min_score` —
and therefore the number θ is compared with — had never gated anything. Parity is
pinned by `test_candidate_scoring_parity.py`.

The case header and the graph measure different things on purpose: the header is
the engine's campaign description frozen at open time, `Member alerts` is
`aisoc_cases.alert_ids`, the `Alerts (N)` tab is the whole evidence set
(members plus dedup witnesses), and `Peak link` is the strongest single pair
score.

### Projections

The API can draw an observation two ways (`?observations=edge|node`, default
from `AISOC_CORRELATION_GRAPH_EDGES`):

- **Actions as nodes** — a hexagon per observation with entity leaves.
- **Actions as edges** — a role-labelled edge between the entities the action
  related. Two endpoints → one edge, three or four → every pair, more than four
  → a spanning tree over the strongest endpoints; duplicate pairs collapse into
  `×N`. Scored pair links are re-anchored, never re-scored.

The evidence set is `aisoc_cases.alert_ids` ∪ `alerts.case_id` ∪ dedup losers
whose `deduplicated_into:<winner>` tag points at a member. Without the third
source a campaign the engine collapsed from 114 advisory alerts to 9 members
could not explain its own header.

### Alert scope

Three levels, with different cost: **hide** (client-side), **exclude** (the
component is rebuilt server-side from the surviving alerts; on a case the
exclusion is saved, and the alert stays case evidence), and **filter**
(`field|op|value|include|exclude` evaluated against `llm_payload` only —
`include` filters AND, `exclude` filters OR). Denormalised `affected_*` columns
are deliberately not addressable: the engine reads the payload, so filtering on
those columns would disagree with the graph on screen. Every exclusion is echoed
with its reason, which gives the analyst a restore path.

The `dedup hidden` switch is a **view**, not a scope: it drops all-witness
observations from the canvas and folds the witnesses into an accordion in the
Alerts tab, without excluding an alert or recomputing a score.

## 9. Operations

| Variable | Default | Meaning |
| --- | --- | --- |
| `AISOC_CORRELATION_OWNER` | `graph_engine` | Value written to `alerts.correlation_owner` |
| `AISOC_CORRELATION_THETA` | `3` | Minimum pair score to link |
| `AISOC_CORRELATION_LOOKBACK_HOURS` | `72` | Context window |
| `AISOC_CORRELATION_MIN_CASE_ALERTS` | `2` | Distinct canonical alerts a new case needs |
| `AISOC_CORRELATION_POLL_SECONDS` | `60` | Worker cadence |
| `AISOC_CORRELATION_CLAIM_TTL_MINUTES` | `60` | Stale-claim recovery |
| `AISOC_CORRELATION_WORKER_ENABLED` | `true` | Run the loop |
| `AISOC_CORRELATION_KAFKA_ENABLED` | `false` | Kafka as a wake-up hint only |
| `AISOC_GRAPH_ENABLED` | `true` | Project observations into Neo4j |

Routes: `GET /healthz`, `GET /readyz`, `GET /metrics`,
`POST /v1/run` (all tenants), `POST /v1/run/{tenant_id}` (backfill),
`GET /v1/diagnostics/{tenant_id}`. `POST /v1/*` is guarded by
`AISOC_INTERNAL_TOKEN`; in production an unset token answers 503 rather than
opening the endpoint.

Rolling the engine's decisions back to re-run from scratch:

```sql
UPDATE alerts
   SET correlation_owner = NULL, correlation_claimed_at = NULL,
       correlation_state = NULL, case_id = NULL
 WHERE case_id IN (SELECT id FROM aisoc_cases
                    WHERE creation_method = 'graph_correlation');
```

Keying on `creation_method` rather than free-text `created_by` keeps the
rollback independent of conventions and never touches the other engine's cases.

## 10. Verification and limitations

Pinned by `services/correlation/tests/test_corpus.py` on the real 166-notable
lab corpus (payload only):

```
alerts 166 → observations 58 → components 8
largest: score 18 · 60 alerts · three hosts · credential access + NTDS + SMB + 3CX
isolated MSI privesc excluded ✓   three distinct C2 frameworks never merged ✓
```

`test_engine_db.py` covers the two SQL behaviours whose failures only appeared
in production (ledger upsert unions `alert_ids`; `_link_case` rebuilds
`aisoc_cases.alert_ids` from ownership in the same transaction), by cloning the
deployed tables into a throwaway schema.

Known limitations, recorded so they are not mistaken for bugs:

1. **Frequency thresholds are uncalibrated.** With 166 alerts no value crossed
   `H_HUB` / `T_USER_COMMON` / `T_COMMON_DOMAIN`, so only the static lists
   applied. They need a production-sized tenant to mean anything.
2. **The window is a fixed lookback.** A campaign spanning weeks is only grouped
   when its alerts fall inside one window; incremental "attach to an old
   campaign" works only through `campaign_key` reuse at the API.
3. **Per-host LSASS clusters stay separate.** Host-scoped GUIDs fix the false
   merge but mean each DC forms its own component; cross-host merging happens
   only through a shared host/user/IP.
4. **Legacy cases are never re-evaluated.** An alert already linked to a legacy
   case is out of scope. A merge pass is future work.
5. **The Go ingest graph is unchanged.** The engine merges the `(:Alert)` nodes
   it needs; the ingest-side projection remains the canonical attack graph.
6. **Lab corpus caveat.** `attack_data` has fixed patterns
   (`AtomicRedTeam` paths, `attackrange.local` hosts); generalising needs
   customer data from that customer.
