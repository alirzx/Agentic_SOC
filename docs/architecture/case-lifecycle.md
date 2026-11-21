# Case lifecycle

A **Case** is AiSOC's durable investigation container: a tenant-scoped record
that aggregates alerts, evidence, MITRE context, ownership, SLA state and
investigation tasks. It is not a single alert and it is not a ticket mirror — the
external ticket is best-effort fan-out, and the case survives without one.

Code of record:

| Concern | File |
| --- | --- |
| ORM model | [`services/api/app/models/case.py`](../../services/api/app/models/case.py) |
| API contract, state machine | [`services/api/app/api/v1/endpoints/cases.py`](../../services/api/app/api/v1/endpoints/cases.py) |
| Correlation write path | [`services/api/app/api/v1/endpoints/cases.py`](../../services/api/app/api/v1/endpoints/cases.py) → `from-correlation` |
| Legacy promotion | [`services/agents/app/workers/case_promoter.py`](../../services/agents/app/workers/case_promoter.py) |
| Campaign keys (legacy) | [`services/agents/app/workers/campaign_case.py`](../../services/agents/app/workers/campaign_case.py) |
| Funnel stages | [`services/agents/app/funnel/stages.py`](../../services/agents/app/funnel/stages.py), [`services/api/app/services/funnel_stages.py`](../../services/api/app/services/funnel_stages.py) |
| External fan-out | [`services/api/app/services/case_fanout.py`](../../services/api/app/services/case_fanout.py) |

Correlation itself (keys, scoring, observations, ownership lock) is in
[correlation-engine.md](correlation-engine.md).

## 1. The object

`aisoc_cases` is the table every case endpoint writes and reads. Fields that
matter operationally:

- `tenant_id` — the isolation boundary on every query.
- `title`, `description` — narrative plus, for engine cases, the campaign
  summary the engine wrote at open time (the header renders a sentence and
  chips, not the observation dump).
- `severity`, `status`, `priority`, `case_type`.
- `alert_ids` (UUID[]) — the denormalised member list the console renders.
- `mitre_tactics`, `mitre_techniques`, `rules` (a rule name → alert count
  roll-up, `JSONB DEFAULT '{}'`).
- `tags` — `campaign_key`, `campaign_theme`, `case_model`, `source`,
  `observation_count`.
- `creation_method` — `graph_correlation` | `agentic_funnel` | `manual` |
  `system` (migration 075, `NOT NULL`, CHECK-constrained, indexed on
  `(tenant_id, creation_method)`).
- `assigned_to_id`, `sla_deadline`, `sla_breached`, `ticket_refs`, `summary`,
  `resolution`, `lessons_learned`, timestamps.

The legacy `cases` table still exists and maps the ORM `Case`. Anything that
resolves a case id must read `aisoc_cases`; an endpoint left on the legacy model
returns 404 for every real case.

`alerts.case_id` is the ownership truth, and it is **UUID** everywhere —
`investigation_runs.case_id` and `agent_approvals.case_id` were `varchar(200)`
and were converted in migration 074, because joins against `aisoc_cases`
silently returned nothing.

## 2. Ingress: how an external event becomes an alert

The boundary is intentionally schema-flexible — it is not an LLM-extraction
step.

| Path | Contract |
| --- | --- |
| Connector → `POST /v1/ingest/batch` | `connector_id`, `connector_type`, `source_format` (default `raw_json`), `events[]` of arbitrary JSON maps, `X-Tenant-ID` header |
| Ingest handler (Go) | Normalises generic JSON maps downstream; no OCSF-only requirement at the HTTP boundary |
| Agent APIs (`AlertInvestigateRequest`, `TriageRequest`) | `alertId`/`alert_id` required; `raw_alert` is a structured dict; `alert_summary` is optional and may be synthesised from `title`/`description` |
| Kafka `aisoc.alerts.fused` | `build_state(message)` reads `message["alert"]` plus tenant/incident/narrative/confidence into `InvestigationState` |

Free-text extraction exists (`extract_entities` in
`services/agents/app/context/bundle.py` is regex over IPs/domains/hashes) but it
is a fallback for summary-shaped input, not the canonical path.

Before any case exists, Fusion applies `dedup_hash` — a content fingerprint that
suppresses the same alert content at the sink. Dedup and correlation are
separate concerns and must stay separate.

## 3. Which alerts become a case

Two creators, both in service:

### Legacy agentic funnel

`should_promote()` gates on the triage disposition:

| Disposition | Severity / confidence | Case |
| --- | --- | --- |
| `true_positive`, `likely_tp`, `escalate` | — | yes |
| `needs_review` | high / critical | yes |
| `needs_review` | medium and confidence ≥ 0.70 | yes |
| `false_positive`, `benign`, `benign_true_positive` | — | no (suppressed) |

It then groups siblings by entity overlap in a recent window — host
(`hostname`, `affected_hosts`, `raw_event->>'hostname'`), IP (`src_ip`,
`dst_ip`, `affected_ips`), user (`username`, `affected_users`) — infers a theme
from MITRE tactics/techniques, and persists the result as
`campaign_key = "<theme>|<kind>:<value>"` with priority `host > ip > user`. An
open case with the same `campaign_key` inside the lookback is reused.

The sablier is deliberately narrow: no embeddings, no fuzzy similarity, no
`process_guid`. MITRE labels the campaign; host/IP/user decide membership.

`AISOC_AGENT_AUTO_CASE` must be **off** (`0`) on any deployment where the graph
engine is the case creator. The two are alternatives, not companions: the
promoter decides from one alert's verdict and claims that alert before the
engine can correlate it, so a campaign the engine should have built loses its
seeds.

### Graph correlation engine

Component-based, gated on `θ` and on `AISOC_CORRELATION_MIN_CASE_ALERTS`
(default 2 distinct canonical alerts). See
[correlation-engine.md §7](correlation-engine.md#7-owned-alerts-and-case-creation).

## 4. Evidence membership

A case stores its members twice — `alerts.case_id` (ownership) and
`aisoc_cases.alert_ids` (what the console lists) — so the two must be kept
identical. Two writers once let them drift: `from-correlation` appended every
eligible alert and only then claimed, so alerts owned by another case stayed in
the array; `POST /cases/{id}/alerts` did the mirror image and never set
`case_id`.

The rules now:

- An alert belongs to exactly one case. `partition_claimable_alerts()` splits
  eligible ids into claimable (unowned, or already this case) and
  `cased_elsewhere`; after the claim `UPDATE`, the endpoint compares
  `RETURNING id` with what it tried to claim and trims the array if a concurrent
  writer won.
- `POST /cases/{id}/alerts` claims first and appends only what it claimed
  (`422 no_linkable_alerts` otherwise).
- Migration 081 reconciles existing rows once, in the only order that cannot
  lose a link: claim what a case lists → drop entries owned elsewhere → append
  alerts owned by the case but missing from its array. Idempotent.

**Soft-dedup losers stay evidence.** Exact dedupe sets
`funnel_stage='deduplicated'` and tags the row `deduplicated_into:<winner>`; it
clears `case_id` only for alerts that had no case. A cased member keeps its
`case_id`, so the correlation graph and the TKG second opinion can score the
repetition while the case lists the canonical alert once. The evidence set the
read paths assemble is `alert_ids` ∪ `alerts.case_id` ∪ losers whose winner is a
member.

## 5. State machine

The route layer is authoritative; the model only stores.

```python
CaseStatus = Literal["new", "triaged", "investigating", "contained",
                     "resolved", "closed"]
_TRANSITIONS = {
    "new": {"triaged"},
    "triaged": {"investigating"},
    "investigating": {"contained", "resolved"},
    "contained": {"resolved"},
    "resolved": {"closed"},
    "closed": set(),
}
```

Forward-only, enforced by validation rather than convention. The ORM default is
`"open"`, which is storage, not a state the API accepts.

Ticket readiness is a separate, stricter bar (`passes_ready_for_jira_stage`):
`high`/`critical` severity, or substantive findings text, or `medium` with
confidence ≥ 0.70 plus MITRE metadata.

## 6. Manual creation and fan-out

`POST /api/v1/cases` accepts `title` (required), `description`, `severity`
(default `medium`), `assignee`, `alert_ids`, `mitre_techniques`,
`compliance_frameworks`, `tags`, `sla_due_at`, `push_to_connector_ids`, writes
an `aisoc_cases` row for the caller's tenant, and returns `creation_method =
"manual"`. This is the path for analyst-initiated work and for importing a set
of alerts that no engine grouped.

`case_fanout.py` is the downstream integration, not the creator: `POST
/api/v1/cases` fan-out on creation, status propagation on existing links, and
`case_external_refs` persistence. Connectors are deliberately narrow (`jira`,
`servicenow`) and the write is best-effort — a failed ticket never rolls back the
case.

## 7. Closure

`status='closed'` with `resolution`, `lessons_learned` and `closed_at`. The
record stays anchored to its alerts, comments, tasks and summary, so closure is a
workflow transition rather than a label flip.

## 8. Gaps worth knowing

1. **No pre-correlated import.** There is no route that accepts an externally
   computed correlation result and creates a case without the internal pipeline.
   The nearest surfaces are `POST /cases` (manual), `POST /cases/{id}/alerts`
   (link after the fact) and `POST /cases/{id}/observables` (attach graph
   evidence). Anything produced elsewhere must still pass through a creator.
2. **Legacy cases are not re-evaluated.** Alerts owned by an `agentic_funnel`
   case are out of scope for the graph engine, and no merge pass exists.
3. **Two case tables.** The legacy `cases` table remains; new code must read
   `aisoc_cases`.
