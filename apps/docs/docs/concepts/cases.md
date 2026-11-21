---
sidebar_position: 1
---

# Cases

A **Case** is the central unit of work in AiSOC. Every security incident, alert,
or investigation is tracked as a Case.

## Case States

`open` → `investigating` → `resolved` | `closed`

## Case Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique identifier |
| `title` | string | Short description |
| `severity` | enum | `critical`, `high`, `medium`, `low` |
| `status` | enum | `open`, `investigating`, `resolved`, `closed` |
| `mitre_tactics` | string[] | Associated ATT&CK tactics |
| `indicators` | Indicator[] | IOCs linked to the case |
| `playbook_runs` | PlaybookRun[] | Automation runs |
| `ledger_entries` | LedgerEntry[] | Replayable agent decisions (see below) |

## AI Investigation

Click **Investigate with AI** to launch the multi-agent investigation pipeline:

1. **OrchestratorAgent** — plans the investigation graph and routes work
2. **ReconAgent** — collects case context, threat intel, environmental fit
3. **ForensicAgent** — deep-dives indicators, timeline, attack-graph paths
4. **ResponderAgent** — proposes (dry-run by default) containment steps
5. **ReportWriterAgent** — generates the PDF / Markdown executive report

The full graph lives under
[`services/agents/app/investigator/`](https://github.com/SoorinSecurity/Agentic_SOC/tree/main/services/agents/app/investigator).

## Investigation Ledger

The **Investigation Ledger** is the structural moat that separates AiSOC from
closed-source AI SOC vendors: every prompt sent to an LLM, every response
received, every tool invocation, every evidence citation, and every decision
branch is appended to a tenant-scoped, append-only ledger and rendered as a
scrubbable timeline on the case workspace.

### What gets logged

For every agent step, the ledger captures:

- `agent_id` — which agent emitted the step (`orchestrator`, `recon`, …)
- `step_kind` — `prompt`, `response`, `tool_call`, `tool_result`,
  `decision`, `evidence_citation`, `plan_update`
- `model` — the model name and provider used for the step
- `prompt_hash` — SHA-256 of the prompt (so you can prove what was asked
  without storing every byte twice)
- `payload` — the structured content of the step (redacted per tenant
  config)
- `started_at` / `completed_at` / `latency_ms`
- `tool_name` and `tool_input_hash` for tool calls
- `evidence_uris` — links into PostgreSQL / OpenSearch / Neo4j / Qdrant
  for every cited piece of evidence

### Why it matters

- **Auditability** — every claim the agent makes on a case is backed by
  a logged tool call and evidence citation, scoped to a tenant.
- **Replayability** — analysts can scrub the timeline and replay the
  exact sequence the agent followed, including failed tool calls.
- **Compliance** — feeds the SOC 2 / ISO 27001 / NIST CSF dashboards
  with concrete, human-readable evidence of automated decisions.
- **Debugging** — when an investigation goes wrong, the ledger is the
  first place to look; you can see the exact prompt, response, and
  tool input that produced the bad output.

### Where it lives

- Schema:
  [`services/api/migrations/008_investigation_ledger.sql`](https://github.com/SoorinSecurity/Agentic_SOC/blob/main/services/api/migrations/008_investigation_ledger.sql)
- Model:
  [`services/api/app/models/investigation.py`](https://github.com/SoorinSecurity/Agentic_SOC/blob/main/services/api/app/models/investigation.py)
- API endpoints:
  [`services/api/app/api/v1/endpoints/investigations.py`](https://github.com/SoorinSecurity/Agentic_SOC/blob/main/services/api/app/api/v1/endpoints/investigations.py)
- Agent-side writer:
  [`services/agents/app/investigator/ledger.py`](https://github.com/SoorinSecurity/Agentic_SOC/blob/main/services/agents/app/investigator/ledger.py)
- UI:
  [`apps/web/src/components/cases/InvestigationLedger.tsx`](https://github.com/SoorinSecurity/Agentic_SOC/blob/main/apps/web/src/components/cases/InvestigationLedger.tsx)

### REST surface

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/cases/{case_id}/investigations` | List ledger entries for a case |
| `GET` | `/api/v1/investigations/{id}` | Get a single ledger entry with full payload |
| `POST` | `/api/v1/cases/{case_id}/investigations:replay` | Replay an investigation deterministically |

The ledger is also surfaced through the [MCP server](../integrations/mcp), so
analysts can replay agent decisions directly from Claude / Cursor / Continue
/ Cody.

## Reading the correlation graph

An **observation** is the engine's record that a set of alerts, on a set of
entities, is one atomic attacker action. It is a relation, and the graph can draw
it either way:

| Projection | What you see |
|---|---|
| **Actions as nodes** | a hexagon per observation, with its hosts/users/IPs/domains as leaves |
| **Actions as edges** | no hexagon: a role-labelled edge between the entities the action related, coloured by ATT&CK role (`credential_access:*` red, `general:intrusion` slate, …) |

The toggle is a server-side projection, not a client-side illusion: the same
choice is available as `?observations=edge|node` on
`GET /api/v1/cases/{id}/correlation` and `GET /api/v1/cases/candidates/{key}`,
and `AISOC_CORRELATION_GRAPH_EDGES=1` flips the default everywhere.

The rules hold whatever the projection:

- Two endpoints → one edge, three or four → every pair, **more than four** → a
  spanning tree over the strongest endpoints (a 20-endpoint action cannot emit
  190 edges; the inspector says `tree projection · N endpoints`).
- Repeated observations on the same entity pair collapse into one edge labelled
  `×N`, which lists every observation and role behind it.
- An observation with fewer than two endpoints keeps its node.
- Switching projection never re-scores: a scored `CORRELATION` pair is
  re-anchored on the strongest entity of each side, with its L1/L2/L3 intact.

The toolbar is a set of type switches rather than a legend — each chip carries
its node count and hides that kind — and observations are always drawn, so
hiding every entity still leaves the campaign. `NBR` caps how many links each
node draws (the strongest win the seats; the rest expand on click), big graphs
are separated into labelled clusters whose pills collapse and expand in place,
and `3D` opens the same partition as a WebGL orbit view for demos and very large
campaigns. `Settings → Auto Details` is off by default: a click only selects,
and the row's `D` action opens details explicitly.

### The scope row

The `Scope` row only exists when there is a scope — an excluded alert or rule, a
`llm_payload` filter, or an open `Field filter` builder. With a clean scope it is
not rendered at all (the tab counts already say `1012 alerts`). `Clear scope`
sits on the count line rather than a row of its own, and excluded chips are
capped at five plus `+N more`.

### What the counts mean

The case header and the correlation graph measure different things on purpose:

| Number | Scope |
|---|---|
| Header line (`9 alerts`, `9 rules`) | counted live on every read: `alerts.case_id` = this case, and the distinct rules those rows carry. The same query backs the list card, so the two always agree |
| Engine snapshot numbers (`73 observations`, `114 alerts`, score, phases) | not shown at all. They were frozen when the case opened and no longer describe the evidence, so the header carries live counts only |
| `Rules (N)` under **Engine details** | measured live from the case record. The engine's own `Rules (17 distinct)` roll-up is not shown: it counted rule occurrences per observation over the pre-dedup alert set, so it disagreed with the rules the alerts actually carry |
| `MITRE ATT&CK` chips | rebuilt from the alerts themselves on every read — canonical members plus the soft-dedup witnesses whose winner is a member. The engine writes its own list at case creation and alerts are re-assigned and re-normalised afterwards, so that snapshot named techniques (`T1027`, `T1490`, `T1218.011`, `T1204.002`, `T1021.001` on case `15b4790b…`) that no alert of the case carries |
| `Member alerts` in the graph rail | `aisoc_cases.alert_ids` — the **canonical** winners the engine linked |
| `+N dedup evidence` under it | soft-dedup **losers** whose winner is a member: scored evidence, not separate members |
| `Alerts (N)` tab | the whole evidence set; the table shows canonical rows and folds the losers into an accordion |
| `Rules (N)` tab | distinct rules, each row counted by the **alerts in view** that fired it |
| `Entities` | every node the canvas draws, **including process GUIDs** |
| `Shared identities` | only the kinds that score L1 links (host/user/IP/domain), which is why it is smaller |
| `Peak link` | the strongest single pair score — the number `θ` gates |

### Dedup witnesses in the graph and the Alerts tab

Soft-dedup losers are scored evidence, but a 98-alert case is nine real actions
and eighty-nine copies of them. The evidence set is the union of
`aisoc_cases.alert_ids`, `alerts.case_id`, and dedup losers whose
`deduplicated_into:<winner>` tag points at a member — which is why a campaign
shows 9 members but 98 alerts on a case the engine collapsed from 114.

The `dedup hidden N` switch beside `Field filter` (on by default, the same chip
the TKG attribution table uses) applies one decision to both surfaces:

- **Graph** — observations whose alerts are all witnesses leave the canvas with
  their edges, and a shared key left without a live observation goes too.
  `Entities` and `Graph (N)` count what is drawn, so they cannot disagree with
  the canvas.
- **Alerts** — the table shows the canonical rows, and an
  `N soft-dedup witnesses hidden from this list` accordion sits under it.

Nothing is excluded and no score changes: the switch is a view, not a scope, so
`Clear scope` does not touch it. An observation carrying at least one canonical
alert always stays.

Any of it can be narrowed from the modal: `Exclude` on an alert drops that one,
`Exclude` on a rule drops every evidence alert that rule fired on, and the scope
bar's `Field filter` drops everything matching a `llm_payload` field. The scope
is applied server-side (graph, timeline and scores are recomputed from what is
left), nothing is deleted, and `Include` restores a rule or an alert.

## Ambient Copilot

The case workspace is **copilot-aware**: the Ambient Copilot panel proposes
the next concrete action based on the current state of the case (e.g.
"contain host", "open jira ticket", "add indicator to threat intel feed").
Each suggestion is one click away from running the right agent tool with
the right payload, and every accepted suggestion is recorded in the
ledger.
