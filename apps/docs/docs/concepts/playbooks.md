---
sidebar_position: 2
---

# Playbooks

Playbooks are reusable, declarative workflows that orchestrate investigation and
response. They run inside the `services/agents` service via the
[`PlaybookEngine`](https://github.com/beenuar/AiSOC/tree/main/services/agents/app/playbook/engine.py),
emit realtime events, and can be authored as JSON or via the visual React Flow
editor in the web app.

## Anatomy of a playbook

A playbook is a Pydantic model with metadata, a trigger, and an ordered list of
steps. The wire format is JSON; the runtime model is in
[`services/agents/app/playbook/models.py`](https://github.com/beenuar/AiSOC/tree/main/services/agents/app/playbook/models.py).

```json
{
  "id": "ransomware-response-v1",
  "name": "Ransomware Response",
  "description": "Immediate containment and investigation for ransomware detections.",
  "version": "1.0.0",
  "tags": ["ransomware", "malware", "critical"],
  "trigger": {
    "on": "alert",
    "severity": ["critical"],
    "tags": ["ransomware"]
  },
  "author": "AiSOC",
  "enabled": true,
  "steps": [
    {
      "id": "isolate",
      "name": "Isolate affected host",
      "type": "isolate_host",
      "params": { "host_field": "alert.host" },
      "on_failure": "abort",
      "timeout_seconds": 30
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable identifier. Generated if omitted. |
| `name` | string | Human-readable name shown in the UI. |
| `version` | semver | Bumped on every breaking change to the playbook. |
| `tags` | string[] | Free-form labels for filtering and marketplace search. |
| `trigger` | object | When the playbook fires. See [Trigger types](#trigger-types). |
| `steps` | object[] | Ordered list of steps. See [Steps](#steps). |
| `enabled` | bool | Disabled playbooks are skipped by the dispatcher. |

## Trigger types

A trigger declares when the playbook should run. The dispatcher evaluates
triggers against incoming alerts, cases, and schedules.

```json
{
  "trigger": {
    "on": "alert",
    "severity": ["high", "critical"],
    "tags": ["ransomware"],
    "rule_ids": ["AIS-EDR-0001"]
  }
}
```

| `on` | Fires when | Common filters |
|------|-----------|----------------|
| `alert` | A new alert arrives in the fusion service | `severity`, `tags`, `rule_ids`, `source` |
| `case` | A case is opened or transitions state | `severity`, `case_status` |
| `manual` | An operator clicks **Run playbook** in the UI | n/a |
| `schedule` | A cron expression matches | `cron` (e.g. `"0 */6 * * *"`) |
| `webhook` | An external system POSTs to `/v1/playbooks/{id}/trigger` | optional `secret` |

Severity values follow the four-tier ladder used everywhere in AiSOC:
`info | low | medium | high`. Vendor-native ladders (Azure, SCC, GitHub) are
collapsed into this set in each connector's `normalize()`.

## Steps

Each step has a `type` that maps to a handler in
[`engine.py`](https://github.com/beenuar/AiSOC/tree/main/services/agents/app/playbook/engine.py).

| `type` | What it does |
|--------|--------------|
| `enrich` | Calls the enrichment service for IOC reputation, geo, ASN, GreyNoise, VT, OTX. |
| `investigate` | Triggers the AI investigator agent with focus areas (`forensics`, `lateral_movement`, etc.). |
| `notify` | Sends a webhook, Slack, PagerDuty, or email notification. |
| `block_ip` | Calls a firewall/EDR connector to block an IP (currently simulated for safety in OSS builds). |
| `isolate_host` | Calls EDR to isolate a host (simulated by default). |
| `create_ticket` | Opens a ticket in Jira / ServiceNow / Linear via connector. |
| `close_case` | Marks the AiSOC case as closed via the API service. |
| `http` | Generic outbound HTTP request — `method`, `url`, `body`, `headers`. |
| `condition` | Pure branching node. Evaluates `condition` and routes to `next_true` / `next_false`. |

Common step fields:

| Field | Default | Description |
|-------|---------|-------------|
| `id` | auto | Used as the target for `next_true` / `next_false`. |
| `name` | required | Human-readable label. |
| `params` | `{}` | Step-specific parameters. Supports `{{field}}` substitution from run context. |
| `condition` | `null` | Optional gate. If false, step is `SKIPPED`. |
| `on_failure` | `abort` | One of `abort`, `continue`, `retry`. |
| `retry_max` | `0` | Retry attempts before applying `on_failure`. Backoff is `min(2^attempt, 30)` seconds. |
| `timeout_seconds` | `30` | Per-step timeout. |
| `next_true` / `next_false` | `null` | Step IDs to jump to for branching. |

## Conditions

A `StepCondition` is evaluated against the run context (which starts as the
trigger payload and accumulates each step's result):

```json
{
  "condition": {
    "field": "alert.severity",
    "operator": "eq",
    "value": "critical"
  }
}
```

Supported operators: `eq`, `ne`, `gt`, `lt`, `contains`, `exists`. The `field`
uses dot-path resolution (`alert.host.name`) and `null` is returned for missing
keys, so `exists` is the safe way to check optional data before branching on it.

## Error handling

The engine treats steps as discrete units of work with structured error
handling.

- `on_failure: "abort"` (default) — failed step stops the run, marks it
  `FAILED`, and emits `run.done` with the error.
- `on_failure: "continue"` — log the failure but proceed to the next step.
  Useful for best-effort enrichment that shouldn't block containment.
- `on_failure: "retry"` — combined with `retry_max`, retries with exponential
  backoff before falling back to whatever you set as the next-failure mode.
- Cycle detection — if the engine revisits the same `step.id`, it aborts with
  `error: "cycle at step <id>"` rather than looping forever.
- Unknown step type — the step is recorded as `SKIPPED` with
  `reason: "no handler for <type>"` so unknown actions never silently succeed.

Each step result includes `_elapsed_ms` so you can see per-step latency in the
UI and in run history.

## Approvals and dry-runs

Two patterns are supported today for human-in-the-loop steps:

1. **`dry_run` flag** — pass `dry_run: true` when calling
   `PlaybookEngine.run(...)` (or set `dry_run` in step params for individual
   destructive actions). Handlers short-circuit with
   `{"dry_run": true, "step": <name>}` and emit the same realtime events, so
   you can preview an entire run without touching production.
2. **Manual approval gate** — model the gate as a `condition` step backed by a
   field that an operator sets via the API (`POST /v1/playbook-runs/{id}/approve`).
   The engine pauses on the condition until the field flips, then resumes.

`block_ip`, `isolate_host`, and `create_ticket` are simulated by default in OSS
builds (they return `{"simulated": true, ...}`). Wire them to real connectors
by editing the corresponding handler in `engine.py` or by replacing the step
with an `http` step that calls your connector's enforcement endpoint.

## Realtime events

Every run emits events to the realtime service so the UI can stream progress:

| Event | When |
|-------|------|
| `run.started` | The engine begins executing. |
| `step.started` | Before each non-condition step. |
| `step.done` | After each step, with `status` and `result_keys`. |
| `run.done` | Final state, including the full `PlaybookRun` object. |

Channel format: `playbook:<run_id>`. Subscribe via WebSocket
(`/realtime/ws?channel=playbook:<run_id>`) or the SDK
(`AiSOC.subscribe("playbook", run_id)`).

## Starter templates

AiSOC ships with starter playbooks under
[`services/agents/data/playbooks/`](https://github.com/beenuar/AiSOC/tree/main/services/agents/data/playbooks):

| Template | Trigger | Description |
|----------|---------|-------------|
| `ransomware-response` | `severity: critical, tags: ransomware` | Isolate, enrich IOCs, AI forensic investigation, P1 ticket, page on-call. |
| `phishing-triage` | `severity: medium+, tags: phishing` | Sandbox attachments, enrich URLs, quarantine, notify user. |
| `credential-stuffing` | `tags: auth-anomaly` | Velocity check, geo-impossible-travel, force-reauth, ticket. |
| `data-exfiltration` | `tags: dlp` | Block egress, snapshot session, enrich destination, page DPO. |
| `malware-analysis` | manual | Sandbox detonation + AI summary of behaviour. |
| `insider-threat` | `tags: ueba` | Pull 30-day behaviour, peer comparison, escalate to HR-sec. |
| `lateral-movement` | `tags: lateral` | Trace process tree, identity-graph hunt, contain pivot host. |
| `privilege-escalation` | `tags: privesc` | Revoke session tokens, audit recent role changes. |
| `c2-beacon` | `tags: c2` | Block destination, isolate beaconing host, enrich infra. |
| `supply-chain-alert` | `tags: supply-chain` | Pin dep, scan repo, open security advisory. |
| `cloud-misconfiguration` | `source: cspm` | Auto-remediate via IaC PR, notify owner. |
| `vulnerability-critical` | `cvss>=9.0` | Patch advisory, asset graph blast-radius, ticket. |

## Playbook editor

The visual editor lives at **Playbooks → Editor** in the web app. It is built
on React Flow and lets you:

- Drag-and-drop nodes (trigger, enrichment, decision, action, notification).
- Connect nodes to define `next_true` / `next_false` flow.
- Configure `params`, `condition`, and `on_failure` inline per node.
- Export to JSON, save to the API, or **Run now** with a sample payload.
- Replay a past run with the same trigger context for debugging.

## See also

- [Plugin overview](../plugins/overview) — discover and install community playbooks from the marketplace.
- [Connectors](../connectors) — the integrations your playbook steps call.
- [Operations → Security](../operations/security) — RBAC for who can edit and
  run playbooks.
- [Glossary](../glossary) — terminology used in playbook authoring.
