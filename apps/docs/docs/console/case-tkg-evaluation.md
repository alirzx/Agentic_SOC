---
sidebar_position: 12
title: TKG second opinion
---

# TKG second opinion

The **TKG** tab in the case workspace asks a [Soorin Temporal Knowledge
Graph](https://github.com/SoorinSecurity) for an independent read on the case's
evidence. It answers one question: *does the graph agree that these alerts are
one intrusion?*

It is advisory. The evaluation never edits a case, never changes its status or
verdict, and never deletes evidence. A deployment without a TKG simply renders
`not configured`.

## What a run does

1. **Freeze the payload.** The case's member alerts (minus any alerts the analyst
   excluded in the correlation scope) are normalised into the curated Splunk
   payload shape and hashed. The hash and the payload are stored, so a reviewer
   can see exactly what the model saw.
2. **Precheck (rubric).** Alerts must exist, carry a title plus at least one
   correlation key, have timestamps and unique ids. A case that fails is stored
   as `ineligible` with the failing check names — not as an error.
3. **Attribution.** Each alert's id is resolved as a `SplunkNotable` in the graph
   (`splunk_notable_id` authority). Resolved alerts contribute their facts;
   facts are classified **real** or **synthetic**.
4. **Evidence floor.** A deterministic verdict from coverage and corroboration —
   it does not depend on any model.
5. **Judge (optional).** When an LLM is wired in, it sees only the frozen payload
   and the attribution. Its verdict may raise the floor by at most one band and
   may never weaken it.
6. **Persist.** One row per run in `case_tkg_evaluations`, newest first.

## Verdicts

| Verdict | Meaning |
|---|---|
| `true_positive` | The graph supports a coordinated intrusion |
| `likely_tp` | Strong but incomplete support |
| `needs_more_evidence` | Some alerts resolved, not enough to confirm |
| `benign` | The graph's facts argue the alerts are noise |
| `insufficient` | Nothing resolved — no opinion, not a clean bill of health |

Coverage below 60% can never confirm a case: the verdict is capped at
`needs_more_evidence`.

## Reading the panel

The panel is one chain, and the stepper states it in order:

1. **Case alert set** — the evidence the engine scored (members plus soft-dedup
   witnesses); excluded and filtered alerts are not sent.
2. **Identity resolved in the graph** — how many alerts the graph knows as an
   entity. The status of the graph's identity layer is one of:

   | Status | Meaning |
   |---|---|
   | `resolved` | The graph knows the notable and returned an entity |
   | `pending_materialization` | The graph accepted the record but has not projected it yet; re-run later, nothing needs re-sending |
   | `not_found` | The graph has never seen this notable (not ingested, or a different identity key) |
   | `unresolved` | The resolver answered with no candidate entity |
   | `skipped` | The run hit its time budget before this alert |

3. **Graph facts read** — the claims held about those entities, split into real
   and synthetic.
4. **Alerts corroborated** — alerts with at least two real facts. Coverage (step
   2) below 60% cannot confirm the case whatever this number is.
5. **Verdict** — the floor above after the judge's input is reconciled with it.

Under the chain, **What held the verdict back** names the stage in pipeline order,
with the action that clears it:

| Finding | What it means | Action |
|---|---|---|
| Never ingested | The alert is not in the graph at all | Push it with *Alerts missing from the graph*, or check the ingest pipeline |
| Not materialised yet | Accepted by the graph, not projected into entities yet | Nothing to re-send; re-run later |
| Nothing to fetch | Resolved, but the entity has no facts | Ingest the supporting events for those entities |
| Facts too thin | Facts exist, but no alert reaches two real ones | Add corroborating evidence for those entities |
| Below the confirm threshold | Coverage under 60% | Resolve more of the case's alerts |
| Time budget | Alerts were skipped mid-run | Re-run |
| Synthetic evidence | Every fact is synthetic | Ingest real evidence |

The confidence figure is the rubric's arithmetic, printed for the run:
`int(coverage × 45) + min(corroborated, 4) × 12` (+10 when an alert was
contextualised), capped at 100 and at 55 for a synthetic-only floor. A run with
5% coverage and five corroborated alerts scores `2 + 48 = 50` — that is the 50 the
panel shows, not a model's opinion.

The per-alert table shows the alert's **title and rule** (hover a row for the
notable id, AiSOC alert id, entity id, time and techniques), its identity status,
its fact count (`(n syn)` marks synthetic facts) and its **pass**:
`corroborated` (two or more real facts), `unconfirmed` (synthetic-only or fewer
than two), `contextualized` (the judge placed it in the campaign) or `—` (no
entity, so nothing was read). Filters: free-text over title/rule/id, one identity
status, and one pass — they compose, and the header shows how many rows survive.

## Graph knowledge base

The panel's **Graph knowledge base** row is the TKG's own knowledge-base id
(`AISOC_TKG_KB_ID`) that the run was answered from, stored on every evaluation.
It exists so a verdict can be tied to the exact graph it came from: the same
alerts evaluated against a different KB id are a different comparison, and a run
whose id differs from the configured one is answering from another graph. It is
an opaque id — the TKG returns no display name for it.

## Synthetic evidence cannot confirm a case

Facts whose document is listed in `AISOC_TKG_SYNTHETIC_DOC_IDS` (or tagged
`synthetic` by the graph) are counted separately. When **every** supporting fact
is synthetic:

- the verdict is capped at `needs_more_evidence`,
- confidence is capped at 55,
- the panel renders an explicit warning.

This is the graph equivalent of the repo's synthetic-vs-real transparency rule:
a demo graph must never read as production proof.

## Reason codes

Every run persists machine-readable reasons so the panel can explain itself.

| Code | Meaning |
|---|---|
| `tkg_not_configured` | `AISOC_TKG_*` credentials are unset |
| `tkg_unreachable` | The TKG did not answer (timeout, connection error, 5xx) or rejected the login |
| `tkg_auth_failed` | The TKG rejected the configured credentials |
| `tkg_kb_missing` | `AISOC_TKG_KB_ID` does not exist (404) or is not a valid UUID; also used when the graph answers with no entities |
| `precheck_failed` | The payload failed the rubric (see the failing check ids) |
| `no_alerts` / `no_llm_payload` | Nothing correlatable to send |
| `too_many_alerts` / `payload_too_large` | Over the configured caps. `AISOC_TKG_MAX_ALERTS` counts **distinct** alerts: soft-dedup witnesses ride along without ever refusing a run |
| `low_coverage` | Fewer than 60% of alerts resolved |
| `partial_attribution` | The time budget expired mid-run |
| `synthetic_evidence_only` | Only synthetic facts were found |
| `judge_unavailable` / `judge_invalid_output` | The judge failed or replied non-JSON |
| `served_from_cache` | Same payload evaluated within `AISOC_TKG_CACHE_TTL_S` |

## Configuration

```bash
# API service
AISOC_FEATURE_TKG_EVALUATION=true
AISOC_TKG_URL=http://192.168.0.55:2516
AISOC_TKG_EMAIL=analyst@example.com
AISOC_TKG_PASSWORD=...          # secret — keep it in your secret store
AISOC_TKG_KB_ID=01a1e46e-4874-7052-97b6-4717a860e793
AISOC_TKG_TENANT=tenant-blue
AISOC_TKG_SOURCE_SYSTEM=splunk
AISOC_TKG_SOURCE_INSTANCE=splunk-e2e
AISOC_TKG_MAX_ALERTS=40
AISOC_TKG_BUDGET_MS=20000
AISOC_TKG_CACHE_TTL_S=900
AISOC_TKG_SYNTHETIC_DOC_IDS=            # comma-separated document ids

# Setup/lab only: allow the panel to push a case's *missing* alerts.
AISOC_TKG_ALLOW_SEND=false
AISOC_TKG_SOURCE_NAME=agentic-soc-manual-20261116
AISOC_TKG_SEND_DELAY_S=1.0
AISOC_TKG_SEND_MAX_ALERTS=25
```

The credentials are the same read-only service account used for ingestion. The
API only calls `graph/overview`, `knowledge/resolve` and `knowledge/context`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/cases/tkg-evaluation/health` | Configured? Ready? Entity/fact counts |
| `POST` | `/api/v1/cases/{id}/tkg-evaluation` | Run (or reuse a cached) evaluation |
| `GET` | `/api/v1/cases/{id}/tkg-evaluation` | Latest stored evaluation |
| `GET` | `/api/v1/cases/{id}/tkg-evaluations` | History (default 20) |

`POST` accepts an optional body
`{"engine_verdict": "likely_tp", "refresh": false, "send_missing": true}`. Passing the
engine's verdict fills the `agree` flag; `refresh` bypasses the cache.

## Re-run, and the alerts it sends

**Re-run evaluation** is the only control: it resolves every member alert
(canonical and dedup witness), waits for materialisation (see
[Watching a run](#watching-a-run)) and scores. One step of it can also write:

- **when `AISOC_TKG_ALLOW_SEND=true`**, it pushes the alerts the graph answered
  `not_found` for — at most 60 per run, spaced by `AISOC_TKG_SEND_DELAY_S` because
  the graph's extractor rate-limits its own model — then re-reads them so they
  count as `sent · processing` instead of `never sent` (the rest wait for the next
  run; sending is idempotent because a delivered notable resolves and is skipped).

A run sends in **two passes**: the canonical members first, then the
soft-dedup witnesses. The first pass resolves, sends, waits and **stores a
verdict** (`canonical_only_verdict`, row status `partial`); the second pushes the
witnesses and stores the full evaluation, which supersedes it. On a real case most
of the set is witnesses, so this is what makes a verdict arrive while the graph is
still working through their queue — and it means a witness that never materialises
costs coverage, not the whole result.

While it runs, the stepper names the pass it is in — `Pass 1 of 2 — canonical
alerts · 3 alerts`, then `Pass 2 of 2 — duplicate witnesses · 1009 alerts` — and
the wait step is labelled `canonical` or `duplicates` accordingly. A long wait on
the witness queue therefore cannot be mistaken for a stalled canonical pass.

With the flag off (the default) nothing is written: the run is read-only and the
missing alerts stay `never sent`. The attempt count and any rejected records are
stored on the evaluation (`attribution.send`) and shown as a **Pushed by this run**
line, so a 422 from the normalizer is never mistaken for a graph outage.

`POST /cases/{id}/tkg-evaluation/sync` still exists for scripts and backfills
(`dry_run` defaults to true and the endpoint refuses with `tkg_send_disabled` when
the flag is off); the console no longer surfaces a separate send step.

## Soft-deduplicated evidence

Exact dedupe does not delete duplicates: it moves them to `funnel_stage='deduplicated'`,
keeps their `case_id` (they stay case witnesses the correlation engine scores) and
hides them from the alerts workbench.

- The case correlation modal's **Alerts** tab lists them with a `deduplicated` badge
  (plus `×N` when `occurrence_count` records how many raw events they stand for).
- The evaluation's evidence set is `aisoc_cases.alert_ids` ∪ `alerts.case_id`, exactly
  like the correlation view — so dedup witnesses are sent to the graph and attributed
  like any other member alert.
- The panel reports `DEDUPLICATED EVIDENCE: N of M`, and each attribution row carries a
  `dedup` chip. They still count toward coverage and corroboration; a dedup witness is
  weaker evidence, not invisible evidence.
- The attribution table **hides witnesses by default** (`dedup hidden N` is on) because
they are copies of alerts the workbench already lists; the chip toggles them back in.
  The status/pass chips and the `N of M alerts` counter follow the same pool, so the
  numbers always describe what is on screen.

### Whose problem is a missing alert?

Each status in the table names the side that owns the fix, so nobody has to read the
code to tell a send-side gap from a graph-side delay:

| Status | Meaning | Fix on |
|---|---|---|
| `in graph` (`resolved`) | The graph returned an entity; facts can be read. | — |
| `sent · processing` (`pending_materialization`) | The TKG accepted the record (receipt exists) and is still projecting it into entities and facts. | TKG side — wait and re-run; re-sending changes nothing. |
| `never sent` (`not_found`) | The graph holds no record for this notable: it was never ingested, or its notable id differs from the identity the graph stores. | AiSOC side — send it, then re-run. Waiting will not make it appear. |
| `sent, no entity` (`unresolved`) | The resolver answered but mapped the record to no candidate entity. | TKG side — nothing to re-send. |
| `skipped` | The run hit its time budget before probing this alert. | Re-run. |

The row shows the label plus a one-line `AiSOC side` / `TKG side` caption, and the
chips above the table use the same wording, so `never sent 74` reads differently from
`sent · processing 16` at a glance.

## Opening an alert from the table

Every row is a link to the alert workbench (`/alerts/{row_id}`): click it, or focus it
and press Enter. Rows from runs stored before the AiSOC row id was recorded carry no
link — the notable id there is not the workbench's id, and guessing it would open the
wrong alert. Re-run the evaluation to refresh such a row.

## Getting new evidence into the graph

The API never writes to the TKG. Ingesting a case's alerts is an operator action:
`scripts/agentic_soc_sync_payload.py` exports a case as `llm_payload_only.jsonl`,
and the standalone sender in the TKG repository posts it with the
`agentic-soc.splunk-curated.v1` profile. Run the sender with a delay
(`--delay 1.5`) — the graph's extraction endpoint rate-limits its own model and
will otherwise answer `LLM endpoint is rate limiting (429)`.

## When the graph does not answer

A run whose readiness probe fails stores `unavailable` with a reason code. Two
details matter there:

- The login is retried three times (0.4 s and 1.2 s apart) before giving up, because
the graph answers slowly while it is ingesting and one busy second is not an outage.
- A failed probe keeps the cause apart: a **404 on a KB path** (or a
`AISOC_TKG_KB_ID` that is not a UUID, which the router rejects with 400/422) is
`tkg_kb_missing` — the graph answered, that knowledge base just is not there.
Only a timeout, a connection error, a 5xx or a rejected login is
`tkg_unreachable`. A graph that answered with zero entities is also
`tkg_kb_missing`.
- The panel keeps the last run that reached the graph, with a **Latest attempt** band
saying what failed and when the usable run was stored. A transient timeout never
leaves the panel empty.

## Watching a run

Re-running the evaluation starts a **job**, not one long request, so the panel
can show where the run is instead of freezing on “asking TKG”. Four counters move
under the header while it runs:

| Step | What it shows |
| --- | --- |
| Read the case | how many alerts are in the set being resolved |
| Resolve identities | `probed / total` as each lookup returns, plus the entities and facts so far |
| Wait for the graph | alerts the graph accepted but has not projected, and which re-probe wave is running |
| Judge and store | scoring, then the verdict and confidence once stored |

The panel is not frozen on the previous run while this one works. After every
few resolved alerts the job publishes a **provisional evaluation** — the same
shape as a stored row, scored with the same rubric (`int(coverage × 45) +
min(corroborated, 4) × 12`) — and the verdict pill, confidence, four-step chain,
diagnosis and attribution table render it, carrying a `live · partial` badge.
Confidence therefore rises as alerts resolve, and a send is pushed one alert at
a time: an accepted record turns into `sent · processing` in its own row before
the next one goes. After the first few alerts you can already judge whether the
case is worth the rest of the run and stop it.

The **Wait for the graph** step exists because ingest is asynchronous: a
materialised alert needs no re-sending, only re-reading. A run polls every
`AISOC_TKG_MATERIALISE_POLL_S` seconds (default 5 s) and re-probes until the queue
drains, the operator stops the wait, or `AISOC_TKG_WAIT_TIMEOUT_S` (default 600 s,
i.e. ten minutes per pass) runs out. `AISOC_TKG_MATERIALISE_WAIT_S` is ignored
(kept so old `.env` files parse).

The step's second line leads with the queue and the clock —
`wave 12 · 73 queued · 8m 42s of waiting left` — because `wave N` is a *re-probe
round*, not a count of alerts: 290 waves for 73 queued alerts is correct, not a
bug.

Each wave re-probes a **rotating slice** of the queued alerts
(`WAVE_PROBE_LIMIT`, 24) rather than the whole queue, so a wave stays shorter
than the poll interval; successive slices rotate through the queue.

Three things end that wait, and only the last one is a failure:

- **Stop waiting & score** — the button appears inside the wait step while it is
running (`POST …/run/{run_id}/skip-wait`). It ends *that stage only*: the run then
judges and stores what is resolved, with `materialise_wait_skipped`. The alerts
already sent keep materialising in the graph and the next run reads them.
- **The cap** — `AISOC_TKG_WAIT_TIMEOUT_S`, ten minutes per pass. When it elapses
the run does exactly what the button does and records `materialise_wait_timeout`.
`0` restores an unlimited wait.
- **Cancel run** is a different control: it halts the whole job at its next
checkpoint. What the run had already resolved and scored is **stored as a
`partial` row** (`run_stopped_partial`), so cancelling costs the rest of the
run, not the minutes already spent. Leaving the page does not cancel it — the
job keeps going and stores its result. A run cancelled *after* its canonical
pass already stored that pass's verdict; the cancel only stops the witness pass
from storing the final one.
- **A document the graph itself reports as failed** also ends the wait (and the
pass is still scored, stored and reported as `tkg_extraction_failed`). A queue that
will never drain is not a slow queue. Before each wave the run reads the knowledge base's
receipts; when *every* alert still queued has a terminal `failure_code`
(`soc_document_failed`, `soc_binding_rejected`, `soc_identity_conflict`,
`soc_revision_predecessor_failed`, or any code whose job the graph marked
`failed` — it only does that when no retry is scheduled) the run stops waiting,
stores the evaluation with `tkg_extraction_failed`, and says so. One dead
document next to live ones is not enough to stop — the rest may still be on
their way.

A slow slice is *not* a partial run: the counter line says
`probed 18/24 of the queued set before the wave budget` and the next wave picks
up where it left off.

The usual cause of `soc_document_failed` is the graph's own extractor: it calls
an LLM endpoint, retries a 429 five times with backoff, and then marks the
document failed. The receipt keeps saying `submitted`, which is why re-probing
never helps. Fix it on the graph side — open **TKG → Library**, filter by
`Failed`, and refresh each document (the per-document refresh re-runs extraction;
the bulk *re-run failed* route only sees documents whose graph status is
`failed`, not these). Then re-run the evaluation. Sending more records into the
same rate limit only adds more failed documents: an ingest answered with HTTP 429
stops the batch, and the run reports `tkg_rate_limited`.

## Limitations

- Each evaluation has a 20 s wall-clock budget for resolution; a large case is
  marked `partial` rather than holding the connection open. Raise
  `AISOC_TKG_BUDGET_MS` for bigger cases.
- Live progress is in-process: restarting the API loses the view of a run in
  flight (its result is still stored when it finishes). A single API process is
  assumed, which is what this deployment runs.
- The judge is not wired to a provider by default, so a run records the
  evidence-only floor. `runner.run_evaluation(..., call_llm=...)` is the seam.
- Attribution depends on the alert id being the same notable id that was
  ingested. Alerts whose ids were rewritten after ingestion will not resolve.
