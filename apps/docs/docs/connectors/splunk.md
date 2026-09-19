---
title: Splunk SIEM
description: Ingest notable events (urgency→severity) into AiSOC (splunk connector).
---

# Splunk SIEM

The **Splunk** connector (`splunk`, category `siem`) pulls notable events via the Splunk REST API and normalizes each into the AiSOC alert shape, mapping urgency onto the five-tier ladder (`info | low | medium | high | critical`).

## Architecture

```
Splunk (8089) → connectors (SplunkConnector) → ingest-worker
  → Kafka raw_events → fusion → Postgres alerts → dashboard / realtime
```

Operator docs for the dedicated live-ingest module live at `services/splunk/README.md`.

## Setup

1. Bring up the live spine (demo stack + Splunk overlay):

   ```bash
   pnpm aisoc:splunk
   pnpm aisoc:purge-demo   # wipe any leftover seeded INC-RT-* / DEMO-* rows
   ```

2. In **Connectors → Add connector**, choose **Splunk SIEM**.
3. Fill in:
   - **Splunk URL** — management port (`https://host:8089`), not the web UI.
   - **HEC / API Token** — vault-encrypted at rest.
   - **Saved Search Name** — default `AiSOC_Alerts`; leave blank to search `index=notable`.
   - **Verify SSL** — disable only for self-signed / private CA labs.
4. Click **Test connection**, then **Save**. The in-process scheduler polls on the default cadence (override per-instance via `poll_interval_seconds`).

Events flow through ingest (OCSF normalize) → Kafka → fusion, where alerts are written to Postgres and broadcast on the realtime channel. The dashboard `/metrics/dashboard` endpoint aggregates those live rows — there is no mock fallback.

## Agent-side SPL queries

Separate from ingest, TriageAgent can run constrained SPL against the same Splunk instance when `SPLUNK_ENABLED=true` (see `.env.example` and `services/agents/app/integrations/splunk/`). That path is for investigation enrichment, not dashboard population.
