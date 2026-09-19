---
title: Splunk SIEM
description: Ingest notable events / ES correlation catalog into AiSOC (splunk connector).
---

# Splunk SIEM

The **Splunk** connector (`splunk`, category `siem`) pulls data via the Splunk REST API on the **management port (8089)** — not the web UI port (8000).

Auth: **Bearer token** *or* **Basic username/password**. Severity maps onto `info | low | medium | high | critical` (including ES numeric 1–5).

## Architecture

```
Splunk (:8089) → connectors (SplunkConnector) → ingest-worker
  → Kafka raw_events → fusion → Postgres alerts → dashboard / realtime
```

## Setup (live stack)

```bash
pnpm aisoc:splunk
pnpm aisoc:purge-demo
```

In **Connectors → Add → Splunk SIEM**:

| Field | Example |
|-------|---------|
| Splunk URL | `https://192.168.0.10:8089` |
| Username / Password | Splunk admin (or leave blank and use Token) |
| Custom SPL | ES correlation-search catalog (below) or `search index=notable` |
| Earliest time | `-90d@d` |
| Verify SSL | off for lab self-signed certs |

### ES correlation-search catalog (operator query)

Use **`| rest`** (not `search rest`) — verified against Splunk 9.3:

```spl
| rest splunk_server=local count=0 /services/saved/searches
| search action.correlationsearch.enabled=1
| eval notable_name=title
| eval severity=action.notable.param.severity
| eval annotations=action.correlationsearch.annotations
| table notable_name description search annotations severity
| rename notable_name as "Notable Name",
         description as "Description",
         search as "Notable SPL",
         severity as "Severity"
| sort "Notable Name"
```

Paste into **Custom SPL**. This returns the ES *rule catalog* (~thousands of definitions).

For **fired** notables (live incidents in the dashboard feed), use instead:

```spl
search index=notable
```

with earliest `-90d@d` (or longer).

Click **Test connection**, then **Save**. The scheduler polls on the configured cadence.

## Env bootstrap

Repo-root `.env` (never commit secrets):

```bash
SPLUNK_ENABLED=true
SPLUNK_BASE_URL=https://192.168.0.10:8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=  # set locally
SPLUNK_VERIFY_SSL=false
SPLUNK_EARLIEST_TIME=-90d@d
SPLUNK_CUSTOM_SEARCH=...   # optional; same SPL as above
```

Then `python scripts/splunk_bootstrap.py` (needs `AISOC_API_TOKEN` + running API).

## Agent-side SPL

TriageAgent can run constrained SPL when `SPLUNK_ENABLED=true` (`services/agents/app/integrations/splunk/`). That path enriches investigations; dashboard KPIs come from the connector ingest spine above.
