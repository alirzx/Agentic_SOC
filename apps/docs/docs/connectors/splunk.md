---
title: Splunk SIEM
description: Ingest fired notable events (index=notable) into AiSOC.
---

# Splunk SIEM

The **Splunk** connector (`splunk`, category `siem`) pulls data via the Splunk REST API on the **management port (8089)** — not the web UI port (8000).

Auth: **Bearer token** *or* **Basic username/password**. Severity maps onto `info | low | medium | high | critical`.

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

In **Connectors → Add → Splunk SIEM** (or Edit existing):

| Field | Value |
|-------|--------|
| Splunk URL | `https://192.168.0.10:8089` |
| Username / Password | Splunk admin (leave Token empty) |
| Custom SPL | fired notables (below) |
| Earliest time | `-90d@d` |
| Verify SSL | **off** for lab self-signed certs |

### Fired notables (use this for the dashboard)

Verified against live ES stash events (`search_name`, `severity`, `dvc`, `source_guid` live inside `_raw`):

```spl
search index=notable
| table _time source search_name severity urgency host dvc dest dest_port transport src src_ip source_guid source_event_id event_id _cd _raw
```

Even a bare `search index=notable` works — the connector parses KV pairs from `_raw`.

Click **Test**, then **Save**. Scheduler polls on the configured cadence.

### ES correlation-search catalog (optional)

Lists rule *definitions*, not fired incidents. Use `| rest` (not `search rest`):

```spl
| rest splunk_server=local count=0 /services/saved/searches
| search action.correlationsearch.enabled=1
| eval notable_name=title
| eval severity=action.notable.param.severity
| table notable_name description search severity
| rename notable_name as "Notable Name", description as "Description", search as "Notable SPL", severity as "Severity"
| sort "Notable Name"
```

## Env bootstrap

Repo-root `.env` (never commit secrets):

```bash
SPLUNK_ENABLED=true
SPLUNK_BASE_URL=https://192.168.0.10:8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=  # set locally
SPLUNK_VERIFY_SSL=false
SPLUNK_EARLIEST_TIME=-90d@d
SPLUNK_CUSTOM_SEARCH=search index=notable | table _time source search_name severity host dvc dest_port source_guid _cd _raw
```

Then `python scripts/splunk_bootstrap.py` (needs `AISOC_API_TOKEN` + running API).
