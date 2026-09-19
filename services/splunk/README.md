# Splunk live-ingest module

Dedicated operator surface for wiring **real Splunk** into AiSOC so the
dashboard fills from live data only.

## Your lab host

| Item | Value |
|------|--------|
| Web UI | `https://192.168.0.10:8000/` |
| REST API (connector) | `https://192.168.0.10:8089` |
| Auth | Basic `admin` / password in local `.env` only |

Credentials live in repo-root `.env` (`SPLUNK_*`) — **never commit them**.

## Quick start

```bash
pnpm aisoc:splunk
pnpm aisoc:purge-demo
# UI → Connectors → Add → Splunk SIEM
#   base_url: https://192.168.0.10:8089
#   username / password
#   custom_search: ES catalog SPL (see docs)
#   earliest_time: -90d@d
#   ssl_verify: false
```

Or register from env:

```bash
python scripts/splunk_bootstrap.py   # needs AISOC_API_TOKEN
```

## Data path

```
Splunk REST → SplunkConnector.fetch_alerts → IngestClient
  → Kafka → fusion → Postgres → /api/v1/metrics/dashboard
```

### Catalog vs fired notables

The ES `action.correlationsearch.enabled=1` query returns the **rule catalog**.
For live incident stream use `search index=notable` (or an ES notable saved search).
