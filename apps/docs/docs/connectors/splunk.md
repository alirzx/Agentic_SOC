---
title: Splunk SIEM
description: Ingest fired notable events (index=notable) into AiSOC every 30 minutes.
---

# Splunk SIEM

Pulls **fired** notables from Splunk ES `index=notable` via REST (:8089), every **30 minutes** by default. Duplicates are skipped (connector checkpoint + fusion fingerprint on `source_guid`).

## Setup

```bash
pnpm aisoc:splunk
pnpm aisoc:purge-demo
```

**Connectors → Add → Splunk SIEM** (or edit existing):

| Field | Value |
|-------|--------|
| Splunk URL | `https://192.168.0.10:8089` |
| Username / Password | admin (Token empty) |
| Custom SPL | see below |
| Earliest time | `-90d@d` (first backfill) |
| Poll interval | `1800` (30 minutes) |
| Verify SSL | **off** |

```spl
search index=notable
| table _time source search_name severity urgency host dvc dest dest_port transport src src_ip source_guid source_event_id event_id _cd _raw
```

Then click **Sync** once (forces an immediate poll). Within seconds you should see:

- Connector card: `Events ingested` ≥ 3 (your lab has 3 notables in 90d)
- **`/alerts` → Alerts tab**: one row per notable (not the Entities demo queue)

Ongoing: scheduler re-polls every 30 minutes; only *new* notables become new alerts.

## Architecture

```
Splunk (:8089) → connectors poll (30m) → ingest-worker
  → Kafka raw_events → fusion (promote + dedupe) → Postgres → /alerts
```
