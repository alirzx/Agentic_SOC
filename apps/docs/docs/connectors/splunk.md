---
title: Splunk SIEM
description: Ingest fired notable events (index=notable) into AiSOC every 30 minutes.
---

# Splunk SIEM

Pulls **fired** Mission Control notables from Splunk ES `index=notable` via the Search REST API (`POST /services/search/jobs`, `exec_mode=oneshot`), every **30 minutes** by default. The poll runs `| extract` and tables stash fields (`search_name`, `dvc`, `orig_rule_*`, `detection_id`, …). Duplicates are skipped (connector checkpoint + fusion fingerprint on `source_guid` / `notable_id`).

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
| extract
| eval notable_id=coalesce(source_event_id, source_guid, detection_id)
| table _time notable_id search_name detection_id dvc dest dest_port src src_ip src_port severity security_domain status owner disposition orig_rule_title orig_rule_description source_event_id source_guid transport is_prohibited
| sort 0 - _time
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
