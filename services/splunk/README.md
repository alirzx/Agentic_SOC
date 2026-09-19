# Splunk live-ingest module

Dedicated operator surface for wiring **real Splunk notables** into AiSOC so the
dashboard, alerts queue, and live feed are populated only from live data — never
from `seed_demo` or UI mock fallbacks.

## What this module is

| Piece | Role |
|-------|------|
| `services/connectors/.../splunk.py` | `SplunkConnector` — poll saved search / `index=notable`, normalize, checkpoint |
| `plugins/splunk/plugin.yaml` | Marketplace manifest |
| `infra/compose/docker-compose.splunk.yml` | Overlay: connectors + ingest + fusion on the slim demo stack |
| `app/bootstrap.py` | Optional CLI to register a Splunk connector instance via the Core API |
| `apps/docs/docs/connectors/splunk.md` | Operator walkthrough |

Investigation-time SPL (TriageAgent tools) lives separately under
`services/agents/app/integrations/splunk/` and is **not** used for dashboard KPIs.

## Quick start

```bash
# 1. Stack with live ingest spine
pnpm aisoc:splunk

# 2. Wipe any leftover seeded demo rows (keeps login tenant/user)
pnpm aisoc:purge-demo

# 3. Connect in the UI: Connectors → Add → Splunk SIEM
#    or bootstrap from env (SPLUNK_BASE_URL + SPLUNK_TOKEN + API auth):
python scripts/splunk_bootstrap.py
```

Required env (repo-root `.env`):

- `AISOC_CREDENTIAL_KEY` — Fernet key shared by API + connectors (vault)
- Splunk credentials entered in the UI (preferred) **or** `SPLUNK_BASE_URL` + `SPLUNK_TOKEN` for bootstrap

## Data path

```
Splunk REST → SplunkConnector.fetch_alerts → IngestClient /v1/ingest/batch
  → Kafka raw_events → fusion → Postgres alerts → /api/v1/metrics/dashboard
```

After a successful poll you should see non-zero tiles on `/dashboard` and
events on the Live Feed panel (WebSocket `alerts` channel).
