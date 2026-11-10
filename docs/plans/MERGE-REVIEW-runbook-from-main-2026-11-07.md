# Merge Review: origin/main → runbook (2026-11-07 — round 2)

## Commits merged

| Hash | Message |
|------|---------|
| `a1e26b4` | feat(alerts): introduce deduplication stage and enhance funnel processing |
| `b77f5c3` | feat(alerts): enhance deduplication logic and improve funnel processing |

**Base commit (shared ancestor):** `cfcf759` — feat(api): enhance connector test timeout handling

---

## Theme of the two commits

A new **soft-deduplication** feature for the SOC Funnel. Instead of hard-deleting duplicate
Splunk ESCU alerts, they are now moved to a new `deduplicated` funnel stage (visible as its
own Deduplicated column on the SOC Funnel board). This prevents alert row loss while keeping
the main Alerts workbench clean.

---

## Files changed in origin/main and their disposition in this merge

### ✅ Auto-merged cleanly (no manual intervention)

| File | What main changed |
|------|--------------------|
| `apps/web/src/components/alerts/AlertsView.tsx` | Added `'deduplicated'` to `FUNNEL_STAGE_QUERY` set so the filter chip works |
| `apps/web/src/components/funnel/SocFunnelBoardView.tsx` | Added `deduplicated` accent colour; updated backfill/dedupe result messages to show `alerts_deduplicated` count |
| `apps/web/src/lib/api.ts` | Added `'deduplicated'` to `FunnelStage` union type; added `dedupe?` shape to backfill response; added `alerts_deduplicated?` to dedupeExact response |
| `services/api/app/api/v1/endpoints/alerts.py` | `list_alerts`: hides deduplicated rows from default workbench (pass `funnel_stage=deduplicated` explicitly to inspect). `get_alert_stats`: excludes deduplicated rows from counts |
| `services/api/app/api/v1/endpoints/soc_funnel.py` | `BackfillResponse` gains `dedupe: dict`; dedupe route summary updated to reflect soft-collapse behaviour |
| `services/api/app/services/alert_queue.py` | Analyst queue filter excludes `funnel_stage=deduplicated` rows |
| `services/api/app/services/funnel_stages.py` | Added `DEDUPLICATED = "deduplicated"` constant; added to `FUNNEL_STAGES`, `STAGE_LABELS`, and `BOARD_ORDER` |
| `services/api/tests/test_alerts_tenant_isolation.py` | Test updates for new dedup behaviour |
| `services/api/tests/test_exact_dedupe.py` | New / updated tests for soft-dedup logic |
| `services/connectors/app/connectors/splunk.py` | `_is_replaceable_notable_search()` enhanced: now also replaces stub `index=notable \| table …` queries that omit vendor identity fields (notable_id, source_guid, etc.) |
| `services/connectors/tests/test_splunk_connector.py` | Tests for the enhanced `_is_replaceable_notable_search` |
| `services/fusion/app/core/config.py` | New setting `alert_display_dedup_enabled` (alias `AISOC_ALERT_DISPLAY_DEDUP`, **default `False`**): gates the ingest-time display-dedupe in AlertSink |
| `services/fusion/app/services/alert_sink.py` | Ingest-time display-dedupe is now behind `settings.alert_display_dedup_enabled` (off by default). Without this flag every distinct Splunk finding.uid now lands as its own row; the Funnel's soft-dedupe is the only collapse path |
| `services/fusion/tests/test_alert_sink.py` | Tests updated for the new opt-in gate |

---

### ⚠️ Manual conflict resolution required

**`services/api/app/services/agentic_funnel.py`** — ONE conflict

**Location:** `run_backfill()`, after `sync_legacy_funnel_stages` call.

**Runbook HEAD had:**
```python
await db.commit()

# Runbook: one "Case opened" row per case this run created...
for created in created_cases:
    await emit_case_created(db, tenant_id=tenant_id, ...)
```

**origin/main had:**
```python
# Soft display-dedupe...
from app.services.exact_dedupe import dedupe_exact
dedupe = await dedupe_exact(db, tenant_id=tenant_id, dry_run=False)
```
*(plus `"dedupe": dedupe` in the return dict — already outside conflict markers)*

**Why this conflicted:** Both sides added code in the same narrow region between
`sync_legacy_funnel_stages` and the `return` statement.

**Also in the new commits:** four other additions to `agentic_funnel.py` that
auto-merged without conflict:
- `import time`
- `_AUTO_DEDUPE_INTERVAL_S = 15.0` / `_last_auto_dedupe_monotonic` throttle dict
- `funnel_board()`: soft-dedupe block (throttled, with try/except + rollback)
- `sync_legacy_funnel_stages()`: excludes `funnel_stage IS DISTINCT FROM 'deduplicated'` from the suppressed-stage sync

**Resolution applied (both sides kept, in correct order):**

```python
stage_sync = await sync_legacy_funnel_stages(db, tenant_id=tenant_id, since=since)

# 1. Commit the main backfill first (from runbook HEAD)
await db.commit()

# 2. Emit Runbook case-opened events (from runbook HEAD)
for created in created_cases:
    await emit_case_created(db, tenant_id=tenant_id, ...)

# 3. Soft-dedupe (from origin/main) — after the commit, with error handling so
#    a dedupe failure never rolls back a completed backfill
dedupe: dict[str, Any] = {}
try:
    from app.services.exact_dedupe import dedupe_exact
    dedupe = await dedupe_exact(db, tenant_id=tenant_id, dry_run=False)
except Exception as exc:  # noqa: BLE001
    logger.warning("run_backfill.auto_dedupe_failed", error=...)
    await db.rollback()

return {
    ...,
    "dedupe": dedupe,   # from origin/main
}
```

**Design notes:**
- `db.commit()` must come first so the backfill is durable before anything else runs.
- `emit_case_created` uses its own commits; safe to run before dedupe.
- `dedupe_exact` is wrapped in try/except (matching the `funnel_board()` pattern) — a
  dedupe failure must never roll back an already-committed backfill.
- `dedupe` initialised to `{}` so the return dict is always valid even if dedupe throws.

---

## Key behaviour changes to be aware of

| Area | Before these commits | After these commits |
|------|----------------------|---------------------|
| Duplicate Splunk ESCU alerts | Hard-deleted by "Remove duplicates" | Soft-moved to `funnel_stage=deduplicated`; visible in Deduplicated board column |
| Alerts workbench (`/alerts`) | Showed all alerts including duplicates | Hides deduplicated rows by default; pass `?funnel_stage=deduplicated` to inspect |
| Dashboard alert counts | Counted all alerts | Excludes deduplicated rows |
| Analyst queue | Included deduplicated rows | Excludes deduplicated rows |
| Backfill response | No dedupe info | Returns `dedupe: {alerts_deduplicated, groups_collapsed, ...}` |
| Ingest-time display-dedupe | Always active if display key matched | Now opt-in via `AISOC_ALERT_DISPLAY_DEDUP=true` (default off) |
| Splunk custom_search detection | Only replaced truly empty SPL | Also replaces bare `index=notable \| table …` stubs without identity fields |
| `funnel_board()` auto-dedupe | Not present | Runs dedupe on every board load, throttled to once per 15s per tenant |
