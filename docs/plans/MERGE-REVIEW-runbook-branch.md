# Merge Review: `fix/connector-availability-and-playbooks` → `runbook`

## Context

Branch `runbook` was created from `origin/main` (commit `cfcf759`) and all commits from
`fix/connector-availability-and-playbooks` (7 commits since `19a0cee`) were merged in via
`git merge --no-commit --no-ff`.

Five files had real 3-way conflicts (both sides modified them). One additional file had a
pre-existing corrupt merge in `origin/main` itself that was fixed during this operation.

---

## File 1 — `services/agents/app/main.py`

**Conflict:** main added privacy gateway startup validation; fix branch added outcomes router.

**Resolution:** Both changes applied — they are in different parts of the file.

### Added by `origin/main` (was missing after `--theirs`):

```python
# import added after PlaybookStore import
from app.privacy.context import validate_privacy_configuration

# added at the top of lifespan(), before playbook store seed
# Privacy is a provider-egress security boundary. An explicitly enabled
# but incomplete remote configuration must stop startup, never degrade to
# an unprotected provider call.
validate_privacy_configuration()
```

### Kept from `fix/connector-availability-and-playbooks`:

```python
from app.api.outcomes import router as outcomes_router
# ...
app.include_router(outcomes_router)  # prefix: /api/v1/outcomes  (Runbook analyst feedback)
```

---

## File 2 — `services/api/app/api/v1/endpoints/alerts.py`

**Conflict:** main renamed `hydrate_alert` → `hydrate_alert_for_detail` in the splunk_notable
import; fix branch added runbook emitters, provenance materialisation, and rule evaluation
scheduling.

**Resolution:** Applied the rename on top of the fix branch version. Both sets of changes are
in completely independent sections of the file.

### Applied from `origin/main`:

```python
# import changed from:
from app.services.splunk_notable import hydrate_alert, iocs_from_raw, mitre_attack_rows

# to:
from app.services.splunk_notable import (
    hydrate_alert_for_detail,
    iocs_from_raw,
    mitre_attack_rows,
)

# Two call sites updated:
# lookup_alert():
alert = await hydrate_alert_for_detail(db, alert)

# get_alert() — with added comment:
# Never block the Investigation Rail on a slow/hung Splunk lookup.
alert = await hydrate_alert_for_detail(db, alert)
```

### Kept from fix branch (unchanged):

- `emit_alert_escalation`, `emit_alert_update_events`, `materialize_alert_provenance`, `evaluate_alert` imports
- `funnel_stage: str | None = "ingested"` (made Optional)
- `materialize_alert_provenance` call in `_build_alert_detail`
- `emit_alert_update_events` + `evaluate_alert` scheduling in `update_alert`
- `emit_alert_escalation` call in `escalate_alert`

---

## File 3 — `services/api/app/api/v1/endpoints/soc_funnel.py`

**Conflict:** main added `FUNNEL_MAX_WINDOW_HOURS` constant reference and updated `le=`
parameter bounds; fix branch added `_audit_bulk_operation` and audit logging on all bulk
operations.

**Resolution:** Both changes applied — they are in independent sections.

### Applied from `origin/main`:

```python
# new import added
from app.services.agentic_funnel import FUNNEL_MAX_WINDOW_HOURS

# Query le= updated in 3 endpoints (get_reportable, get_funnel_board, post_funnel_backfill):
hours: int = Query(24, ge=1, le=FUNNEL_MAX_WINDOW_HOURS)   # was le=168

# Route summary updated:
@router.post("/funnel/backfill", ..., summary="Run agentic funnel backfill")
# was: summary="Run 24h agentic funnel backfill"
```

### Kept from fix branch:

- `_audit_bulk_operation` helper function
- Audit emission in `post_funnel_backfill`, `post_funnel_dedupe_exact`, `post_funnel_reenrich_splunk`
- `request: Request` parameter added to all three bulk endpoints

---

## File 4 — `services/api/app/services/agentic_funnel.py`

**Conflict:** main added `FUNNEL_MAX_WINDOW_HOURS` constant, `_window_since()` helper, and
fixed PostgreSQL cast syntax; fix branch added `emit_case_created`, `created_cases` tracking,
and `_open_runbook_tasks` function.

**Resolution:** All changes from both sides applied.

### Applied from `origin/main`:

```python
# Constant added after _SIBLING_CAP:
# Max lookback for board / backfill / reportable (30 days). A 7d cap left
# multi-day ingest floods stuck at ``ingested`` with no way to advance them.
FUNNEL_MAX_WINDOW_HOURS = 720

# Helper added:
def _window_since(hours: int) -> datetime:
    """Clamp ``hours`` into ``[1, FUNNEL_MAX_WINDOW_HOURS]`` and return UTC since."""
    return datetime.now(UTC) - timedelta(hours=max(1, min(int(hours), FUNNEL_MAX_WINDOW_HOURS)))

# 3 inline timedelta calls replaced with _window_since():
# run_backfill(), list_reportable(), funnel_board()
since = _window_since(hours)   # was: datetime.now(UTC) - timedelta(hours=max(1, min(hours, 168)))

# PostgreSQL cast syntax fixed (2 SQL blocks, ~12 occurrences):
# was:  :host::text IS NOT NULL
# now:  CAST(:host AS text) IS NOT NULL
# was:  to_jsonb(ARRAY[:host::text])
# now:  to_jsonb(ARRAY[CAST(:host AS text)])
# (same pattern for :ip and :usr bindings)
```

### Kept from fix branch:

- `from app.services.runbook.emitters import emit_case_created`
- `created_cases: list[dict[str, Any]] = []` accumulator in `run_backfill`
- `created_cases.append(...)` inside the case-creation loop
- Post-commit `emit_case_created` loop after `run_backfill`'s own commit
- `_open_runbook_tasks()` function (reads Runbook task counts for the board)

---

## File 5 — `apps/web/src/components/funnel/SocFunnelBoardView.tsx`

**Conflict:** main added case-link routing (CASE_LINK_STAGES, alertCardHref, stageListHref)
and a 30d time-window option; fix branch added task badges per alert and a persistent
"Open Runbook" button.

**Resolution:** Full manual merge — both sets of UI features integrated into a single
coherent component.

### Applied from `origin/main`:

```tsx
/** Stages where the primary object is the case, not the alert row. */
const CASE_LINK_STAGES = new Set(['cased', 'ready_for_jira', 'jira_pushed']);

function alertCardHref(stageId: string, alert: FunnelBoardAlert): string {
  if (CASE_LINK_STAGES.has(stageId) && alert.case_id) {
    return `/cases/${alert.case_id}`;
  }
  return `/alerts/${alert.id}`;
}

function stageListHref(stageId: string): string {
  if (CASE_LINK_STAGES.has(stageId)) {
    return '/cases';
  }
  return `/alerts?funnel_stage=${encodeURIComponent(stageId)}`;
}

// StageColumn: listHref, smart title, case indicator
const listHref = stageListHref(stage.id);
// header link: href={listHref}, conditional title
// footer "view all": href={listHref}
// alert card: href={alertCardHref(stage.id, alert)}, title={opensCase ? 'Open case' : ...}
//             severity line: {opensCase ? ' · case' : ''}

// Time filter: added 720 (30d)
{[24, 48, 168, 720].map((h) => (
  // ...
  {h === 720 ? '30d' : h === 168 ? '7d' : `${h}h`}
))}
```

### Kept from fix branch:

```tsx
const TASK_BADGE: Record<string, { label: string; className: string }> = { ... };

// per-stage "N waiting on an analyst" counter
{(stage.open_tasks ?? 0) > 0 ? <p ...>{stage.open_tasks} waiting on an analyst</p> : null}

// per-alert task badge chips + "Runbook →" link
const tasks = alert.open_tasks ?? [];
// restructured li (class on <li>, <Link className="block">) to allow task badges below the link
<div className="mt-1.5 flex flex-wrap items-center gap-1">
  {tasks.map((task) => (
    <span ...>{badge.label}</span>
  ))}
  <Link href={`/runbook/alert/${alert.id}`} ...>Runbook →</Link>
</div>

// "Open Runbook" button in filter bar
<Link href="/runbook?tab=action-plan" ...>Open Runbook</Link>
```

---

## File 6 — `services/agents/app/api/alert_investigate.py` *(pre-existing bug in origin/main)*

**This file was NOT in the 5 conflict files** — `git merge` auto-merged it. However, `origin/main`
itself contained a corrupt merge (a bad commit by another developer) that was silently copied in.
This caused the `SyntaxError: invalid syntax` at startup.

**Root cause:** `origin/main` had two overlapping versions of `investigate_alert` and a broken
`_run_investigation` except block resulting from an earlier failed merge on the remote:
- Duplicate keyword arguments in `InvestigatorOrchestrator().run()` (`raw_alert` and `tenant_id` appeared twice)
- Duplicate `logger.error` call with an incomplete `result = AgentInvestigationOut(` statement
- Orphaned `error=str(exc),` and `).model_dump()` lines after a `raise HTTPException`

**Fix applied:** Rewrote the corrupted section with the clearly intended structure:

```python
async def _run_investigation(
    *,
    run_id: str,
    alert_id: str,
    summary: str,
    raw_alert: dict[str, Any],
    tenant_id: str,
    model_name: str | None,
    started_at: str,
) -> None:
    """Background worker — never raises into the request path."""
    tenant_owner: str | None = None
    try:
        tenant_owner = tenant_id
        _runs[run_id]["_tenant_owner"] = tenant_owner
        state = await InvestigatorOrchestrator().run(
            case_id=alert_id,
            alert_summary=summary,
            raw_alert=raw_alert or {"alert_id": alert_id},
            tenant_id=tenant_id or "default",
        )
        # ... success path unchanged ...
    except Exception as exc:  # noqa: BLE001 — persist failure for the poller
        completed_at = datetime.now(UTC).isoformat()
        logger.error("alert_investigate.failed", run_id=run_id, alert_id=alert_id, error_category=type(exc).__name__)
        result = AgentInvestigationOut(
            id=run_id,
            alertId=alert_id,
            status="failed",
            findings=None,
            recommendations=[],
            actions=[],
            startedAt=started_at,
            completedAt=completed_at,
            model=model_name,
            error="Investigation failed",
        )
        _runs[run_id] = {
            **result.model_dump(),
            **({"_tenant_owner": tenant_owner} if tenant_owner is not None else {}),
        }
        # No raise here — this is a background task; the caller already returned pending.
```

**Key design decisions in the fix:**
1. `tenant_id` comes from the function parameter — not re-resolved from `request`/`req` (those don't exist in the background worker scope).
2. `raise HTTPException` removed from the except block — background tasks cannot propagate HTTP exceptions to the caller (the response was already sent).
3. The old blocking `investigate_alert(req, request)` function (which did everything inline) was removed; the new async-task version at line ~240 is the only entry point.
