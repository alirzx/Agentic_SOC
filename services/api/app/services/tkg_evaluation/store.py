"""Case-evidence reads shared by the evaluator and the manual sync path.

Both flows need the same three things — the case row, its alerts (minus the
analyst's exclusions) and the saved alert scope — so they live here instead of
being imported from one caller by the other.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from sqlalchemy import text


async def load_case(db: Any, case_id: UUID, tenant_id: UUID) -> Mapping[str, Any]:
    """The case row the evaluation is scoped to (``{}`` when it does not exist)."""

    row = (
        await db.execute(
            text("SELECT id, title, severity, status, alert_ids FROM aisoc_cases WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=case_id, tenant_id=tenant_id
            )
        )
    ).fetchone()
    if not row:
        return {}
    return {
        "id": row.id,
        "title": row.title,
        "severity": row.severity,
        "status": row.status,
        "alert_ids": row.alert_ids or [],
    }


async def load_alerts(db: Any, tenant_id: UUID, case_id: UUID, alert_ids: list[str], excluded: set[str]) -> list[Mapping[str, Any]]:
    """Alert rows that are the case's evidence, with analyst exclusions removed.

    Mirrors ``cases._case_evidence``: ``aisoc_cases.alert_ids`` is a fast cache
    that can lag behind ownership, so the union of the cached ids and
    ``alerts.case_id`` is the truth. A cached id that now belongs to another case
    is dropped; an unowned cached id is kept (a writer has not stamped it yet).

    Soft-deduplicated alerts are **included**: they are case witnesses the graph
    engine scores, and their rows are only hidden from the alerts workbench.
    """

    cached = {value for value in alert_ids if value not in excluded}
    if not cached and not case_id:
        return []

    rows = (
        await db.execute(
            text(
                "SELECT id, title, severity, event_time, rule_name, mitre_techniques, llm_payload, "
                "       funnel_stage, correlation_state, occurrence_count, case_id "
                "FROM alerts WHERE tenant_id = :tenant_id "
                "  AND (case_id = :case_id OR id::text = ANY(:cached))"
            ).bindparams(
                tenant_id=tenant_id,
                case_id=case_id,
                cached=sorted(cached) or [""],
            )
        )
    ).all()

    alerts: list[Mapping[str, Any]] = []
    for row in rows:
        if str(row.id) in excluded:
            continue
        owned_by_case = row.case_id == case_id
        unowned_cached = row.case_id is None and str(row.id) in cached
        if owned_by_case or unowned_cached:
            alerts.append(dict(row._mapping))

    # Soft-dedup losers are evidence too: the engine links only the canonical
    # winner to the case and tags the losers ``deduplicated_into:<winner>``. The
    # correlation view reads the same union, so the graph's second opinion must
    # describe the same evidence the analyst is looking at.
    winners = sorted({str(alert["id"]) for alert in alerts} - excluded)
    if winners:
        loser_rows = (
            await db.execute(
                text(
                    "SELECT id, title, severity, event_time, rule_name, mitre_techniques, llm_payload, "
                    "       funnel_stage, correlation_state, occurrence_count, case_id "
                    "FROM alerts a CROSS JOIN unnest(CAST(:winners AS text[])) AS w(winner) "
                    "WHERE a.tenant_id = :tenant_id "
                    "  AND a.funnel_stage = 'deduplicated' "
                    "  AND a.tags @> to_jsonb(ARRAY['deduplicated_into:' || w.winner])"
                ).bindparams(tenant_id=tenant_id, winners=winners)
            )
        ).all()
        alert_ids = {str(alert["id"]) for alert in alerts}
        for row in loser_rows:
            if str(row.id) in alert_ids or str(row.id) in excluded:
                continue
            alerts.append(dict(row._mapping))
            alert_ids.add(str(row.id))

    return alerts


async def load_case_scope(db: Any, case_id: UUID, tenant_id: UUID) -> tuple[list[str], list[str]]:
    """``(excluded_alert_ids, filters)`` saved for the case (empty when none)."""

    row = (
        await db.execute(
            text("SELECT excluded_alert_ids, filters FROM case_alert_scopes WHERE case_id = :id AND tenant_id = :tenant_id").bindparams(
                id=case_id, tenant_id=tenant_id
            )
        )
    ).fetchone()
    if not row:
        return [], []
    return [str(value) for value in (row.excluded_alert_ids or [])], [str(value) for value in (row.filters or [])]
