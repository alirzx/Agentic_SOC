"""Translate real API-side actions into Runbook ledger rows.

Each function here answers one question: *this just happened — what does the
Runbook need to remember about it?* They are called from the endpoint or service
that performs the action, immediately after it commits, so the ledger records
what actually happened rather than what was requested.

Two rules every emitter follows
-------------------------------
1. **Never break the action.** A ledger write is bookkeeping; it must not turn a
   successful analyst decision into a 500. Every emitter swallows and logs its
   own failures. The primary write has already committed by then, so a lost
   ledger row is a reporting gap, not data loss.
2. **Never invent.** A row is written only for a field that actually changed,
   with the previous value captured before the write. No row is emitted for a
   no-op, and nothing is derived after the fact.

Scope
-----
Phase 1 wires the analyst-facing alert endpoints (disposition/status, tags,
assignment, case link, escalation) and case creation from the funnel. Connector
ingest is covered separately by :mod:`app.services.runbook.materialize`.

Agent-side triage stays in the investigation ledger
(``investigation_runs`` / ``investigation_events``) and is **read** by
:mod:`app.services.runbook.read` at page-render time (the ``triage_verdict``
events, joined on ``investigation_runs.case_id``). It is not copied here, so the
agent ledger remains the only writer of that evidence and the two cannot drift.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.runbook.recorder import record_event

logger = structlog.get_logger()

__all__ = [
    "emit_alert_update_events",
    "emit_alert_escalation",
    "emit_case_created",
    "emit_itsm_status_change",
]

# Fields a client may PATCH, in the order they read best on the page.
_FIELD_LABELS: dict[str, str] = {
    "status": "Status",
    "priority": "Priority",
    "tags": "Tags",
    "assigned_to_id": "Assignee",
    "case_id": "Linked case",
    "severity": "Severity",
}

# Fields whose change belongs to the funnel stage rather than the triage stage.
_FUNNEL_FIELDS = {"case_id"}

_CLOSED_STATUSES = {"resolved", "false_positive", "closed"}


def _render(value: Any) -> str:
    """Short, log-safe rendering of a field value for a summary line."""
    if value is None:
        return "unset"
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (list, tuple, set)):
        items = sorted(str(item) for item in value)
        if len(items) > 5:
            return ", ".join(items[:5]) + f", +{len(items) - 5} more"
        return ", ".join(items) if items else "empty"
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text[:120]


def _action_for(field: str, new_value: Any) -> str | None:
    """The catalog action this change corresponds to, when there is one.

    Deliberately conservative: an assignment is *not* ``assign_case``, so it
    gets no action name instead of a wrong one.
    """
    if field == "status" and str(new_value or "").lower() in _CLOSED_STATUSES:
        return "close_alert"
    if field == "tags":
        return "add_alert_tag"
    if field == "case_id":
        return "create_case"
    return None


async def emit_alert_update_events(
    db: AsyncSession,
    *,
    alert: Any,
    tenant_id: uuid.UUID,
    actor_id: str | None,
    actor_label: str | None,
    updates: dict[str, Any],
    previous: dict[str, Any] | None = None,
) -> int:
    """Record one ledger row per field the analyst actually changed."""
    previous = previous or {}
    written = 0
    try:
        for field, new_value in updates.items():
            if field in {"updated_at", "assigned_at"}:
                continue
            old_value = previous.get(field)
            if old_value == new_value:
                continue

            label = _FIELD_LABELS.get(field, field)
            stage = "funnel" if field in _FUNNEL_FIELDS else "triage"
            row_id = await record_event(
                db,
                tenant_id=tenant_id,
                subject_type="alert",
                subject_id=alert.id,
                stage=stage,
                kind="state_change",
                summary=f"{label}: {_render(old_value)} → {_render(new_value)}",
                status="recorded",
                actor_type="analyst",
                actor_id=actor_id,
                actor_label=actor_label,
                action_name=_action_for(field, new_value),
                input_payload={"field": field, "previous": _render(old_value)},
                output_payload={"field": field, "value": _render(new_value)},
                idempotency_key=None,
            )
            if row_id is not None:
                written += 1
        if written:
            await db.commit()
    except Exception as exc:  # noqa: BLE001 — bookkeeping must not fail the action
        await db.rollback()
        logger.warning(
            "runbook.emit.alert_update_failed",
            alert_id=str(getattr(alert, "id", "")),
            error_type=type(exc).__name__,
            error=str(exc).replace("\r", " ").replace("\n", " ")[:200],
        )
        return 0
    return written


async def emit_alert_escalation(
    db: AsyncSession,
    *,
    alert: Any,
    tenant_id: uuid.UUID,
    actor_id: str | None,
    actor_label: str | None,
    previous_severity: str | None,
) -> int:
    """Record a manual escalation (severity raised by an analyst)."""
    if previous_severity == alert.severity:
        return 0
    try:
        row_id = await record_event(
            db,
            tenant_id=tenant_id,
            subject_type="alert",
            subject_id=alert.id,
            stage="triage",
            kind="state_change",
            summary=f"Severity: {_render(previous_severity)} → {_render(alert.severity)}",
            detail="Manual escalation by an analyst.",
            status="recorded",
            actor_type="analyst",
            actor_id=actor_id,
            actor_label=actor_label,
            output_payload={"severity": alert.severity},
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — bookkeeping must not fail the action
        await db.rollback()
        logger.warning(
            "runbook.emit.escalation_failed",
            alert_id=str(getattr(alert, "id", "")),
            error_type=type(exc).__name__,
        )
        return 0
    return 1 if row_id is not None else 0


async def emit_case_created(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    case_title: str,
    alert_ids: list[str],
    actor_label: str = "agentic-funnel",
    severity: str | None = None,
    disposition: str | None = None,
    idempotency_key: str | None = None,
) -> int:
    """Record that a case was opened from a group of alerts.

    Defaults to the funnel's key so a retried backfill cannot append a second
    "Case opened" line; callers that legitimately open a second case for the
    same id (a different alert set) pass their own key.
    """
    try:
        row_id = await record_event(
            db,
            tenant_id=tenant_id,
            subject_type="case",
            subject_id=case_id,
            stage="funnel",
            kind="state_change",
            summary=(
                f"Case opened from {len(alert_ids)} alert(s)"
                + (f" · severity {severity}" if severity else "")
                + (f" · {disposition}" if disposition else "")
            ),
            detail=case_title[:4000] or None,
            status="recorded",
            actor_type="system",
            actor_label=actor_label,
            action_name="create_case",
            output_payload={"alert_ids": alert_ids[:50], "severity": severity, "disposition": disposition},
            idempotency_key=idempotency_key if idempotency_key is not None else f"case-created:{case_id}",
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — bookkeeping must not fail the funnel
        await db.rollback()
        logger.warning(
            "runbook.emit.case_created_failed",
            case_id=str(case_id),
            error_type=type(exc).__name__,
        )
        return 0
    return 1 if row_id is not None else 0


async def emit_itsm_status_change(
    db: AsyncSession,
    *,
    case_id: uuid.UUID,
    tenant_id: uuid.UUID,
    new_status: str,
    vendor: str,
    external_id: str,
    actor_label: str,
) -> int:
    """Record an inbound ITSM status transition applied to a case.

    Called by the webhook handler **after** its own commit, so the case row
    (the source of truth) is already durable: a failed ledger insert here is a
    reporting gap, never a 503 that makes the vendor retry a transition we
    already applied. This function therefore commits its own row and swallows
    its own errors.

    ``record_event`` runs its INSERT inside a SAVEPOINT, so a failure rolls
    back only the ledger row and leaves the session clean for the next use.
    """
    try:
        row_id = await record_event(
            db,
            tenant_id=tenant_id,
            subject_type="case",
            subject_id=case_id,
            stage="itsm",
            kind="action",
            summary=f"{vendor.title()} ticket {external_id}: case status → {new_status}",
            detail=f"Status mirrored from {vendor.title()} via inbound webhook by {actor_label}.",
            status="recorded",
            actor_type="system",
            actor_label=actor_label,
            output_payload={"status": new_status, "vendor": vendor, "external_id": external_id},
            idempotency_key=f"itsm:{case_id}:{external_id}:{new_status}",
        )
        if row_id is not None:
            await db.commit()
    except Exception as exc:  # noqa: BLE001 — bookkeeping must not fail the webhook
        logger.warning(
            "runbook.emit.itsm_status_failed",
            case_id=str(case_id),
            error_type=type(exc).__name__,
            error=str(exc).replace("\r", " ").replace("\n", " ")[:200],
        )
        await db.rollback()
        return 0
    return 1 if row_id is not None else 0
