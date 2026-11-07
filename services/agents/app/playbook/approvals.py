"""Approval-gate tasks for parked playbook runs.

When a playbook parks at an ``approval`` step, the analyst has to find it. That
means a row in ``runbook_tasks`` — the same table the Action Plan reads — that
names the run it belongs to, so approving the task can release *that* run.

Best-effort, like every other writer in this service: with no database the run
stays parked and the failure is logged. A gate must never depend on its own
bookkeeping.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from app.investigator.ledger import get_pool, resolve_tenant

from . import run_store

logger = logging.getLogger("aisoc.playbook.approvals")

__all__ = ["create_gate_task", "title_for"]


def title_for(run: Any) -> str:
    """Analyst-facing task title: playbook → gate step."""
    name = getattr(run, "playbook_name", "") or "playbook"
    gate = getattr(run, "gate_step_name", None) or "approval"
    title = f"Approve Playbook: {name} → {gate}"
    return title[:255]


def _alert_uuid(run: Any) -> uuid.UUID | None:
    ctx = getattr(run, "trigger_context", {}) or {}
    for key in ("alert_id", "id"):
        value = ctx.get(key)
        if not value:
            continue
        try:
            return uuid.UUID(str(value))
        except (TypeError, ValueError):
            continue
    return None


async def create_gate_task(run: Any, *, tenant_ref: str | None = None) -> str | None:
    """Create the Runbook task for a run parked at an approval gate.

    Returns the task id, or ``None`` when the surface is switched off, the
    database is unavailable, or an open task already exists for this run.
    """
    if not run_store.resume_enabled():
        logger.debug("playbook_gate.task_skipped", extra={"reason": "AISOC_PLAYBOOK_RESUME off"})
        return None

    pool = await get_pool()
    run_id = getattr(run, "run_id", None)
    if pool is None or not run_id:
        return None

    try:
        run_uuid = uuid.UUID(str(run_id))
    except (TypeError, ValueError):
        return None

    description = (
        f"Run {run_uuid} is paused at the approval step "
        f"'{getattr(run, 'gate_step_name', '') or 'approval'}'. "
        "Approving continues the playbook from the next step; rejecting ends the run "
        "as cancelled. Nothing after the gate has executed yet.\n\n"
        f"Playbook: {getattr(run, 'playbook_name', '')} ({getattr(run, 'playbook_id', '')})"
    )

    try:
        async with pool.acquire() as conn:
            tenant_id = await resolve_tenant(str(tenant_ref or getattr(run, "tenant_ref", "default")))
            if tenant_id is None:
                logger.warning("playbook_gate.unknown_tenant", extra={"run_id": str(run_uuid)})
                return None

            task_id = await conn.fetchval(
                """
                INSERT INTO runbook_tasks
                  (id, tenant_id, alert_id, task_type, title, description, status,
                   created_by, created_at, playbook_run_id)
                VALUES
                  (uuid_generate_v4(), $1, $2, 'approval_gate', $3, $4, 'pending',
                   'system', NOW(), $5)
                ON CONFLICT DO NOTHING
                RETURNING id
                """,
                uuid.UUID(tenant_id),
                _alert_uuid(run),
                title_for(run),
                description,
                run_uuid,
            )
    except Exception as exc:  # noqa: BLE001 — bookkeeping is best-effort
        logger.warning(
            "playbook_gate.task_failed",
            extra={"run_id": str(run_uuid), "error": str(exc)},
        )
        return None

    if task_id is None:
        # The partial unique index fired: an open task already exists for this run.
        logger.info("playbook_gate.task_exists", extra={"run_id": str(run_uuid)})
        return None

    logger.info("playbook_gate.task_created", extra={"run_id": str(run_uuid), "task_id": str(task_id)})
    return str(task_id)
