"""Runbook task creation helpers (exception / HITL queue).

One responsibility: when a governed action is blocked, make sure exactly one
pending approval task exists for it.

Two rules this module follows
-----------------------------
1. **Idempotent.** A blocked action is re-evaluated on every alert update, so the
   insert must not fan out into duplicate queue items. The partial unique index
   ``uq_runbook_tasks_open_gate`` (migration 065) plus ``ON CONFLICT DO NOTHING``
   makes that a database guarantee, not a read-then-write race.
2. **Never break the caller.** Task creation is bookkeeping on the alert write
   path; a failure is logged and reported as ``False``, never raised.
"""

from __future__ import annotations

import uuid

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger()

#: Task types this module can create. ``mssp_sla_check`` is intentionally
#: absent: no tenant-facing SLA source exists yet, so creating that task would
#: be inventing a deadline.
APPROVAL_GATE = "approval_gate"


async def ensure_approval_gate_task(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID | None,
    action_name: str,
    autonomy_level: str,
    reason: str,
) -> bool:
    """Create an approval task for a blocked action. Returns True if inserted.

    ``title`` carries the action slug so the partial unique index treats two
    different blocked actions on the same alert as two distinct tasks, while a
    repeat evaluation of the same action collapses onto the open one.
    """
    title = f"Approve Action: {action_name}"[:255]
    description = (
        f"AI recommends '{action_name}' but the effective autonomy level is "
        f"{autonomy_level}, so it cannot run without an analyst decision. "
        f"Gate reason: {reason}"
    )[:4000]

    try:
        inserted = await db.execute(
            text(
                """
                INSERT INTO runbook_tasks
                  (id, tenant_id, alert_id, task_type, title, description,
                   status, created_by, created_at)
                VALUES
                  (:id, :tid, :aid, 'approval_gate', :title, :desc,
                   'pending', 'system', now())
                ON CONFLICT DO NOTHING
                """
            ).bindparams(
                id=uuid.uuid4(),
                tid=tenant_id,
                aid=alert_id,
                title=title,
                desc=description,
            )
        )
    except Exception as exc:  # noqa: BLE001 — bookkeeping must not break the caller
        logger.warning(
            "runbook.approval_task_failed",
            action=str(action_name).replace("\r", "").replace("\n", " ")[:120],
            error=str(exc),
        )
        return False

    created = bool(inserted.rowcount)
    logger.info(
        "runbook.approval_task",
        action=str(action_name).replace("\r", "").replace("\n", " ")[:120],
        autonomy_level=autonomy_level,
        created=created,
    )
    return created
