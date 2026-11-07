"""Release a parked playbook run (approve) or end it (reject).

Kept out of :mod:`app.api.playbooks` because it is the security-sensitive half of
the gate: it decides whether the guarded steps may execute, and it must refuse
anything that is not a live ``pending_approval`` run belonging to the caller.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from . import run_store
from .engine import PlaybookEngine, PlaybookRun, RunStatus
from .models import Playbook

logger = logging.getLogger("aisoc.playbook.resume")

__all__ = ["ResumeResult", "resume_run"]

Decision = Literal["approve", "reject"]


class ResumeResult(dict):
    """``{"status": ..., "resumed": bool, "detail"?: str}`` with a bounded shape."""


async def resume_run(
    row: dict[str, Any],
    *,
    decision: Decision,
    actor: str,
    tenant_ref: str,
) -> ResumeResult:
    """Apply an analyst decision to a persisted run row.

    ``row`` must already be scoped to ``tenant_ref`` by the caller (a run from
    another tenant is a 404, never a 403 — existence is not disclosed).
    """
    run_id = str(row.get("id"))
    status = str(row.get("status") or "")

    if status != RunStatus.PENDING_APPROVAL.value:
        return ResumeResult(status=status, resumed=False, detail=f"run is {status}")

    snapshot = row.get("playbook_snapshot") or {}
    try:
        playbook = Playbook.model_validate(snapshot)
    except Exception as exc:  # noqa: BLE001 — a corrupt snapshot must fail closed
        logger.warning("playbook_resume.bad_snapshot", extra={"run_id": run_id, "error": str(exc)})
        return ResumeResult(status=status, resumed=False, detail="playbook snapshot is unreadable")

    pr = PlaybookRun.from_state(
        playbook,
        run_id=run_id,
        trigger_context=row.get("trigger_context") or {},
        context=row.get("context") or {},
        step_results=row.get("step_results") or [],
        status=RunStatus.PENDING_APPROVAL,
        next_step_index=row.get("next_step_index"),
        gate_step_id=row.get("gate_step_id"),
        gate_step_name=row.get("gate_step_name"),
        started_at=row.get("started_at") or "",
        error=row.get("error"),
        tenant_ref=tenant_ref,
    )

    engine = PlaybookEngine()
    await run_store.mark_decided(run_id, tenant_ref, actor=actor, decision=decision)

    if decision == "reject":
        reason = f"rejected by {actor}"
        await engine.cancel(pr, actor=actor, reason=reason)
        logger.info("playbook_resume.rejected", extra={"run_id": run_id, "actor": actor})
        return ResumeResult(status=pr.status.value, resumed=False)

    try:
        await engine.resume(pr, playbook, actor=actor)
    except ValueError as exc:
        # Status changed underneath us (a concurrent approve won the race).
        return ResumeResult(status=status, resumed=False, detail=str(exc))

    logger.info(
        "playbook_resume.approved",
        extra={"run_id": run_id, "actor": actor, "status": pr.status.value},
    )
    return ResumeResult(status=pr.status.value, resumed=pr.gate_released, error=pr.error)
