"""Creation-time automation-rule evaluator.

Automation rules used to be evaluated only from the alert API — ``POST
/api/v1/alerts`` and ``PATCH /api/v1/alerts/{id}``. The alerts that matter in
production never take that path: fusion's ``AlertSink`` inserts
connector-ingested alerts straight into Postgres, so a rule only ever fired for
a hand-submitted (or demo-seeded) alert. The rule engine was, in practice,
disconnected from the telemetry spine.

This worker closes that gap without moving rule execution. It claims alerts
whose ``automation_rules_evaluated_at`` is NULL — the marker added in migration
073, left NULL by both fusion and the API — and runs the ``alert.created`` rules
for them through the same ``run_rules_for_trigger`` the API uses. Rule coverage
therefore depends on "an alert exists", not on which code path created it.

Why a database queue instead of a Kafka consumer
------------------------------------------------
Rules, the governance gate, the ledger and the task queue all live in this
service. A consumer would still need a durable per-alert marker to avoid
evaluating twice (Kafka is at-least-once, and a rebalance replays), so the
marker is required either way; with it, a poller also covers alerts created
while the API was down and needs no new dependency in the API process.

One evaluation per alert, or none
---------------------------------
The claim is an atomic ``UPDATE ... RETURNING`` (``FOR UPDATE SKIP LOCKED``), so
two replicas cannot both evaluate an alert, and the marker is set *before* the
evaluation runs. If the process dies between claim and evaluation, that alert's
creation-time rules are skipped rather than executed twice — a deliberate choice:
a duplicated containment action is worse than a missed passive rule, and the
``PATCH`` path re-evaluates rules on the next analyst update. Re-queue one alert
deliberately with:

    UPDATE alerts SET automation_rules_evaluated_at = NULL WHERE id = '<alert>';

Failure model
-------------
* An exception on one alert is logged with its id and tenant and does not stop
  the pass; the alert is already claimed, so it cannot hot-loop.
* A database outage is caught per pass and retried after the normal interval.
* Cancellation (ASGI shutdown) propagates through ``CancelledError``.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import runbook_enabled, settings
from app.db.database import AsyncSessionLocal
from app.db.rls import set_session_rls_context
from app.models.alert import Alert
from app.services.runbook.rule_executor import alert_subject_fields, run_rules_for_trigger

logger = structlog.get_logger()

__all__ = ["claim_pending_alerts", "evaluate_alert", "evaluate_pending", "run_forever"]

#: Queue claim. ``SKIP LOCKED`` keeps two replicas from contending on the same
#: rows; the marker is written by this statement, so the claim *is* the
#: de-duplication.
_CLAIM_PENDING = text(
    """
    UPDATE alerts
       SET automation_rules_evaluated_at = now()
     WHERE id IN (
             SELECT id
               FROM alerts
              WHERE automation_rules_evaluated_at IS NULL
              ORDER BY created_at ASC
              LIMIT :batch
                FOR UPDATE SKIP LOCKED
           )
    RETURNING id, tenant_id
    """
)


async def claim_pending_alerts(
    db: AsyncSession,
    *,
    batch_size: int | None = None,
) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Mark up to ``batch_size`` unevaluated alerts as claimed and return them.

    Returns ``[(alert_id, tenant_id), ...]``. The caller owns the promise that
    each returned id is evaluated; the rows are already stamped, so a second
    claim will not see them.
    """
    # ``batch_size or default`` would turn an explicit 0 into the default; a
    # disabled batch has to stay disabled.
    batch = int(settings.RULE_EVALUATOR_BATCH_SIZE if batch_size is None else batch_size)
    if batch <= 0:
        return []
    rows = (await db.execute(_CLAIM_PENDING.bindparams(batch=batch))).fetchall()
    await db.commit()
    return [(row[0], row[1]) for row in rows]


async def evaluate_alert(
    *,
    alert_id: uuid.UUID,
    tenant_id: uuid.UUID,
    trigger_type: str = "alert.created",
) -> bool:
    """Run automation rules for one alert. Never raises.

    ``trigger_type`` defaults to ``alert.created`` (this worker's own job). The
    alert API passes ``alert.updated`` so an in-place edit re-evaluates through
    exactly the same code — the two paths must not drift the way the rule
    preview panel once did.

    A dedicated session per call because the rule executor commits (an approval
    gate task commits its own row), and the tenant GUC has to survive those
    commits — see :func:`app.db.rls.set_session_rls_context`.
    """
    try:
        async with AsyncSessionLocal() as db:
            # ``automation_rules`` and ``runbook_tasks`` RLS policies have no
            # NULL-tenant escape, so without this the executor would find zero
            # rules for the tenant and silently do nothing.
            await set_session_rls_context(db, tenant_id)

            alert = (
                await db.execute(
                    select(Alert).where(
                        Alert.id == alert_id,
                        Alert.tenant_id == tenant_id,
                    )
                )
            ).scalar_one_or_none()
            if alert is None:
                # Deleted between claim and evaluation — nothing to evaluate.
                logger.info(
                    "rule_evaluator.alert_missing",
                    alert_id=str(alert_id),
                )
                return False

            await run_rules_for_trigger(
                db,
                tenant_id=tenant_id,
                trigger_type=trigger_type,
                subject_type="alert",
                subject_id=alert_id,
                # One definition shared with the preview endpoints and the
                # request path; a second inline copy is how the test panel
                # drifted from the executor.
                subject_fields=alert_subject_fields(alert),
            )
            # ``run_rules_for_trigger`` writes ledger rows and rule counters but
            # does not commit; the request path relied on the session teardown,
            # which is exactly the bug this worker replaces.
            await db.commit()
        return True
    except Exception as exc:  # noqa: BLE001 — one alert must not stop the pass
        logger.warning(
            "rule_evaluator.alert_failed",
            alert_id=str(alert_id),
            tenant_id=str(tenant_id),
            trigger=trigger_type,
            error_type=type(exc).__name__,
            error=str(exc).replace("\r", " ").replace("\n", " ")[:200],
        )
        return False


async def evaluate_pending(*, batch_size: int | None = None) -> dict[str, Any]:
    """Claim and evaluate one batch. Returns a small report for logs and tests."""
    claimed: list[tuple[uuid.UUID, uuid.UUID]] = []
    try:
        async with AsyncSessionLocal() as db:
            claimed = await claim_pending_alerts(db, batch_size=batch_size)
    except Exception as exc:  # noqa: BLE001 — a DB outage is retried next pass
        logger.warning(
            "rule_evaluator.claim_failed",
            error_type=type(exc).__name__,
            error=str(exc).replace("\r", " ").replace("\n", " ")[:200],
        )
        return {"claimed": 0, "evaluated": 0, "failed": 0}

    evaluated = 0
    for alert_id, tenant_id in claimed:
        if await evaluate_alert(alert_id=alert_id, tenant_id=tenant_id):
            evaluated += 1

    return {
        "claimed": len(claimed),
        "evaluated": evaluated,
        "failed": len(claimed) - evaluated,
    }


def _disabled_reason() -> str | None:
    """Why the worker should not run in this process, or ``None`` if it should."""
    if not settings.RULE_EVALUATOR_ENABLED:
        return "disabled_by_configuration"
    if not runbook_enabled():
        # The ledger writer is a no-op without the Runbook, so evaluating rules
        # would burn queries to produce rows nobody can read.
        return "runbook_disabled"
    if not (os.getenv("DATABASE_URL") or "").strip():
        return "no_database_url"
    return None


async def run_forever() -> None:
    """Poll for unevaluated alerts until cancelled."""
    reason = _disabled_reason()
    if reason is not None:
        logger.info("rule_evaluator idle", reason=reason)
        return

    interval_seconds = max(1, int(settings.RULE_EVALUATOR_INTERVAL_SECONDS))
    logger.info(
        "rule_evaluator starting",
        interval_seconds=interval_seconds,
        batch_size=int(settings.RULE_EVALUATOR_BATCH_SIZE),
    )

    while True:
        try:
            report = await evaluate_pending()
            if report["claimed"]:
                logger.info("rule_evaluator pass", **report)
        except asyncio.CancelledError:
            logger.info("rule_evaluator cancelled during shutdown")
            raise
        except Exception as exc:  # noqa: BLE001 — never die on one bad pass
            logger.exception(
                "rule_evaluator pass_failed",
                error_type=type(exc).__name__,
                detail=str(exc)[:200],
            )

        await asyncio.sleep(interval_seconds)
