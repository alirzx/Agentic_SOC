"""Write one governed step into the Runbook ledger (``runbook_events``).

Everything that happens to an alert / case / incident goes through
:func:`record_event`. The ledger is append-only (enforced by a trigger, see
migration 062), so a writer only ever inserts — there is no update path and no
delete path anywhere in this module.

Three properties the writer guarantees
-------------------------------------
* **Idempotent.** A caller that retries with the same ``idempotency_key`` gets
  ``None`` back instead of a duplicate step. That is what makes it safe to call
  from a Kafka consumer's at-least-once path.
* **Monotonic ``seq``.** Sequence numbers are allocated per
  ``(tenant, subject_type, subject_id)`` inside the INSERT itself, with a
  savepoint retry for the rare concurrent-writer collision. The unique
  constraint is the backstop, not the strategy.
* **Sanitised.** Free text is stripped of control characters and capped before
  it reaches the database, so a hostile event body cannot forge ledger lines or
  blow up a row.

What this module deliberately does **not** do
---------------------------------------------
It does not write ``audit_log``. ``AuditContract.audit_log`` is part of an
action's definition, and the writer that honours it is the action executor —
which does not exist yet (execute paths still live in the playbook engine and
the actions service). ``runbook_events.audit_log_id`` therefore stays NULL until
an executor adopts this contract; claiming otherwise would make compliance
believe a hash-chained record exists when it does not.

It also does not read ``settings`` for the feature flag at import time: callers
that must be silent when the Runbook is off get that from
:func:`record_event`'s own check, which reads the flag per call.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import runbook_enabled
from app.services.runbook.contracts import DataSafetyContract
from app.services.runbook.gate import GateDecision

logger = structlog.get_logger()

__all__ = [
    "SUBJECT_TYPES",
    "STATUSES",
    "ACTOR_TYPES",
    "record_event",
    "record_policy_decision",
    "allocate_next_seq",
    "find_by_idempotency_key",
]

SUBJECT_TYPES = ("alert", "case", "incident")
STATUSES = ("recorded", "allowed", "denied", "executed", "simulated", "failed", "skipped")
ACTOR_TYPES = ("system", "agent", "analyst", "connector")

# How many times to retry a seq collision before giving up. Three is generous:
# each collision means another writer landed on the exact same subject within
# microseconds, and the unique index is the final arbiter.
_SEQ_ATTEMPTS = 3

_MAX_SUMMARY = 1000
_MAX_DETAIL = 8000
_MAX_ERROR = 2000

_INSERT = text(
    """
    INSERT INTO runbook_events (
        id, tenant_id, subject_type, subject_id, seq, occurred_at,
        stage, kind, action_name, actor_type, actor_id, actor_label,
        summary, detail, status, policy, approval_id, run_id,
        input, output, cost, error, duration_ms, audit_log_id,
        idempotency_key, created_at
    )
    SELECT
        :id, :tenant_id, :subject_type, :subject_id,
        COALESCE(MAX(seq), 0) + 1, :occurred_at,
        :stage, :kind, :action_name, :actor_type, :actor_id, :actor_label,
        :summary, :detail, :status,
        CAST(:policy AS JSONB), :approval_id, :run_id,
        CAST(:input AS JSONB), CAST(:output AS JSONB), CAST(:cost AS JSONB),
        :error, :duration_ms, :audit_log_id,
        :idempotency_key, :created_at
      FROM runbook_events
     WHERE tenant_id = :filter_tenant_id
       AND subject_type = :filter_subject_type
       AND subject_id = :filter_subject_id
    ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL
    DO NOTHING
    """
)

_SELECT_BY_IDEMPOTENCY = text(
    """
    SELECT id FROM runbook_events
     WHERE tenant_id = :tenant_id AND idempotency_key = :idempotency_key
     LIMIT 1
    """
)


def _clean(value: str | None, *, limit: int) -> str | None:
    """Strip control characters and cap length before it reaches the database."""
    if value is None:
        return None
    text_value = str(value).replace("\r", " ").replace("\n", " ").replace("\x00", "")
    text_value = " ".join(text_value.split())
    if not text_value:
        return None
    return text_value[:limit]


def _clean_multiline(value: str | None, *, limit: int) -> str | None:
    """Like :func:`_clean` but keeps newlines (detail bodies are readable prose)."""
    if value is None:
        return None
    text_value = str(value).replace("\x00", "").strip()
    if not text_value:
        return None
    return text_value[:limit]


def _validate(*, subject_type: str, status: str, actor_type: str, stage: str, kind: str) -> None:
    if subject_type not in SUBJECT_TYPES:
        raise ValueError(f"subject_type must be one of {SUBJECT_TYPES}, got {subject_type!r}")
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}, got {status!r}")
    if actor_type not in ACTOR_TYPES:
        raise ValueError(f"actor_type must be one of {ACTOR_TYPES}, got {actor_type!r}")
    if not (stage or "").strip():
        raise ValueError("stage is required")
    if not (kind or "").strip():
        raise ValueError("kind is required")


async def allocate_next_seq(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID,
) -> int:
    """Next free sequence number for a subject (read-only helper).

    ``record_event`` allocates inside its INSERT instead of calling this; the
    helper exists for callers that need to know the number ahead of time (and
    for tests). It is advisory: another writer may take the same value, which is
    why nothing should *rely* on it for ordering guarantees.
    """
    row = (
        await db.execute(
            text(
                """
                SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq
                  FROM runbook_events
                 WHERE tenant_id = :tenant_id
                   AND subject_type = :subject_type
                   AND subject_id = :subject_id
                """
            ).bindparams(tenant_id=tenant_id, subject_type=subject_type, subject_id=subject_id)
        )
    ).scalar_one()
    return int(row)


async def record_event(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID,
    stage: str,
    kind: str,
    summary: str,
    status: str = "recorded",
    actor_type: str = "system",
    actor_id: str | None = None,
    actor_label: str | None = None,
    detail: str | None = None,
    action_name: str | None = None,
    policy: dict[str, Any] | None = None,
    approval_id: uuid.UUID | None = None,
    run_id: uuid.UUID | None = None,
    input_payload: Any = None,
    output_payload: Any = None,
    cost: dict[str, Any] | None = None,
    error: str | None = None,
    duration_ms: int | None = None,
    audit_log_id: uuid.UUID | None = None,
    idempotency_key: str | None = None,
    occurred_at: datetime | None = None,
    data_contract: DataSafetyContract | None = None,
) -> uuid.UUID | None:
    """Append one ledger row.

    Returns the new row id, or ``None`` when nothing was written — because the
    Runbook is disabled for this deployment, or because ``idempotency_key`` was
    already recorded.
    """
    if not runbook_enabled():
        return None

    _validate(subject_type=subject_type, status=status, actor_type=actor_type, stage=stage, kind=kind)

    cleaned_summary = _clean(summary, limit=_MAX_SUMMARY)
    if not cleaned_summary:
        raise ValueError("summary must not be empty")

    contract = data_contract or DataSafetyContract()
    safe_input = contract.sanitize(input_payload) if isinstance(input_payload, dict) else None
    safe_output = contract.sanitize(output_payload) if isinstance(output_payload, dict) else None

    row_id = uuid.uuid4()
    now = occurred_at or datetime.now(UTC)

    params = {
        "id": row_id,
        "tenant_id": tenant_id,
        "subject_type": subject_type,
        "subject_id": subject_id,
        # The INSERT target list and the WHERE clause need separate parameters:
        # Postgres deduces a parameter's type once and refuses to reconcile the
        # ``text`` it infers for a bare SELECT column with the ``varchar`` it
        # infers for the same parameter compared against the column
        # (``AmbiguousParameterError: inconsistent types deduced for $3``).
        "filter_tenant_id": tenant_id,
        "filter_subject_type": subject_type,
        "filter_subject_id": subject_id,
        "occurred_at": now,
        "stage": stage[:32],
        "kind": kind[:32],
        "action_name": str(action_name)[:64] if action_name else None,
        "actor_type": actor_type,
        "actor_id": (str(actor_id)[:200] if actor_id else None),
        "actor_label": (str(actor_label)[:200] if actor_label else None),
        "summary": cleaned_summary,
        "detail": _clean_multiline(detail, limit=_MAX_DETAIL),
        "status": status,
        "policy": _json(policy) if policy is not None else None,
        "approval_id": approval_id,
        "run_id": run_id,
        "input": _json(safe_input) if safe_input is not None else None,
        "output": _json(safe_output) if safe_output is not None else None,
        "cost": _json(cost) if cost is not None else None,
        "error": _clean(error, limit=_MAX_ERROR),
        "duration_ms": duration_ms,
        "audit_log_id": audit_log_id,
        "idempotency_key": (str(idempotency_key)[:128] if idempotency_key else None),
        "created_at": datetime.now(UTC),
    }

    for attempt in range(1, _SEQ_ATTEMPTS + 1):
        try:
            async with db.begin_nested():
                result = await db.execute(_INSERT, params)
            if (result.rowcount or 0) == 0:
                logger.info(
                    "runbook.record.duplicate_ignored",
                    subject_type=subject_type,
                    stage=str(stage)[:32],
                )
                return None
            return row_id
        except IntegrityError:
            # Either the idempotency index (should be swallowed by DO NOTHING,
            # so this is the seq race) or a genuine constraint breach. Only the
            # seq race is worth retrying.
            if attempt >= _SEQ_ATTEMPTS:
                raise
            logger.warning(
                "runbook.record.seq_race_retry",
                subject_type=subject_type,
                attempt=attempt,
            )

    # Unreachable: the loop either returns or raises.
    raise RuntimeError("runbook.record_event exhausted its retry budget")


def _json(payload: Any) -> str | None:
    """Serialise for a JSONB bind parameter; ``None`` stays ``None``."""
    if payload is None:
        return None
    return json.dumps(payload, default=str, ensure_ascii=False)


async def record_policy_decision(
    db: AsyncSession,
    decision: GateDecision,
    *,
    tenant_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID,
    stage: str = "policy",
    idempotency_key: str | None = None,
) -> uuid.UUID | None:
    """Persist a gate decision as a ``kind='policy'`` ledger row.

    Recording the decision is what makes "why was this allowed?" answerable
    later: ``policy_snapshot()`` carries the layer that won, the thresholds that
    were in force, and the resulting autonomy level.
    """
    return await record_event(
        db,
        tenant_id=tenant_id,
        subject_type=subject_type,
        subject_id=subject_id,
        stage=stage,
        kind="policy",
        summary=f"{decision.action}: {decision.decision.value}",
        detail=decision.reason,
        status="allowed" if decision.allowed else "denied",
        actor_type="system",
        actor_label="runbook-gate",
        action_name=decision.action,
        policy=decision.policy_snapshot(),
        idempotency_key=idempotency_key,
    )


async def find_by_idempotency_key(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    idempotency_key: str,
) -> uuid.UUID | None:
    """Row id previously recorded under ``idempotency_key``, if any."""
    row = (
        await db.execute(
            _SELECT_BY_IDEMPOTENCY.bindparams(tenant_id=tenant_id, idempotency_key=idempotency_key[:128])
        )
    ).first()
    return row[0] if row else None
