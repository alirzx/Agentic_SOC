"""Durable storage for playbook runs.

A playbook that reaches an ``approval`` step parks (``pending_approval``) and
can wait hours for a human. Before this module those runs only existed in the
agents process's in-memory ``_runs`` dict, so a deploy — or simply a different
worker — forgot them and the analyst's approval had nothing to release.

Storage lives in Postgres next to every other per-tenant row. Writes are
best-effort in the same way as :mod:`app.investigator.ledger`: a missing
``DATABASE_URL`` or an unmigrated database logs and returns ``False``, and the
run keeps working in memory. A gate must never fail because its bookkeeping did.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

from app.investigator.ledger import get_pool, resolve_tenant

logger = logging.getLogger("aisoc.playbook.run_store")

__all__ = [
    "persist_run",
    "load_run",
    "list_runs",
    "find_run_by_dedupe",
    "mark_decided",
    "prune_payloads",
    "resume_enabled",
]

_TRUE = {"1", "true", "yes", "on"}


def resume_enabled() -> bool:
    """Whether the approval-resume surface is switched on for this process.

    Default **off**. With it off no gate task is created and no resume call is
    accepted, which is exactly the pre-Phase-12 behaviour: the run parks and
    nothing pretends it can continue.
    """
    return os.environ.get("AISOC_PLAYBOOK_RESUME", "").strip().lower() in _TRUE


def _json(value: Any) -> str:
    return json.dumps(value, default=str)


def _coerce_uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


async def _tenant_uuid(tenant_ref: str) -> uuid.UUID | None:
    # One argument, never a connection: ``resolve_tenant`` opens its own pool
    # entry. Three call sites used to pass ``conn`` here as well, which raised
    # ``TypeError`` — swallowed by each caller's best-effort handler, so
    # ``load_run`` / ``mark_decided`` / ``prune_payloads`` silently answered
    # "not found" on every call and an approval could never resume its run.
    canonical = await resolve_tenant(tenant_ref)
    return uuid.UUID(canonical) if canonical is not None else None


async def persist_run(run: Any, *, tenant_ref: str | None = None) -> bool:
    """Upsert the current state of ``run`` (a :class:`PlaybookRun`).

    Called at three boundaries only — run start, gate reached, terminal state —
    so the hot loop pays no extra round trip per step.
    """
    pool = await get_pool()
    if pool is None:
        return False

    run_uuid = _coerce_uuid(getattr(run, "run_id", None))
    if run_uuid is None:
        return False

    ref = tenant_ref or getattr(run, "tenant_ref", None) or "default"
    status = getattr(run.status, "value", str(run.status))

    try:
        async with pool.acquire() as conn:
            tenant_id = await _tenant_uuid(str(ref))
            if tenant_id is None:
                logger.warning("playbook_run.persist_skipped", extra={"reason": "unknown tenant", "run_id": str(run_uuid)})
                return False

            await conn.execute(
                """
                INSERT INTO playbook_runs
                  (id, tenant_id, playbook_id, playbook_name, playbook_snapshot,
                   status, trigger_context, context, step_results, next_step_index,
                   gate_step_id, gate_step_name, error, started_at, finished_at,
                   created_at, updated_at)
                VALUES
                  ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8::jsonb, $9::jsonb,
                   $10, $11, $12, $13, $14, $15, NOW(), NOW())
                ON CONFLICT (id) DO UPDATE SET
                    status          = EXCLUDED.status,
                    context         = EXCLUDED.context,
                    step_results    = EXCLUDED.step_results,
                    next_step_index = EXCLUDED.next_step_index,
                    gate_step_id    = EXCLUDED.gate_step_id,
                    gate_step_name  = EXCLUDED.gate_step_name,
                    error           = EXCLUDED.error,
                    finished_at     = EXCLUDED.finished_at,
                    updated_at      = NOW()
                """,
                run_uuid,
                tenant_id,
                str(getattr(run, "playbook_id", "")),
                str(getattr(run, "playbook_name", "")),
                _json(getattr(run, "playbook_snapshot", {}) or {}),
                status,
                _json(getattr(run, "trigger_context", {}) or {}),
                _json(getattr(run, "context", {}) or {}),
                _json(getattr(run, "step_results", []) or []),
                getattr(run, "next_step_index", None),
                getattr(run, "gate_step_id", None),
                getattr(run, "gate_step_name", None),
                getattr(run, "error", None),
                _coerce_datetime(getattr(run, "started_at", None)),
                _coerce_datetime(getattr(run, "finished_at", None)),
            )
        return True
    except Exception as exc:  # noqa: BLE001 — bookkeeping is best-effort
        logger.warning(
            "playbook_run.persist_failed",
            extra={"run_id": str(run_uuid), "status": status, "error": str(exc)},
        )
        return False


def _coerce_datetime(value: Any) -> Any:
    """Run timestamps are ISO strings; asyncpg wants a datetime or None."""
    if not value:
        return None
    if isinstance(value, str):
        from datetime import datetime  # noqa: PLC0415

        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return value


async def load_run(run_id: str, tenant_ref: str) -> dict[str, Any] | None:
    """Load a run row scoped to ``tenant_ref``. ``None`` ⇒ not found (or other tenant)."""
    pool = await get_pool()
    run_uuid = _coerce_uuid(run_id)
    if pool is None or run_uuid is None:
        return None

    try:
        async with pool.acquire() as conn:
            tenant_id = await _tenant_uuid(str(tenant_ref))
            if tenant_id is None:
                return None
            row = await conn.fetchrow(
                """
                SELECT id, tenant_id, playbook_id, playbook_name, playbook_snapshot,
                       status, trigger_context, context, step_results, next_step_index,
                       gate_step_id, gate_step_name, actor, decided_at, error,
                       started_at, finished_at, payloads_pruned_at
                  FROM playbook_runs
                 WHERE id = $1 AND tenant_id = $2
                """,
                run_uuid,
                tenant_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_run.load_failed", extra={"run_id": str(run_uuid), "error": str(exc)})
        return None

    return _row_to_dict(row) if row is not None else None


def _row_to_dict(row: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in dict(row).items():
        if isinstance(value, uuid.UUID):
            out[key] = str(value)
        elif hasattr(value, "isoformat"):
            out[key] = value.isoformat()
        else:
            out[key] = value
    for blob in ("playbook_snapshot", "trigger_context", "context", "step_results"):
        if isinstance(out.get(blob), str):
            try:
                out[blob] = json.loads(out[blob])
            except (TypeError, ValueError):
                out[blob] = None if blob == "playbook_snapshot" else ([] if blob == "step_results" else {})
    return out


async def list_runs(tenant_ref: str, limit: int = 50) -> list[dict[str, Any]]:
    """Recent durable runs for a tenant, newest first.

    Run History reads this so a parked run stays visible after the worker that
    started it is gone. Returns ``[]`` when the store is unavailable.
    """
    pool = await get_pool()
    if pool is None:
        return []

    try:
        async with pool.acquire() as conn:
            tenant_id = await _tenant_uuid(str(tenant_ref))
            if tenant_id is None:
                return []
            rows = await conn.fetch(
                """
                SELECT id, tenant_id, playbook_id, playbook_name, playbook_snapshot,
                       status, trigger_context, context, step_results, next_step_index,
                       gate_step_id, gate_step_name, actor, decided_at, error,
                       started_at, finished_at, payloads_pruned_at
                  FROM playbook_runs
                 WHERE tenant_id = $1
                 ORDER BY created_at DESC
                 LIMIT $2
                """,
                tenant_id,
                max(1, min(int(limit), 200)),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_run.list_failed", extra={"error": str(exc)})
        return []

    return [_row_to_dict(r) for r in rows]


async def find_run_by_dedupe(tenant_ref: str, playbook_id: str, dedupe_key: str) -> str | None:
    """Id of an earlier run started under ``dedupe_key``, or ``None``.

    Automation rules re-evaluate a subject on every alert update, so the
    control-plane API stamps each start with a stable key
    (``automation:<rule>:<playbook>:<subject>``). Without a check here one
    update storm would fire the same playbook dozens of times.

    Best-effort by convention: a store that cannot answer returns ``None`` and
    the caller starts a fresh run. The API's ledger ``idempotency_key`` is the
    authoritative dedupe; this lookup is the second belt, closing the window
    between that check and the HTTP call.
    """
    if not dedupe_key or not playbook_id:
        return None
    pool = await get_pool()
    if pool is None:
        return None

    try:
        async with pool.acquire() as conn:
            tenant_id = await _tenant_uuid(str(tenant_ref))
            if tenant_id is None:
                return None
            run_id = await conn.fetchval(
                """
                SELECT id
                  FROM playbook_runs
                 WHERE tenant_id = $1
                   AND playbook_id = $2
                   AND trigger_context->>'dedupe_key' = $3
                 ORDER BY created_at DESC
                 LIMIT 1
                """,
                tenant_id,
                str(playbook_id),
                str(dedupe_key),
            )
    except Exception as exc:  # noqa: BLE001 — best-effort, like every other read
        logger.warning(
            "playbook_run.dedupe_lookup_failed",
            extra={
                "playbook_id": str(playbook_id).replace("\r", " ").replace("\n", " ")[:128],
                "error": str(exc),
            },
        )
        return None

    return str(run_id) if run_id else None


async def mark_decided(run_id: str, tenant_ref: str, *, actor: str, decision: str) -> bool:
    """Record who decided a gate, without executing anything.

    Used for ``reject`` (the run ends as ``cancelled``) and for the approve path
    so the audit trail names the person even if the resume itself fails.
    """
    pool = await get_pool()
    run_uuid = _coerce_uuid(run_id)
    if pool is None or run_uuid is None:
        return False

    try:
        async with pool.acquire() as conn:
            tenant_id = await _tenant_uuid(str(tenant_ref))
            if tenant_id is None:
                return False
            await conn.execute(
                """
                UPDATE playbook_runs
                   SET actor = $3, decided_at = NOW(), updated_at = NOW()
                 WHERE id = $1 AND tenant_id = $2
                """,
                run_uuid,
                tenant_id,
                f"{actor}:{decision}",
            )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_run.decide_failed", extra={"run_id": str(run_uuid), "error": str(exc)})
        return False


async def prune_payloads(older_than_days: int = 90, *, tenant_ref: str | None = None) -> int:
    """Drop the heavy JSONB payloads of old terminal runs, keeping the metadata.

    Retention decision (Phase 12): the row — who approved what, when, and how it
    ended — is audit value and stays. ``playbook_snapshot`` / ``context`` /
    ``step_results`` are bulk and only matter while a run can still be resumed,
    so they are cleared after the window. Parked runs are never pruned: they are
    still waiting on a human.
    """
    pool = await get_pool()
    if pool is None:
        return 0

    try:
        async with pool.acquire() as conn:
            tenant_id: uuid.UUID | None = None
            if tenant_ref:
                tenant_id = await _tenant_uuid(str(tenant_ref))
                if tenant_id is None:
                    return 0
            result = await conn.execute(
                """
                UPDATE playbook_runs
                   SET playbook_snapshot = '{}'::jsonb,
                       context           = '{}'::jsonb,
                       step_results      = '[]'::jsonb,
                       payloads_pruned_at = NOW(),
                       updated_at        = NOW()
                 WHERE payloads_pruned_at IS NULL
                   AND finished_at IS NOT NULL
                   AND status <> 'pending_approval'
                   AND finished_at < NOW() - ($1::text || ' days')::interval
                   AND ($2::uuid IS NULL OR tenant_id = $2)
                """,
                int(older_than_days),
                tenant_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_run.prune_failed", extra={"error": str(exc)})
        return 0

    try:
        return int(str(result).split()[-1])
    except (ValueError, IndexError):
        return 0
