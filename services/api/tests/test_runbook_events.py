"""Integration tests for the append-only Runbook ledger (migration 062).

Needs a real Postgres: the guarantees under test are database guarantees
(``seq`` allocation, the partial unique idempotency index, the immutability
trigger, row-level security), and an in-memory database would happily prove
nothing about them.

Gated behind ``pytest.mark.integration`` so a developer machine without
Postgres still gets a green unit run. Execute with:

    AISOC_RUN_INTEGRATION=1 pytest -m integration tests/test_runbook_events.py

Every test runs inside one transaction that is rolled back at the end: the
ledger is append-only, so a test that committed could never clean up after
itself.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Awaitable, Callable

import pytest
import structlog
from app.db.database import AsyncSessionLocal

pytestmark = pytest.mark.integration

_REQUIRES_ENV = "AISOC_RUN_INTEGRATION"

log = structlog.get_logger()


def _skip_unless_enabled() -> None:
    if not os.getenv(_REQUIRES_ENV):
        pytest.skip(f"set {_REQUIRES_ENV}=1 to run the ledger tests against Postgres")


class _RollbackSession:
    """Async context manager yielding a session whose work is always rolled back."""

    _requires_env = _REQUIRES_ENV

    def __init__(self) -> None:
        self.session = None

    async def __aenter__(self):
        self.session = AsyncSessionLocal()
        return await self.session.__aenter__()

    async def __aexit__(self, *exc_info):
        assert self.session is not None
        try:
            await self.session.rollback()
        finally:
            await self.session.__aexit__(*exc_info)


def _run(coro: Callable[[], Awaitable[object]]) -> object:
    """Run ``coro`` on a private event loop, then drop the pooled sockets.

    The SQLAlchemy engine in :mod:`app.db.database` is process-global and its
    asyncpg connections are bound to the loop that opened them. Without the
    ``dispose()`` below the second test's ``asyncio.run`` reuses sockets owned
    by the first, already-closed loop and fails with "Event loop is closed"
    before the assertion under test is ever reached.
    """

    from app.db.database import engine

    async def _wrapped():
        try:
            return await coro
        finally:
            await engine.dispose()

    return asyncio.run(_wrapped())


# ─── Sequence + idempotency ──────────────────────────────────────────────────


def test_seq_is_monotonic_per_subject() -> None:
    _skip_unless_enabled()

    from app.services.runbook.recorder import record_event

    tenant = uuid.uuid4()
    alert = uuid.uuid4()

    async def run() -> list[int]:
        from sqlalchemy import text

        async with _RollbackSession() as db:
            for index in range(3):
                await record_event(
                    db,
                    tenant_id=tenant,
                    subject_type="alert",
                    subject_id=alert,
                    stage="triage",
                    kind="finding",
                    summary=f"step {index}",
                )
            rows = await db.execute(
                text(
                    """
                    SELECT seq FROM runbook_events
                     WHERE tenant_id = :tid AND subject_id = :sid
                     ORDER BY seq
                    """
                ).bindparams(tid=tenant, sid=alert)
            )
            return [int(row[0]) for row in rows]

    assert _run(run()) == [1, 2, 3]


def test_seq_restarts_for_a_different_subject() -> None:
    _skip_unless_enabled()

    from app.services.runbook.recorder import record_event
    from sqlalchemy import text

    tenant = uuid.uuid4()
    first, second = uuid.uuid4(), uuid.uuid4()

    async def run() -> tuple[int, int]:
        async with _RollbackSession() as db:
            for subject in (first, second):
                await record_event(
                    db,
                    tenant_id=tenant,
                    subject_type="alert",
                    subject_id=subject,
                    stage="triage",
                    kind="finding",
                    summary="first step",
                )
            rows = await db.execute(
                text(
                    "SELECT subject_id, seq FROM runbook_events WHERE tenant_id = :tid"
                ).bindparams(tid=tenant)
            )
            by_subject = {row[0]: int(row[1]) for row in rows}
            return by_subject[first], by_subject[second]

    assert _run(run()) == (1, 1)


def test_idempotency_key_prevents_a_duplicate_step() -> None:
    _skip_unless_enabled()

    from app.services.runbook.recorder import record_event
    from sqlalchemy import text

    tenant = uuid.uuid4()
    alert = uuid.uuid4()
    key = f"ingest:{alert}:query_mode"

    async def run() -> tuple[uuid.UUID | None, uuid.UUID | None, int]:
        async with _RollbackSession() as db:
            first = await record_event(
                db,
                tenant_id=tenant,
                subject_type="alert",
                subject_id=alert,
                stage="ingest",
                kind="query_mode",
                summary="Query mode: simple",
                idempotency_key=key,
            )
            second = await record_event(
                db,
                tenant_id=tenant,
                subject_type="alert",
                subject_id=alert,
                stage="ingest",
                kind="query_mode",
                summary="Query mode: simple",
                idempotency_key=key,
            )
            total = (
                await db.execute(
                    text(
                        "SELECT count(*) FROM runbook_events WHERE tenant_id = :tid"
                    ).bindparams(tid=tenant)
                )
            ).scalar_one()
            return first, second, int(total)

    first, second, total = _run(run())
    assert first is not None
    assert second is None
    assert total == 1


# ─── Database-enforced immutability ─────────────────────────────────────────


def test_ledger_rows_cannot_be_updated_or_deleted() -> None:
    _skip_unless_enabled()

    from app.services.runbook.recorder import record_event
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    tenant = uuid.uuid4()
    alert = uuid.uuid4()

    async def run() -> tuple[str, str]:
        async with _RollbackSession() as db:
            await record_event(
                db,
                tenant_id=tenant,
                subject_type="alert",
                subject_id=alert,
                stage="triage",
                kind="finding",
                summary="original",
            )
            update_error = ""
            try:
                await db.execute(
                    text("UPDATE runbook_events SET summary = 'tampered' WHERE tenant_id = :tid").bindparams(
                        tid=tenant
                    )
                )
            except DBAPIError as exc:
                update_error = str(exc.orig)
            await db.rollback()

            # A fresh row in a fresh transaction for the DELETE probe.
            await record_event(
                db,
                tenant_id=tenant,
                subject_type="alert",
                subject_id=alert,
                stage="triage",
                kind="finding",
                summary="original again",
            )
            delete_error = ""
            try:
                await db.execute(
                    text("DELETE FROM runbook_events WHERE tenant_id = :tid").bindparams(tid=tenant)
                )
            except DBAPIError as exc:
                delete_error = str(exc.orig)
            return update_error, delete_error

    update_error, delete_error = _run(run())
    assert "immutable" in update_error
    assert "immutable" in delete_error


# ─── Contract enforcement at write time ─────────────────────────────────────


def test_credential_fields_are_redacted_before_storage() -> None:
    _skip_unless_enabled()

    from app.services.runbook.recorder import record_event
    from sqlalchemy import text

    tenant = uuid.uuid4()
    alert = uuid.uuid4()

    async def run() -> dict:
        async with _RollbackSession() as db:
            await record_event(
                db,
                tenant_id=tenant,
                subject_type="alert",
                subject_id=alert,
                stage="respond",
                kind="action",
                summary="Blocked an IP",
                input_payload={"target": "10.0.0.5", "token": "super-secret", "password": "hunter2"},
            )
            row = (
                await db.execute(
                    text("SELECT input FROM runbook_events WHERE tenant_id = :tid").bindparams(tid=tenant)
                )
            ).scalar_one()
            return dict(row)

    stored = _run(run())
    assert stored["target"] == "10.0.0.5"
    assert stored["token"] == "[redacted]"
    assert stored["password"] == "[redacted]"


def test_invalid_enums_are_rejected_before_the_database_sees_them() -> None:
    _skip_unless_enabled()

    from app.services.runbook.recorder import record_event

    async def run() -> None:
        async with _RollbackSession() as db:
            with pytest.raises(ValueError):
                await record_event(
                    db,
                    tenant_id=uuid.uuid4(),
                    subject_type="banana",
                    subject_id=uuid.uuid4(),
                    stage="triage",
                    kind="finding",
                    summary="nope",
                )

    _run(run())


# ─── Tenant isolation at the query layer ────────────────────────────────────


def test_rows_are_tenant_scoped() -> None:
    _skip_unless_enabled()

    from app.services.runbook.recorder import record_event
    from sqlalchemy import text

    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    alert = uuid.uuid4()

    async def run() -> tuple[int, int]:
        async with _RollbackSession() as db:
            await record_event(
                db,
                tenant_id=tenant_a,
                subject_type="alert",
                subject_id=alert,
                stage="triage",
                kind="finding",
                summary="tenant A only",
            )
            own = (
                await db.execute(
                    text("SELECT count(*) FROM runbook_events WHERE tenant_id = :tid").bindparams(tid=tenant_a)
                )
            ).scalar_one()
            other = (
                await db.execute(
                    text("SELECT count(*) FROM runbook_events WHERE tenant_id = :tid").bindparams(tid=tenant_b)
                )
            ).scalar_one()
            return int(own), int(other)

    own, other = _run(run())
    assert own == 1
    assert other == 0


# ─── Feature flag ───────────────────────────────────────────────────────────


def test_recorder_is_a_no_op_when_the_feature_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    _skip_unless_enabled()

    from app.core import config as app_config
    from app.services.runbook.recorder import record_event

    monkeypatch.setattr(app_config.settings, "RUNBOOK_ENABLED", False)

    async def run() -> uuid.UUID | None:
        async with _RollbackSession() as db:
            return await record_event(
                db,
                tenant_id=uuid.uuid4(),
                subject_type="alert",
                subject_id=uuid.uuid4(),
                stage="triage",
                kind="finding",
                summary="should not be written",
            )

    assert _run(run()) is None
