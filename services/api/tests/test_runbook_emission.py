"""Phase 1.10 — emission tests for the Runbook ledger.

Two kinds of proof, kept deliberately separate:

* **Wiring** (mocked session): the endpoint actually calls its emitter with the
  right arguments — the call site exists, the previous value is captured before
  the write, and a no-op emits nothing.
* **Persistence** (real Postgres): the emitter writes exactly what the ledger
  promises — one row per changed field, none for a no-op, idempotent under
  retry, and connector provenance promoted exactly once.

The persistence half is gated behind ``pytest.mark.integration``:

    AISOC_RUN_INTEGRATION=1 pytest -m integration tests/test_runbook_emission.py

Each persistence test runs inside one transaction that is rolled back: the
ledger is append-only, so a test that committed could never clean up after
itself (see ``test_runbook_events.py`` for the same harness).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import alerts as alerts_module
from app.api.v1.endpoints.alerts import AlertUpdateRequest, escalate_alert, update_alert

# Wiring tests reuse the alert/user builders and the queued-result mock from the
# tenant-isolation suite so both files describe the same endpoint contract
# instead of drifting apart. pytest puts ``tests/`` on ``sys.path`` (rootless
# test package), which is what makes this import resolve.
from test_alerts_tenant_isolation import _alert, _mk_db, _user

_REQUIRES_ENV = "AISOC_RUN_INTEGRATION"


def _skip_unless_enabled() -> None:
    if not os.getenv(_REQUIRES_ENV):
        pytest.skip(f"set {_REQUIRES_ENV}=1 to run ledger emission tests against Postgres")


# ─── Wiring: the endpoints actually call the emitters ─────────────────────────


@pytest.mark.asyncio
async def test_update_alert_emits_one_row_per_changed_field(monkeypatch: pytest.MonkeyPatch) -> None:
    """PATCH records the transition: emitter called with old **and** new value."""
    emit = AsyncMock(return_value=2)
    monkeypatch.setattr(alerts_module, "emit_alert_update_events", emit)

    user = _user()
    alert = _alert(user.tenant_id, status="new")
    db = _mk_db([alert, None])  # SELECT, then the UPDATE.

    resp = await update_alert(
        alert_id=alert.id,
        request=AlertUpdateRequest(status="resolved", tags=["triaged"]),
        current_user=user,
        db=db,
    )

    assert resp.id == alert.id
    emit.assert_awaited_once()
    kwargs = emit.await_args.kwargs
    assert kwargs["tenant_id"] == user.tenant_id
    assert kwargs["alert"] is alert
    assert kwargs["updates"]["status"] == "resolved"
    # The previous value must be captured BEFORE the write, or the ledger
    # would record "resolved → resolved".
    assert kwargs["previous"]["status"] == "new"


@pytest.mark.asyncio
async def test_update_alert_emits_nothing_when_no_field_changed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A request that changes no field must not invent a ledger row."""
    emit = AsyncMock()
    monkeypatch.setattr(alerts_module, "emit_alert_update_events", emit)

    user = _user()
    alert = _alert(user.tenant_id)
    db = _mk_db([alert])

    await update_alert(
        alert_id=alert.id,
        request=AlertUpdateRequest(),
        current_user=user,
        db=db,
    )

    emit.assert_not_awaited()


@pytest.mark.asyncio
async def test_escalate_alert_emits_the_previous_severity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Escalation records where severity came **from**, not only where it went."""
    emit = AsyncMock(return_value=1)
    monkeypatch.setattr(alerts_module, "emit_alert_escalation", emit)

    user = _user()
    alert = _alert(user.tenant_id, severity="medium")
    # ``_mk_db`` serves one queued payload per session call, in order:
    #   SELECT → the alert, UPDATE → no row (None), refresh → the post-write row.
    # The refresh copy is what mutates ``alert`` in place, so the response and
    # the emitter both see the new severity.
    updated = _alert(user.tenant_id, severity="high")
    db = _mk_db([alert, None, updated])

    resp = await escalate_alert(alert_id=alert.id, current_user=user, db=db)

    assert resp.severity == "high"
    emit.assert_awaited_once()
    kwargs = emit.await_args.kwargs
    assert kwargs["previous_severity"] == "medium"
    assert kwargs["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_emitters_never_break_the_action_when_the_ledger_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The feature flag must gate the ledger, not the analyst's action."""
    from app.core import config as app_config

    monkeypatch.setattr(app_config.settings, "RUNBOOK_ENABLED", False)

    user: CurrentUser = _user()
    alert = _alert(user.tenant_id, severity="medium")
    updated = _alert(user.tenant_id, severity="high")
    db = _mk_db([alert, None, updated])  # SELECT, UPDATE, then the refreshed row.

    # ``emit_alert_escalation`` is called unconditionally by the endpoint; with
    # the flag off ``record_event`` returns None and the response still builds.
    resp = await escalate_alert(alert_id=alert.id, current_user=user, db=db)
    assert resp.severity == "high"


# ─── Persistence: what actually lands in runbook_events ──────────────────────


class _RollbackSession:
    """Async context manager yielding a session whose work is always rolled back."""

    def __init__(self) -> None:
        self.session = None

    async def __aenter__(self):
        from app.db.database import AsyncSessionLocal

        self.session = AsyncSessionLocal()
        session = await self.session.__aenter__()
        # Every emitter commits its own row (callers range from a FastAPI
        # request, which commits on close, to a funnel that has already
        # returned). Stubbing ``commit`` here keeps those writes inside the
        # open transaction so this test's final ``rollback()`` can still undo
        # them — otherwise an append-only ledger would accumulate test rows in
        # the developer's database forever.
        session.commit = AsyncMock()
        return session

    async def __aexit__(self, *exc_info):
        assert self.session is not None
        try:
            await self.session.rollback()
        finally:
            await self.session.__aexit__(*exc_info)


def _run(coro):
    """Run ``coro`` on a private event loop, then drop the pooled sockets.

    The SQLAlchemy engine is process-global and its asyncpg connections are
    bound to the loop that opened them; without ``dispose()`` the second test
    reuses sockets owned by the first, already-closed loop.
    """
    import asyncio

    from app.db.database import engine

    async def _wrapped():
        try:
            return await coro
        finally:
            await engine.dispose()

    return asyncio.run(_wrapped())


def _rows(db: Any, *, tenant_id: uuid.UUID, subject_id: uuid.UUID) -> list[Any]:
    """Ledger rows for one subject (helper for assertions)."""
    from sqlalchemy import text

    return (
        db.execute(
            text(
                """
                SELECT seq, stage, kind, summary, actor_type, status, idempotency_key
                  FROM runbook_events
                 WHERE tenant_id = :tid AND subject_id = :sid
                 ORDER BY seq
                """
            ).bindparams(tid=tenant_id, sid=subject_id)
        )
    )


def test_alert_update_emitter_writes_one_row_per_changed_field() -> None:
    _skip_unless_enabled()
    from app.services.runbook.emitters import emit_alert_update_events

    tenant = uuid.uuid4()
    alert = _alert(tenant)

    async def run() -> list[Any]:
        async with _RollbackSession() as db:
            written = await emit_alert_update_events(
                db,
                alert=alert,
                tenant_id=tenant,
                actor_id="analyst-1",
                actor_label="analyst@example.com",
                updates={"status": "resolved", "severity": "high", "updated_at": datetime.now(UTC)},
                previous={"status": "new", "severity": "medium", "updated_at": None},
            )
            rows = [
                tuple(row)
                for row in (await _rows(db, tenant_id=tenant, subject_id=alert.id)).all()
            ]
            return [written, *rows]

    result = _run(run())
    written, *rows = result
    assert written == 2, "one row per changed field (updated_at is bookkeeping, not a step)"
    stages = [row[1] for row in rows]
    summaries = [row[3] for row in rows]
    assert stages == ["triage", "triage"] or stages == ["funnel", "triage"]
    assert any("new" in s and "resolved" in s for s in summaries)
    assert {row[4] for row in rows} == {"analyst"}


def test_alert_update_emitter_skips_no_ops() -> None:
    _skip_unless_enabled()
    from app.services.runbook.emitters import emit_alert_update_events

    tenant = uuid.uuid4()
    alert = _alert(tenant)

    async def run() -> tuple[int, int]:
        async with _RollbackSession() as db:
            written = await emit_alert_update_events(
                db,
                alert=alert,
                tenant_id=tenant,
                actor_id=None,
                actor_label=None,
                updates={"status": "new"},
                previous={"status": "new"},
            )
            count = (await _rows(db, tenant_id=tenant, subject_id=alert.id)).all()
            return written, len(count)

    assert _run(run()) == (0, 0)


def test_escalation_emitter_records_the_transition_once() -> None:
    _skip_unless_enabled()
    from app.services.runbook.emitters import emit_alert_escalation

    tenant = uuid.uuid4()
    alert = _alert(tenant, severity="high")

    async def run() -> tuple[int, int, int]:
        async with _RollbackSession() as db:
            changed = await emit_alert_escalation(
                db,
                alert=alert,
                tenant_id=tenant,
                actor_id=None,
                actor_label="analyst@example.com",
                previous_severity="medium",
            )
            unchanged = await emit_alert_escalation(
                db,
                alert=alert,
                tenant_id=tenant,
                actor_id=None,
                actor_label="analyst@example.com",
                previous_severity="high",
            )
            rows = (await _rows(db, tenant_id=tenant, subject_id=alert.id)).all()
            return changed, unchanged, len(rows)

    assert _run(run()) == (1, 0, 1)


def test_case_created_is_idempotent_under_retry() -> None:
    _skip_unless_enabled()
    from app.services.runbook.emitters import emit_case_created

    tenant = uuid.uuid4()
    case_id = uuid.uuid4()

    async def run() -> tuple[int, int, int]:
        async with _RollbackSession() as db:
            first = await emit_case_created(
                db,
                tenant_id=tenant,
                case_id=case_id,
                case_title="LSASS dump on win-dc-807",
                alert_ids=[str(uuid.uuid4()), str(uuid.uuid4())],
                severity="high",
                disposition="true_positive",
            )
            second = await emit_case_created(
                db,
                tenant_id=tenant,
                case_id=case_id,
                case_title="LSASS dump on win-dc-807",
                alert_ids=[str(uuid.uuid4())],
                severity="high",
                disposition="true_positive",
            )
            rows = (await _rows(db, tenant_id=tenant, subject_id=case_id)).all()
            return first, second, len(rows)

    first, second, total = _run(run())
    assert first == 1
    assert second == 0, "a retried backfill must not append a second 'Case opened' line"
    assert total == 1


def test_itsm_status_change_writes_a_single_itm_row() -> None:
    _skip_unless_enabled()
    from app.services.runbook.emitters import emit_itsm_status_change

    tenant = uuid.uuid4()
    case_id = uuid.uuid4()
    external_id = f"AIS-{uuid.uuid4().hex[:6]}"

    async def run() -> tuple[list[Any], int]:
        from sqlalchemy import text

        async with _RollbackSession() as db:
            written = await emit_itsm_status_change(
                db,
                case_id=case_id,
                tenant_id=tenant,
                new_status="resolved",
                vendor="jira",
                external_id=external_id,
                actor_label="itsm-webhook (jira)",
            )
            rows = [
                tuple(row)
                for row in (
                    await db.execute(
                        text(
                            """
                            SELECT stage, kind, summary, actor_type, idempotency_key
                              FROM runbook_events
                             WHERE tenant_id = :tid AND subject_id = :sid
                            """
                        ).bindparams(tid=tenant, sid=case_id)
                    )
                ).all()
            ]
            # ``_RollbackSession`` stubs ``commit``, so this asserts the row
            # shape and the deterministic idempotency key — the retry-safety
            # contract the webhook depends on.
            return rows, written

    rows, written = _run(run())
    assert written == 1
    assert rows[0][0] == "itsm"
    assert rows[0][1] == "action"
    assert "resolved" in rows[0][2]
    assert rows[0][4] == f"itsm:{case_id}:{external_id}:resolved"


def test_materialize_promotes_connector_provenance_exactly_once() -> None:
    _skip_unless_enabled()
    from app.services.runbook.materialize import materialize_alert_provenance

    tenant = uuid.uuid4()
    alert_id = uuid.uuid4()
    provenance = {
        "runbook_provenance": {
            "source": "splunk-connector",
            "query_mode": "simple",
            "notable_volume": 24310,
            "threshold": 20000,
            "reason": "volume_above_threshold",
            "llm_payload_source": "code",
            "caveats": ["macros_not_expanded"],
        }
    }

    async def run() -> tuple[int, int, list[str]]:
        from sqlalchemy import text

        async with _RollbackSession() as db:
            first = await materialize_alert_provenance(
                db,
                tenant_id=tenant,
                alert_id=alert_id,
                raw_event={"raw_data": provenance},
            )
            second = await materialize_alert_provenance(
                db,
                tenant_id=tenant,
                alert_id=alert_id,
                raw_event={"raw_data": provenance},
            )
            kinds = [
                str(row[0])
                for row in (
                    await db.execute(
                        text(
                            """
                            SELECT kind FROM runbook_events
                             WHERE tenant_id = :tid AND subject_id = :sid
                             ORDER BY seq
                            """
                        ).bindparams(tid=tenant, sid=alert_id)
                    )
                ).all()
            ]
            return first, second, kinds

    first, second, kinds = _run(run())
    assert first == 2, "query_mode + llm_payload rows are both promoted"
    assert second == 0, "re-reading the alert must not duplicate the provenance rows"
    assert kinds == ["query_mode", "llm_payload"]


def test_materialize_writes_nothing_when_there_is_no_provenance() -> None:
    _skip_unless_enabled()
    from app.services.runbook.materialize import materialize_alert_provenance

    tenant = uuid.uuid4()
    alert_id = uuid.uuid4()

    async def run() -> int:
        from sqlalchemy import text

        async with _RollbackSession() as db:
            written = await materialize_alert_provenance(
                db,
                tenant_id=tenant,
                alert_id=alert_id,
                raw_event={"some": "envelope without a provenance block"},
            )
            count = (
                await db.execute(
                    text("SELECT count(*) FROM runbook_events WHERE tenant_id = :tid").bindparams(tid=tenant)
                )
            ).scalar_one()
            assert count == 0
            return written

    assert _run(run()) == 0
