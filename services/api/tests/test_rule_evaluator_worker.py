"""Unit tests for the creation-time automation-rule evaluator (``app.workers.rule_evaluator``).

These are deliberately DB-free: the interesting behaviour is (a) which SQL the
claim issues, (b) that the tenant is scoped *session-wide* before the executor
runs (the RLS policies on ``automation_rules``/``runbook_tasks`` have no
NULL-tenant escape), (c) that the executor is called on a session the worker
commits, and (d) that a disabled worker is inert instead of polling.

The end-to-end "connector alert produces a rule row" behaviour needs Postgres and
lives with the integration suites.
"""

from __future__ import annotations

import ast
import asyncio
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.workers import rule_evaluator as worker


class _FetchResult:
    def __init__(self, rows: list[tuple[uuid.UUID, uuid.UUID]] | None = None) -> None:
        self._rows = rows or []

    def fetchall(self):
        return list(self._rows)


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _ClaimSession:
    """Stub session that records the claim SQL and commits."""

    def __init__(self, rows: list[tuple[uuid.UUID, uuid.UUID]] | None = None) -> None:
        self.rows = rows or []
        self.sql: list[str] = []
        self.commits = 0

    async def execute(self, statement, params=None):  # noqa: ARG002
        self.sql.append(str(statement))
        return _FetchResult(self.rows)

    async def commit(self) -> None:
        self.commits += 1

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


class _AlertSession:
    """Stub session for one alert evaluation."""

    def __init__(self, alert, *, fail: bool = False) -> None:
        self._alert = alert
        self._fail = fail
        self.commits = 0

    async def execute(self, statement, params=None):  # noqa: ARG002
        if self._fail:
            raise RuntimeError("database went away")
        return _ScalarResult(self._alert)

    async def commit(self) -> None:
        self.commits += 1

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


def _session_factory(session):
    """Return ``AsyncSessionLocal``-shaped callable yielding ``session`` itself.

    The same object is returned on purpose: the assertions are about what the
    worker did to the session it used, so a fresh stub per call would hide it.
    """

    def _factory():
        return session

    return _factory


@pytest.mark.asyncio
async def test_claim_marks_rows_and_returns_alert_and_tenant():
    alert_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    db = _ClaimSession([(alert_id, tenant_id)])

    claimed = await worker.claim_pending_alerts(db, batch_size=10)

    assert claimed == [(alert_id, tenant_id)]
    assert db.commits == 1
    assert len(db.sql) == 1
    # The marker is written by the claim, which is what makes the claim the
    # de-duplication: a second pass cannot see the same row.
    assert "automation_rules_evaluated_at = now()" in db.sql[0]
    # Concurrency guard for multi-replica deployments.
    assert "FOR UPDATE SKIP LOCKED" in db.sql[0]
    assert "automation_rules_evaluated_at IS NULL" in db.sql[0]


@pytest.mark.asyncio
async def test_claim_with_non_positive_batch_is_a_noop():
    db = _ClaimSession([(uuid.uuid4(), uuid.uuid4())])

    assert await worker.claim_pending_alerts(db, batch_size=0) == []
    assert db.sql == []
    assert db.commits == 0


@pytest.mark.asyncio
async def test_evaluate_alert_scopes_the_tenant_session_wide_and_commits(monkeypatch):
    alert_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    alert = SimpleNamespace(id=alert_id, tenant_id=tenant_id)
    session = _AlertSession(alert)

    monkeypatch.setattr(worker, "AsyncSessionLocal", _session_factory(session))

    scoped: list[uuid.UUID] = []

    async def _scope(db, tid):  # noqa: ARG001
        scoped.append(tid)

    monkeypatch.setattr(worker, "set_session_rls_context", _scope)
    monkeypatch.setattr(worker, "alert_subject_fields", lambda row: {"rule_name": "Access LSASS"})

    calls: list[dict] = []

    async def _run_rules(db, **kwargs):  # noqa: ARG001
        calls.append(kwargs)

    monkeypatch.setattr(worker, "run_rules_for_trigger", _run_rules)

    assert await worker.evaluate_alert(alert_id=alert_id, tenant_id=tenant_id) is True

    # Session-wide scoping, not transaction-local: the executor commits mid-work.
    assert scoped == [tenant_id]
    assert len(calls) == 1
    assert calls[0]["trigger_type"] == "alert.created"
    assert calls[0]["subject_type"] == "alert"
    assert calls[0]["subject_id"] == alert_id
    assert calls[0]["tenant_id"] == tenant_id
    assert calls[0]["subject_fields"] == {"rule_name": "Access LSASS"}
    # The ledger rows and rule counters the executor writes are only durable
    # once the worker commits; the request path used to rely on session teardown.
    assert session.commits == 1


@pytest.mark.asyncio
async def test_evaluate_alert_honours_an_explicit_trigger(monkeypatch):
    alert_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    session = _AlertSession(SimpleNamespace(id=alert_id, tenant_id=tenant_id))
    monkeypatch.setattr(worker, "AsyncSessionLocal", _session_factory(session))

    async def _scope(db, tid):  # noqa: ARG001
        return None

    monkeypatch.setattr(worker, "set_session_rls_context", _scope)
    monkeypatch.setattr(worker, "alert_subject_fields", lambda row: {})  # noqa: ARG005

    calls: list[str] = []

    async def _run_rules(db, **kwargs):  # noqa: ARG001
        calls.append(kwargs["trigger_type"])

    monkeypatch.setattr(worker, "run_rules_for_trigger", _run_rules)

    await worker.evaluate_alert(
        alert_id=alert_id,
        tenant_id=tenant_id,
        trigger_type="alert.updated",
    )

    assert calls == ["alert.updated"]


@pytest.mark.asyncio
async def test_evaluate_alert_skips_when_the_row_vanished(monkeypatch):
    session = _AlertSession(None)
    monkeypatch.setattr(worker, "AsyncSessionLocal", _session_factory(session))

    async def _scope(db, tid):  # noqa: ARG001
        return None

    monkeypatch.setattr(worker, "set_session_rls_context", _scope)

    async def _run_rules(db, **kwargs):  # noqa: ARG001
        raise AssertionError("executor must not run without an alert row")

    monkeypatch.setattr(worker, "run_rules_for_trigger", _run_rules)

    assert await worker.evaluate_alert(alert_id=uuid.uuid4(), tenant_id=uuid.uuid4()) is False


@pytest.mark.asyncio
async def test_evaluate_alert_swallows_failures(monkeypatch):
    alert_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    session = _AlertSession(SimpleNamespace(id=alert_id, tenant_id=tenant_id), fail=True)
    monkeypatch.setattr(worker, "AsyncSessionLocal", _session_factory(session))

    assert await worker.evaluate_alert(alert_id=alert_id, tenant_id=tenant_id) is False


@pytest.mark.asyncio
async def test_evaluate_pending_reports_what_it_did(monkeypatch):
    first = (uuid.uuid4(), uuid.uuid4())
    second = (uuid.uuid4(), uuid.uuid4())
    db = _ClaimSession([first, second])
    monkeypatch.setattr(worker, "AsyncSessionLocal", lambda: db)

    outcomes = {first[0]: True, second[0]: False}
    evaluated: list[uuid.UUID] = []

    async def _evaluate(**kwargs):
        evaluated.append(kwargs["alert_id"])
        return outcomes[kwargs["alert_id"]]

    monkeypatch.setattr(worker, "evaluate_alert", _evaluate)

    report = await worker.evaluate_pending(batch_size=2)

    assert evaluated == [first[0], second[0]]
    assert report == {"claimed": 2, "evaluated": 1, "failed": 1}
    assert db.commits == 1


@pytest.mark.asyncio
async def test_evaluate_pending_survives_a_claim_failure(monkeypatch):
    class _Broken(_ClaimSession):
        async def execute(self, statement, params=None):  # noqa: ARG002
            raise RuntimeError("postgres is down")

    monkeypatch.setattr(worker, "AsyncSessionLocal", lambda: _Broken())

    assert await worker.evaluate_pending() == {"claimed": 0, "evaluated": 0, "failed": 0}


def test_disabled_reason_follows_configuration(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
    monkeypatch.setattr(worker, "runbook_enabled", lambda: True)
    monkeypatch.setattr(settings, "RULE_EVALUATOR_ENABLED", True)
    assert worker._disabled_reason() is None

    monkeypatch.setattr(settings, "RULE_EVALUATOR_ENABLED", False)
    assert worker._disabled_reason() == "disabled_by_configuration"

    monkeypatch.setattr(settings, "RULE_EVALUATOR_ENABLED", True)
    monkeypatch.setattr(worker, "runbook_enabled", lambda: False)
    assert worker._disabled_reason() == "runbook_disabled"

    monkeypatch.setattr(worker, "runbook_enabled", lambda: True)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert worker._disabled_reason() == "no_database_url"


@pytest.mark.asyncio
async def test_run_forever_is_inert_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "RULE_EVALUATOR_ENABLED", False)

    async def _no_pass():
        raise AssertionError("a disabled worker must not claim alerts")

    monkeypatch.setattr(worker, "evaluate_pending", _no_pass)

    # Returns immediately instead of entering the loop.
    await worker.run_forever()


@pytest.mark.asyncio
async def test_run_forever_runs_a_pass_then_stops_on_cancel(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
    monkeypatch.setattr(worker, "runbook_enabled", lambda: True)
    monkeypatch.setattr(settings, "RULE_EVALUATOR_ENABLED", True)

    passes: list[int] = []

    async def _pass(**kwargs):  # noqa: ARG001
        passes.append(1)
        return {"claimed": 0, "evaluated": 0, "failed": 0}

    async def _cancel_after_first_pass(_seconds):
        raise asyncio.CancelledError

    monkeypatch.setattr(worker, "evaluate_pending", _pass)
    monkeypatch.setattr(worker.asyncio, "sleep", _cancel_after_first_pass)

    with pytest.raises(asyncio.CancelledError):
        await worker.run_forever()

    assert len(passes) == 1


def test_alert_endpoint_delegates_creation_rules_to_the_worker():
    """Ownership guard: the API must not schedule ``alert.created`` itself.

    Two writers (the endpoint and the worker) would evaluate every hand-submitted
    alert twice and leave fusion-created alerts evaluated once — the exact split
    this worker exists to remove. Cheap AST check instead of an endpoint test so
    the rule survives refactors of the request path.
    """
    source = Path(__file__).resolve().parents[1] / "app/api/v1/endpoints/alerts.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))

    executor_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_rules_for_trigger"
    ]
    assert executor_calls == [], (
        "alerts.py must not call run_rules_for_trigger directly; creation-time "
        "evaluation belongs to app/workers/rule_evaluator.py"
    )

    delegated = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "evaluate_alert" in delegated, (
        "the PATCH path re-evaluates rules through evaluate_alert, which owns "
        "the tenant-scoped session"
    )
