"""Regression tests for the materialisation wave loop.

The bug these lock down: the per-wave re-probe used a fixed 10 s budget, a slow
wave set ``retry["partial"]``, that flag was copied onto the whole attribution,
and the ``while ... and not partial`` condition ended the loop after wave 1. The
panel showed "re-probe 1 of 12" and jumped straight to the judge with no
explanation. A slow wave is a slow wave — not a partial evaluation.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.services.tkg_evaluation import progress, runner
from app.services.tkg_evaluation.attribution import aggregate

CASE_ID = uuid4()
TENANT_ID = uuid4()


def _envelope(alert_id: str, *, status: str) -> dict:
    return {
        "alert_id": alert_id,
        "status": status,
        "entity_id": f"entity-{alert_id}" if status == "resolved" else None,
        "canonical_key": None,
        "facts": 2 if status == "resolved" else 0,
        "synthetic_facts": 0,
        "pass": "corroborated" if status == "resolved" else "none",
        "error": None,
        "fact_samples": [],
        "limitations": [],
        "retrieval_status": None,
    }


def _bundle() -> dict:
    alerts = [
        {
            "alert_id": "row-1",
            "notable_id": "notable-1",
            "time": "2026-01-01T00:00:00+00:00",
            "title": "first alert",
            "rule": "rule-a",
            "severity": "high",
            "techniques": [],
        },
        {
            "alert_id": "row-2",
            "notable_id": "notable-2",
            "time": "2026-01-01T00:01:00+00:00",
            "title": "second alert",
            "rule": "rule-b",
            "severity": "medium",
            "techniques": [],
        },
    ]
    return {
        "ok": True,
        "payload": {"case": {"id": str(CASE_ID), "title": "case"}, "alerts": alerts},
        "stats": {"alerts": len(alerts), "fingerprint": "fp"},
    }


def _settings(wait_s: float = 1.0, poll_s: float = 0.05) -> SimpleNamespace:
    return SimpleNamespace(
        AISOC_TKG_URL="http://tkg.test",
        AISOC_TKG_EMAIL="a@example.test",
        AISOC_TKG_PASSWORD="secret",
        AISOC_TKG_KB_ID="kb-1",
        AISOC_TKG_MATERIALISE_WAIT_S=wait_s,
        AISOC_TKG_MATERIALISE_POLL_S=poll_s,
        AISOC_TKG_WAIT_TIMEOUT_S=600.0,
        AISOC_TKG_BUDGET_MS=20_000,
        AISOC_TKG_CACHE_TTL_S=0,
        AISOC_TKG_MAX_ALERTS=500,
        AISOC_TKG_ALLOW_SEND=False,
    )


class _Client:
    async def readiness(self) -> dict:
        return {"ready": True, "checks": [], "counts": {}, "kb_id": "kb-1"}

    async def receipts(self) -> dict:
        return {"counts": [], "receipts": []}


@pytest.mark.asyncio
async def test_partial_wave_does_not_end_the_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    persisted: list[dict] = []

    async def fake_attribute_alerts(client, alert_ids, **kwargs):
        ids = list(alert_ids)
        calls.append(ids)
        if len(calls) == 1:
            rolled = aggregate([_envelope("notable-1", status="resolved"),
                                _envelope("notable-2", status="pending_materialization")])
            rolled["partial"] = False
            return rolled
        if len(calls) == 2:
            # A wave that only got part-way through the queued set.
            rolled = aggregate([_envelope("notable-2", status="pending_materialization")])
            rolled["partial"] = True
            return rolled
        rolled = aggregate([_envelope("notable-2", status="resolved")])
        rolled["partial"] = False
        return rolled

    async def fake_persist(db, **kwargs):
        persisted.append(kwargs)
        return SimpleNamespace(id=uuid4())

    async def fake_load_case(db, case_id, tenant_id):
        return {"id": case_id, "title": "case", "alert_ids": ["row-1", "row-2"], "severity": "high", "status": "open"}

    async def fake_load_case_scope(db, case_id, tenant_id):
        return [], []

    async def fake_load_alerts(db, tenant_id, case_id, alert_ids, excluded):
        return [{"id": f"row-{index}", "llm_payload": {}} for index in (1, 2)]

    monkeypatch.setattr(runner, "load_case", fake_load_case)
    monkeypatch.setattr(runner, "load_case_scope", fake_load_case_scope)
    monkeypatch.setattr(runner, "load_alerts", fake_load_alerts)
    monkeypatch.setattr(runner, "build_bundle", lambda **kwargs: _bundle())
    monkeypatch.setattr(runner, "precheck", lambda bundle: {"eligible": True, "checks": []})
    monkeypatch.setattr(runner, "attribute_alerts", fake_attribute_alerts)
    monkeypatch.setattr(runner, "_cached", lambda *a, **k: _none())
    monkeypatch.setattr(runner, "_persist", fake_persist)
    monkeypatch.setattr(runner, "_result", lambda row, stats=None: {"status": "ok", "stats": stats})
    monkeypatch.setattr(
        runner,
        "config_from_settings",
        lambda settings: SimpleNamespace(configured=True, kb_id="kb-1", allow_send=False),
    )
    monkeypatch.setattr(runner, "evidence_floor", lambda **kwargs: {"coverage": 0.5})
    monkeypatch.setattr(
        runner,
        "reconcile",
        lambda **kwargs: {
            "verdict": "needs_more_evidence",
            "confidence": 50,
            "passes": None,
            "agree": None,
            "reasons": [],
        },
    )

    job = progress.start(case_id=CASE_ID, tenant_id=TENANT_ID)
    await runner.run_evaluation(
        SimpleNamespace(),
        tenant_id=TENANT_ID,
        case_id=CASE_ID,
        client=_Client(),
        settings_obj=_settings(),
        job=job,
    )
    progress.finish(job)

    # The partial wave must not stop the loop: wave 1 ran out of its probe
    # budget, wave 2 re-probed the same alert and it materialised. Before the
    # fix the loop exited after wave 1 with three of them never happening.
    assert len(calls) == 3, calls
    assert job.wave == 2
    assert job.snapshot()["pending"] == 0
    # ... and a slow wave is not a partial evaluation.
    assert persisted and persisted[-1]["status"] == "ok"


async def _none():
    return None


class _WritingClient(_Client):
    """A client that records the records a run pushes into the graph."""

    def __init__(self) -> None:
        self.ingested: list[dict] = []

    async def ensure_source(self) -> tuple[str, str]:
        return "source-1", "ingest-token"

    async def ingest(self, source_id: str, ingest_token: str, body: dict) -> dict:
        self.ingested.append(body["record"])
        return {"receipt_id": f"receipt-{len(self.ingested)}", "status": "pending"}


@pytest.mark.asyncio
async def test_run_sends_unknown_alerts_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-run is the whole job: an unknown alert is pushed, then re-read."""

    calls: list[list[str]] = []
    persisted: list[dict] = []

    async def fake_attribute_alerts(client, alert_ids, **kwargs):
        calls.append(list(alert_ids))
        if len(calls) == 1:
            rolled = aggregate([_envelope("notable-1", status="not_found")])
            rolled["partial"] = False
            return rolled
        # The send step re-reads what it pushed: now the graph has it.
        rolled = aggregate([_envelope("notable-1", status="resolved")])
        rolled["partial"] = False
        return rolled

    async def fake_persist(db, **kwargs):
        persisted.append(kwargs)
        return SimpleNamespace(id=uuid4())

    async def fake_load_case(db, case_id, tenant_id):
        return {"id": case_id, "title": "case", "alert_ids": ["row-1"], "severity": "high", "status": "open"}

    async def fake_load_alerts(db, tenant_id, case_id, alert_ids, excluded):
        return [
            {
                "id": "row-1",
                "llm_payload": {
                    "alert_id": "notable-1",
                    "event_time": "2026-01-01T00:00:00+00:00",
                    "rule_name": "rule-a",
                },
            }
        ]

    monkeypatch.setattr(runner, "load_case", fake_load_case)
    monkeypatch.setattr(runner, "load_case_scope", lambda *a, **k: _empty())
    monkeypatch.setattr(runner, "load_alerts", fake_load_alerts)
    monkeypatch.setattr(
        runner,
        "build_bundle",
        lambda **kwargs: {
            "ok": True,
            "payload": {"case": {"id": str(CASE_ID)}, "alerts": [_bundle()["payload"]["alerts"][0]]},
            "stats": {"alerts": 1, "fingerprint": "fp"},
        },
    )
    monkeypatch.setattr(runner, "precheck", lambda bundle: {"eligible": True, "checks": []})
    monkeypatch.setattr(runner, "attribute_alerts", fake_attribute_alerts)
    monkeypatch.setattr(runner, "_cached", lambda *a, **k: _none())
    monkeypatch.setattr(runner, "_persist", fake_persist)
    monkeypatch.setattr(runner, "_result", lambda row, stats=None: {"status": "ok", "stats": stats})
    monkeypatch.setattr(
        runner,
        "config_from_settings",
        lambda settings: SimpleNamespace(configured=True, kb_id="kb-1", allow_send=True),
    )
    monkeypatch.setattr(runner, "evidence_floor", lambda **kwargs: {"coverage": 1.0})
    monkeypatch.setattr(
        runner,
        "reconcile",
        lambda **kwargs: {"verdict": "true_positive", "confidence": 70, "passes": None, "agree": None, "reasons": []},
    )

    client = _WritingClient()
    job = progress.start(case_id=CASE_ID, tenant_id=TENANT_ID)
    await runner.run_evaluation(
        SimpleNamespace(),
        tenant_id=TENANT_ID,
        case_id=CASE_ID,
        client=client,
        settings_obj=_settings(),
        job=job,
        send_missing=True,
    )
    progress.finish(job)

    assert [record["notable_id"] for record in client.ingested] == ["notable-1"]
    send_report = persisted[-1]["attribution"]["send"]
    assert len(send_report["sent"]) == 1
    assert send_report["rejected"] == []
    # Re-read after the send, so the alert is not left looking never-sent.
    assert len(calls) == 2
    assert job.snapshot()["pending"] == 0


async def _empty() -> tuple:
    return [], []


class _DeadDocumentClient(_WritingClient):
    """Ingest succeeds, but the graph's extractor has already given up."""

    def __init__(self) -> None:
        super().__init__()
        self.receipt_calls = 0

    async def receipts(self) -> dict:
        self.receipt_calls += 1
        return {
            "counts": [{"status": "submitted", "count": 1}],
            "receipts": [
                {
                    "receipt_id": "receipt-1",
                    "status": "submitted",
                    "failure_code": "soc_document_failed",
                    "job_status": "failed",
                }
            ],
        }


@pytest.mark.asyncio
async def test_the_wait_ends_when_the_graph_reports_the_documents_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An accepted record whose extraction died is not "slow": stop, and say why."""

    calls: list[list[str]] = []
    persisted: list[dict] = []

    async def fake_attribute_alerts(client, alert_ids, **kwargs):
        calls.append(list(alert_ids))
        status = "not_found" if len(calls) == 1 else "pending_materialization"
        rolled = aggregate([_envelope("notable-1", status=status)])
        rolled["partial"] = False
        return rolled

    async def fake_persist(db, **kwargs):
        persisted.append(kwargs)
        return SimpleNamespace(id=uuid4())

    async def fake_load_case(db, case_id, tenant_id):
        return {"id": case_id, "title": "case", "alert_ids": ["row-1"], "severity": "high", "status": "open"}

    async def fake_load_alerts(db, tenant_id, case_id, alert_ids, excluded):
        return [
            {
                "id": "row-1",
                "llm_payload": {
                    "alert_id": "notable-1",
                    "event_time": "2026-01-01T00:00:00+00:00",
                    "rule_name": "rule-a",
                },
            }
        ]

    monkeypatch.setattr(runner, "load_case", fake_load_case)
    monkeypatch.setattr(runner, "load_case_scope", lambda *a, **k: _empty())
    monkeypatch.setattr(runner, "load_alerts", fake_load_alerts)
    monkeypatch.setattr(
        runner,
        "build_bundle",
        lambda **kwargs: {
            "ok": True,
            "payload": {"case": {"id": str(CASE_ID)}, "alerts": [_bundle()["payload"]["alerts"][0]]},
            "stats": {"alerts": 1, "fingerprint": "fp"},
        },
    )
    monkeypatch.setattr(runner, "precheck", lambda bundle: {"eligible": True, "checks": []})
    monkeypatch.setattr(runner, "attribute_alerts", fake_attribute_alerts)
    monkeypatch.setattr(runner, "_cached", lambda *a, **k: _none())
    monkeypatch.setattr(runner, "_persist", fake_persist)
    monkeypatch.setattr(runner, "_result", lambda row, stats=None: {"status": "ok", "stats": stats})
    monkeypatch.setattr(
        runner,
        "config_from_settings",
        lambda settings: SimpleNamespace(configured=True, kb_id="kb-1", allow_send=True),
    )
    monkeypatch.setattr(runner, "evidence_floor", lambda **kwargs: {"coverage": 1.0})
    monkeypatch.setattr(
        runner,
        "reconcile",
        lambda **kwargs: {"verdict": "true_positive", "confidence": 70, "passes": None, "agree": None, "reasons": []},
    )

    client = _DeadDocumentClient()
    job = progress.start(case_id=CASE_ID, tenant_id=TENANT_ID)
    await runner.run_evaluation(
        SimpleNamespace(),
        tenant_id=TENANT_ID,
        case_id=CASE_ID,
        client=client,
        settings_obj=_settings(),
        job=job,
        send_missing=True,
    )
    progress.finish(job)

    # resolve, the post-send re-read, then exactly one wave — no endless polling.
    assert len(calls) == 3, calls
    assert client.receipt_calls == 1
    assert job.wave == 1
    stored = persisted[-1]
    assert "tkg_extraction_failed" in stored["reason_codes"]
    assert stored["attribution"]["graph_failures"]["count"] == 1
    assert stored["attribution"]["graph_failures"]["error"] == "soc_document_failed"
    assert "rate-limited" in (job.message or "")


class _RateLimitedClient(_WritingClient):
    """The graph answers the second ingest with 429."""

    async def ingest(self, source_id: str, ingest_token: str, body: dict) -> dict:
        if len(self.ingested) == 1:
            raise runner.TkgError("tkg_unreachable", "ingest -> HTTP 429", status=429)
        return await super().ingest(source_id, ingest_token, body)


@pytest.mark.asyncio
async def test_a_rate_limited_ingest_stops_the_send_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refused for budget: do not queue the rest of the batch behind it."""

    # A real run tags every envelope with its AiSOC row id; the send step looks
    # the payload up by it.
    rolled = aggregate(
        [
            _envelope("notable-1", status="not_found"),
            _envelope("notable-2", status="not_found"),
            _envelope("notable-3", status="not_found"),
        ]
    )
    for index, envelope in enumerate(rolled["alerts"], start=1):
        envelope["row_id"] = f"row-{index}"

    report = await runner._send_unknown_alerts(
        _RateLimitedClient(),
        attribution=rolled,
        raw_by_row={
            "row-1": {
                "id": "row-1",
                "llm_payload": {
                    "alert_id": "notable-1",
                    "event_time": "2026-01-01T00:00:00+00:00",
                    "rule_name": "rule-a",
                },
            },
            "row-2": {
                "id": "row-2",
                "llm_payload": {
                    "alert_id": "notable-2",
                    "event_time": "2026-01-01T00:01:00+00:00",
                    "rule_name": "rule-b",
                },
            },
        },
        delay=0.0,
        job=None,
    )

    assert report["stopped"] == "tkg_rate_limited"
    # One record accepted, the next refused, and the third never attempted.
    assert len(report["sent"]) == 1
    assert len(report["failed"]) == 1


class _MixedReceiptClient:
    """One receipt whose job is dead, one whose job is still queued."""

    async def receipts(self) -> dict:
        return {
            "receipts": [
                {
                    "receipt_id": "r-1",
                    "failure_code": "soc_source_busy_retry",
                    "job_status": "failed",
                },
                {
                    "receipt_id": "r-2",
                    "failure_code": "soc_source_busy_retry",
                    "job_status": "queued",
                },
            ]
        }


@pytest.mark.asyncio
async def test_a_failed_job_is_terminal_whatever_its_code() -> None:
    """The graph writes ``failed`` only when no retry is scheduled."""

    client = _MixedReceiptClient()
    both = aggregate(
        [
            _envelope("notable-1", status="pending_materialization"),
            _envelope("notable-2", status="pending_materialization"),
        ]
    )
    send_both = {
        "sent": [
            {"notable_id": "notable-1", "receipt_id": "r-1"},
            {"notable_id": "notable-2", "receipt_id": "r-2"},
        ]
    }
    # One live document next to a dead one: keep waiting, do not call it a failure.
    assert await runner._graph_failures(client, attribution=both, send_report=send_both) is None

    dead_only = aggregate([_envelope("notable-1", status="pending_materialization")])
    report = await runner._graph_failures(
        client,
        attribution=dead_only,
        send_report={"sent": [{"notable_id": "notable-1", "receipt_id": "r-1"}]},
    )
    assert report is not None
    assert report["count"] == 1
    assert report["error"] == "soc_source_busy_retry"


def _install_run(
    monkeypatch: pytest.MonkeyPatch, *, attribute, persisted: list[dict], bundle: dict | None = None
) -> None:
    """Wire a run to fakes, so each test only states what the run must do."""

    async def fake_persist(db, **kwargs):
        persisted.append(kwargs)
        return SimpleNamespace(id=uuid4())

    async def fake_load_case(db, case_id, tenant_id):
        return {
            "id": case_id,
            "title": "case",
            "alert_ids": ["row-1", "row-2"],
            "severity": "high",
            "status": "open",
        }

    async def fake_load_alerts(db, tenant_id, case_id, alert_ids, excluded):
        return [{"id": f"row-{index}", "llm_payload": {}} for index in (1, 2)]

    monkeypatch.setattr(runner, "load_case", fake_load_case)
    monkeypatch.setattr(runner, "load_case_scope", lambda *a, **k: _empty())
    monkeypatch.setattr(runner, "load_alerts", fake_load_alerts)
    monkeypatch.setattr(runner, "build_bundle", lambda **kwargs: bundle or _bundle())
    monkeypatch.setattr(runner, "precheck", lambda bundle: {"eligible": True, "checks": []})
    monkeypatch.setattr(runner, "attribute_alerts", attribute)
    monkeypatch.setattr(runner, "_cached", lambda *a, **k: _none())
    monkeypatch.setattr(runner, "_persist", fake_persist)
    monkeypatch.setattr(
        runner,
        "_result",
        lambda row, stats=None: {
            "status": "ok",
            "verdict": "needs_more_evidence",
            "confidence": 50,
            "stats": stats or {},
        },
    )
    monkeypatch.setattr(
        runner,
        "config_from_settings",
        lambda settings: SimpleNamespace(configured=True, kb_id="kb-1", allow_send=False),
    )
    monkeypatch.setattr(runner, "evidence_floor", lambda **kwargs: {"coverage": 0.5})
    monkeypatch.setattr(
        runner,
        "reconcile",
        lambda **kwargs: {
            "verdict": "needs_more_evidence",
            "confidence": 50,
            "passes": None,
            "agree": None,
            "reasons": [],
        },
    )


async def _stop_waiting_when_it_starts(job) -> None:
    """Play the operator: press *stop waiting* as soon as the wait stage opens."""

    while job.state == "running":
        if job.stage == "materialise":
            progress.skip_waiting(job.id, case_id=job.case_id, tenant_id=job.tenant_id)
        await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_stopping_the_wait_still_judges_and_stores(monkeypatch: pytest.MonkeyPatch) -> None:
    """*Stop waiting* ends the wait, not the run: the row is judged and stored."""

    persisted: list[dict] = []

    async def fake_attribute_alerts(client, alert_ids, **kwargs):
        rolled = aggregate(
            [
                _envelope("notable-1", status="resolved"),
                _envelope("notable-2", status="pending_materialization"),
            ]
        )
        rolled["partial"] = False
        return rolled

    _install_run(monkeypatch, attribute=fake_attribute_alerts, persisted=persisted)
    job = progress.start(case_id=CASE_ID, tenant_id=TENANT_ID)
    stopper = asyncio.create_task(_stop_waiting_when_it_starts(job))
    try:
        await runner.run_evaluation(
            SimpleNamespace(),
            tenant_id=TENANT_ID,
            case_id=CASE_ID,
            client=_Client(),
            settings_obj=_settings(),
            job=job,
        )
    finally:
        stopper.cancel()
        progress.finish(job)

    assert persisted, "a stopped wait must still store a verdict"
    assert runner.C.R_WAIT_SKIPPED in persisted[-1]["reason_codes"]
    assert persisted[-1]["status"] == "ok"
    assert persisted[-1]["attribution"]["wait"]["ended"] == "skipped"


@pytest.mark.asyncio
async def test_the_wait_times_out_and_the_run_still_stores(monkeypatch: pytest.MonkeyPatch) -> None:
    """A queue that never drains may not hide the verdict: the cap, then score."""

    persisted: list[dict] = []

    async def fake_attribute_alerts(client, alert_ids, **kwargs):
        rolled = aggregate(
            [
                _envelope("notable-1", status="resolved"),
                _envelope("notable-2", status="pending_materialization"),
            ]
        )
        rolled["partial"] = False
        return rolled

    _install_run(monkeypatch, attribute=fake_attribute_alerts, persisted=persisted)
    settings = _settings()
    settings.AISOC_TKG_WAIT_TIMEOUT_S = 0.2
    job = progress.start(case_id=CASE_ID, tenant_id=TENANT_ID)
    try:
        await runner.run_evaluation(
            SimpleNamespace(),
            tenant_id=TENANT_ID,
            case_id=CASE_ID,
            client=_Client(),
            settings_obj=settings,
            job=job,
        )
    finally:
        progress.finish(job)

    assert persisted, "a timed-out wait must still store a verdict"
    assert runner.C.R_WAIT_TIMEOUT in persisted[-1]["reason_codes"]
    assert persisted[-1]["attribution"]["wait"]["ended"] == "timeout"
    assert persisted[-1]["attribution"]["wait"]["timeout_s"] == 0.2


@pytest.mark.asyncio
async def test_canonical_alerts_are_scored_before_the_witnesses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pass 1 stores a verdict from the canonical members; pass 2 re-scores."""

    persisted: list[dict] = []
    bundle = _bundle()
    bundle["payload"]["alerts"][1]["deduplicated"] = True
    bundle["stats"]["deduplicated"] = 1

    async def fake_attribute_alerts(client, alert_ids, **kwargs):
        rolled = aggregate(
            [
                _envelope("notable-1", status="resolved"),
                _envelope("notable-2", status="resolved"),
            ]
        )
        rolled["partial"] = False
        return rolled

    _install_run(
        monkeypatch, attribute=fake_attribute_alerts, persisted=persisted, bundle=bundle
    )
    job = progress.start(case_id=CASE_ID, tenant_id=TENANT_ID)
    try:
        await runner.run_evaluation(
            SimpleNamespace(),
            tenant_id=TENANT_ID,
            case_id=CASE_ID,
            client=_Client(),
            settings_obj=_settings(),
            job=job,
        )
    finally:
        progress.finish(job)

    assert len(persisted) == 2, [row["reason_codes"] for row in persisted]
    assert runner.C.R_CANONICAL_ONLY in persisted[0]["reason_codes"]
    assert persisted[0]["status"] == "partial"
    assert runner.C.R_CANONICAL_ONLY not in persisted[-1]["reason_codes"]
    assert persisted[-1]["status"] == "ok"
    assert persisted[-1]["attribution"]["phase"] == "dedup"
    # The live stepper names the pass, so the panel can say "duplicates", not just
    # "materialise".
    live = job.snapshot()
    assert live["phase"] == "dedup"
    assert live["phase_index"] == 2
    assert live["phase_count"] == 2
    assert live["phase_total"] == 1


@pytest.mark.asyncio
async def test_the_run_publishes_a_live_result_alert_by_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The panel is not stuck on the previous run while this one works.

    Every envelope the resolve stage returns is folded into a provisional
    evaluation (same rubric as the stored row), so confidence and the table rows
    move during the run — the analyst can judge after the first few alerts, and
    a cancel still keeps that work.
    """

    persisted: list[dict] = []
    snapshots: list[dict] = []
    job_holder: dict = {}

    async def fake_attribute_alerts(client, alert_ids, **kwargs):
        on_envelope = kwargs.get("on_envelope")
        envelopes = [
            _envelope("notable-1", status="resolved"),
            _envelope("notable-2", status="resolved"),
        ]
        for envelope in envelopes:
            if on_envelope is not None:
                await on_envelope(envelope)
            job = job_holder["job"]
            snapshots.append(job.snapshot().get("partial"))
        rolled = aggregate(envelopes)
        rolled["partial"] = False
        return rolled

    _install_run(monkeypatch, attribute=fake_attribute_alerts, persisted=persisted)
    job = progress.start(case_id=CASE_ID, tenant_id=TENANT_ID)
    job_holder["job"] = job
    try:
        await runner.run_evaluation(
            SimpleNamespace(),
            tenant_id=TENANT_ID,
            case_id=CASE_ID,
            client=_Client(),
            settings_obj=_settings(),
            job=job,
        )
    finally:
        progress.finish(job)

    live = [snapshot for snapshot in snapshots if snapshot]
    assert live, "the run must publish a partial evaluation while resolving"
    first = live[0]
    assert first["status"] == "provisional"
    assert first["confidence"] == 50
    assert len(first["attribution"]["alerts"]) == 1
    assert first["attribution"]["alerts"][0]["alert_id"] == "notable-1"
    # ... and the live row is the one a cancel stores.
    assert job.partial is not None
    assert len(job.partial["attribution"]["alerts"]) == 2
    assert job.partial_store and job.partial_store["fingerprint"] == "fp"


@pytest.mark.asyncio
async def test_a_stopped_run_stores_what_it_already_scored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancel is not "throw the work away": the provisional result is persisted."""

    persisted: list[dict] = []

    async def fake_attribute_alerts(client, alert_ids, **kwargs):
        rolled = aggregate([_envelope("notable-1", status="resolved")])
        rolled["partial"] = False
        return rolled

    _install_run(monkeypatch, attribute=fake_attribute_alerts, persisted=persisted)
    job = progress.start(case_id=CASE_ID, tenant_id=TENANT_ID)
    try:
        await runner.run_evaluation(
            SimpleNamespace(),
            tenant_id=TENANT_ID,
            case_id=CASE_ID,
            client=_Client(),
            settings_obj=_settings(),
            job=job,
        )
    finally:
        progress.finish(job)

    job.partial = job.partial or {
        "verdict": "needs_more_evidence",
        "confidence": 57,
        "passes": None,
        "agree": None,
        "reasons": [],
        "attribution": {"alerts": [_envelope("notable-1", status="resolved")], "resolved": 1},
    }
    stored = await runner.persist_provisional(SimpleNamespace(), job)

    assert stored is not None
    assert persisted[-1]["status"] == "partial"
    assert runner.C.R_RUN_STOPPED_PARTIAL in persisted[-1]["reason_codes"]
    assert persisted[-1]["confidence"] == job.partial["confidence"]
    assert persisted[-1]["resolved_count"] == 1
