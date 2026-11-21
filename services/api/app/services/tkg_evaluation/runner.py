"""Orchestrate one TKG evaluation and persist it.

Nothing here blocks a case's normal workflow: the worst outcome is a stored row
with ``status='unavailable'`` and a reason code, and the case's own correlation
verdict is never touched.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text

from app.services.tkg_evaluation import constants as C
from app.services.tkg_evaluation import progress
from app.services.tkg_evaluation.attribution import aggregate, attribute_alerts
from app.services.tkg_evaluation.bundle import build_bundle
from app.services.tkg_evaluation.client import TkgClient, TkgError, config_from_settings
from app.services.tkg_evaluation.judge import LlmCall
from app.services.tkg_evaluation.judge import judge as run_judge
from app.services.tkg_evaluation.rubric import evidence_floor, precheck, reconcile
from app.services.tkg_evaluation.sender import RecordError, build_curated_record
from app.services.tkg_evaluation.store import load_alerts, load_case, load_case_scope

logger = logging.getLogger(__name__)

#: How many missing alerts one run may push. Sending is spaced (the graph's
#: extractor rate-limits its own model), so an unbounded batch would push the run
#: past the panel's three-minute limit. Anything over this is left for the next
#: run, which sends only what is still unknown.
MAX_SEND_PER_RUN = 60

#: Alerts one wave re-probes. Re-reading every queued alert on every wave made a
#: wave slower than the poll interval, so a 60 s window fitted only three waves
#: and the panel stopped at "3 of 12". Waves now take a rotating slice: 12 waves
#: still cover the whole queue (several times over) while each stays cheap enough
#: to fit the panel's polling budget.
WAVE_PROBE_LIMIT = 24


async def _cached(db: Any, case_id: UUID, tenant_id: UUID, fingerprint: str, ttl_s: int) -> dict[str, Any] | None:
    if ttl_s <= 0:
        return None
    cutoff = datetime.now(UTC) - timedelta(seconds=ttl_s)
    row = (
        await db.execute(
            text(
                "SELECT id, verdict, confidence, passes, agree, reasons, attribution, input_payload, "
                "       status, reason_codes, kb_id, profile, alert_count, resolved_count, created_at "
                "FROM case_tkg_evaluations "
                "WHERE case_id = :case_id AND tenant_id = :tenant_id "
                "  AND payload_fingerprint = :fp AND created_at >= :cutoff "
                "ORDER BY created_at DESC LIMIT 1"
            ).bindparams(case_id=case_id, tenant_id=tenant_id, fp=fingerprint, cutoff=cutoff)
        )
    ).fetchone()
    if not row:
        return None
    return {
        "evaluation_id": str(row.id),
        "status": row.status,
        "reason_codes": list(row.reason_codes or []) + [C.R_CACHED],
        "verdict": row.verdict,
        "confidence": row.confidence,
        "passes": row.passes,
        "agree": row.agree,
        "reasons": list(row.reasons or []),
        "attribution": row.attribution or {},
        "input_payload": row.input_payload,
        "kb_id": row.kb_id,
        "profile": row.profile,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "stats": {
            "alerts": row.alert_count,
            "resolved": row.resolved_count,
            "cached": True,
        },
    }


async def _persist(db: Any, **values: Any) -> Any:
    from app.models.tkg_evaluation import CaseTkgEvaluation

    row = CaseTkgEvaluation(**values)
    db.add(row)
    await db.commit()
    return row


def _result(row: Any, *, stats: dict[str, Any] | None = None, detail: str | None = None) -> dict[str, Any]:
    payload = {
        "evaluation_id": str(row.id) if getattr(row, "id", None) else None,
        "status": row.status,
        "reason_codes": list(row.reason_codes or []),
        "verdict": row.verdict,
        "confidence": row.confidence,
        "passes": row.passes,
        "agree": row.agree,
        "reasons": list(row.reasons or []),
        "attribution": row.attribution or {},
        "input_payload": row.input_payload,
        "kb_id": row.kb_id,
        "profile": row.profile,
        "created_at": row.created_at.isoformat() if getattr(row, "created_at", None) else None,
        "stats": stats or {"alerts": row.alert_count, "resolved": row.resolved_count},
    }
    if detail:
        payload["detail"] = detail
    return payload


def _merge_attribution(attribution: dict[str, Any], retry: dict[str, Any]) -> dict[str, Any]:
    """Fold a re-probe into the attribution, keeping each row's display identity."""

    replacement = {str(item["alert_id"]): item for item in retry.get("alerts") or []}
    if not replacement:
        return attribution
    merged: list[dict[str, Any]] = []
    for envelope in attribution["alerts"]:
        fresh = replacement.get(str(envelope["alert_id"]))
        if fresh is None:
            merged.append(envelope)
            continue
        # Keep the identity the panel already shows (title, dedup badges) while
        # adopting the new status and facts.
        for key in (
            "deduplicated",
            "occurrence_count",
            "row_id",
            "title",
            "rule",
            "severity",
            "time",
            "techniques",
        ):
            fresh.setdefault(key, envelope.get(key))
        merged.append(fresh)
    rolled = aggregate(merged)
    # aggregate() rebuilds from the envelopes; the run-level flags it did not see
    # (completeness of the first pass, what this run sent) must survive.
    for key in ("partial", "send", "wait", "phase"):
        if key in attribution:
            rolled[key] = attribution[key]
    return rolled


async def _send_unknown_alerts(
    tkg: TkgClient,
    *,
    attribution: dict[str, Any],
    raw_by_row: dict[str, Any],
    delay: float,
    job: progress.RunJob | None,
    on_progress: Any = None,
) -> dict[str, Any]:
    """Push the alerts the graph answered ``not_found`` for, and report every outcome.

    Bounded by what the run already resolved (never a blind backfill), spaced by
    ``delay`` because the graph's extractor rate-limits its own model. A rejected
    record is reported as a send problem, not left to look like a graph problem.

    One alert at a time, and every outcome is mirrored onto the live attribution
    before the next send: an accepted record becomes ``pending_materialization``
    (the graph has it, it is just not projected yet) and ``on_progress`` republishes
    the provisional result, so the panel's rows and send counts move while the
    batch runs instead of only at the end.
    """

    missing = [item for item in attribution.get("alerts") or [] if str(item.get("status")) == "not_found"]
    unknown = missing[:MAX_SEND_PER_RUN]
    report: dict[str, Any] = {
        "eligible": len(missing),
        "deferred": len(missing) - len(unknown),
        "sent": [],
        "rejected": [],
        "failed": [],
    }
    #: Set when the graph answered 429: the batch stops instead of queueing more
    #: work the extractor cannot take.
    report["stopped"] = None
    if not unknown:
        return report
    if job is not None:
        job.touch(message=f"sending {len(unknown)} alert(s) the graph does not know")
    try:
        source_id, ingest_token = await tkg.ensure_source()
    except TkgError as exc:
        report["error"] = exc.code
        return report

    for index, envelope in enumerate(unknown):
        row = raw_by_row.get(str(envelope.get("row_id") or ""))
        if row is None:
            report["failed"].append({"notable_id": str(envelope.get("alert_id")), "error": "no_payload"})
            continue
        try:
            record, _warnings = build_curated_record(row)
        except RecordError as exc:
            report["rejected"].append({"notable_id": str(envelope.get("alert_id")), "error": exc.code})
            continue
        if index and delay > 0:
            await asyncio.sleep(delay)
        try:
            response = await tkg.ingest(source_id, ingest_token, {"profile": C.PROFILE, "record": record})
        except TkgError as exc:
            if exc.status == 429:
                # The graph is out of ingest budget. Pushing the rest would only
                # add more receipts it cannot process, which is exactly how a
                # batch ends up failed on the extractor (they surface as
                # ``soc_document_failed``). Stop the batch and say so.
                report["stopped"] = C.R_TKG_RATE_LIMITED
                report["failed"].append({"notable_id": record["notable_id"], "error": exc.code})
                break
            bucket = report["rejected"] if exc.status == 422 else report["failed"]
            bucket.append({"notable_id": record["notable_id"], "error": exc.code})
            continue
        if response.get("receipt_id"):
            report["sent"].append({"notable_id": record["notable_id"], "receipt_id": response.get("receipt_id")})
            # Accepted is not resolved: the graph has the record and is still
            # projecting it. Say so in the same row the table renders.
            envelope["status"] = "pending_materialization"
            envelope["error"] = None
        else:
            report["failed"].append({"notable_id": record["notable_id"], "error": "no_receipt_id"})
        if job is not None:
            job.touch(
                message=(
                    f"sent {len(report['sent'])}/{len(unknown)} missing alert(s)"
                    + (f"; {len(report['rejected'])} rejected" if report["rejected"] else "")
                )
            )
        if on_progress is not None:
            on_progress()
    if job is not None:
        job.touch(
            message=(
                f"sent {len(report['sent'])}/{len(unknown)} missing alert(s) to the graph"
                + (f"; {len(report['rejected'])} rejected" if report["rejected"] else "")
                + (f"; {len(report['failed'])} failed" if report["failed"] else "")
                + (f"; {report['deferred']} left for the next run" if report["deferred"] else "")
            )
        )
    return report


async def _graph_failures(
    tkg: TkgClient,
    *,
    attribution: dict[str, Any],
    send_report: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Name the queued alerts the graph has already given up on.

    ``knowledge/resolve`` answers ``pending_materialization`` for a record the
    graph accepted, and it keeps answering that forever when the extractor died
    on it — the run then waits on documents that will never be projected. The
    receipts list carries the answer (``failure_code='soc_document_failed'``,
    usually an LLM 429 after the extractor's own five retries).

    Returns a report only when *every* alert still queued is dead: a single
    dead document next to live ones is worth waiting for, and naming it as a
    graph failure would stop the run early.
    """

    pending = [
        str(envelope["alert_id"])
        for envelope in attribution.get("alerts") or []
        if str(envelope.get("status") or "") == "pending_materialization"
    ]
    receipt_by_notable = {
        str(item["notable_id"]): str(item["receipt_id"]) for item in (send_report or {}).get("sent") or [] if item.get("receipt_id")
    }
    if not pending or not receipt_by_notable:
        return None
    try:
        body = await tkg.receipts()
    except TkgError as exc:
        logger.info("tkg receipts unavailable while waiting: %s", exc.code)
        return None

    dead = {}
    for row in body.get("receipts") or []:
        if not isinstance(row, dict):
            continue
        receipt_id = str(row.get("receipt_id") or "")
        code = row.get("failure_code")
        if not receipt_id or not code:
            continue
        # ``job_status='failed'`` is terminal on the graph: its worker only writes
        # that once no retry is scheduled (a retryable failure goes back to
        # ``queued``, an exhausted one to ``failed``). So a receipt whose job is
        # failed will never be projected, whatever the code says.
        if code in C.RECEIPT_FAILED_CODES or str(row.get("job_status") or "") == "failed":
            dead[receipt_id] = str(code)
    failing = [
        {
            "notable_id": notable_id,
            "receipt_id": receipt_by_notable[notable_id],
            "error": dead[receipt_by_notable[notable_id]],
        }
        for notable_id in pending
        if receipt_by_notable.get(notable_id) in dead
    ]
    if len(failing) < len(pending):
        return None
    return {
        "count": len(failing),
        "error": sorted({item["error"] for item in failing})[0],
        "alerts": failing[:60],
    }


#: How long one wait pass may hold a run before it scores what it already has.
#: A queue that never drains must not make the verdict unreachable, and a few
#: hundred soft-dedup witnesses waiting on the graph must not hide the verdict the
#: canonical alerts already earned. ``0`` restores the old open-ended wait.
WAIT_TIMEOUT_DEFAULT_S = 600.0


def _phase_of(item: dict[str, Any]) -> str:
    """Which pass an alert belongs to: canonical members first, witnesses last."""

    return "dedup" if item.get("deduplicated") else "canonical"


def _decorate(attribution: dict[str, Any], alert_meta: dict[str, Any]) -> None:
    """Give every envelope the display identity the table renders.

    Re-applied after each re-probe: a merged envelope carries the new status and
    facts, and would otherwise lose its title, rule and dedup badge.
    """

    for envelope in attribution["alerts"]:
        meta = alert_meta.get(envelope["alert_id"]) or {}
        envelope["deduplicated"] = bool(meta.get("deduplicated"))
        envelope["occurrence_count"] = meta.get("occurrence_count")
        envelope["row_id"] = meta.get("alert_id")
        envelope["title"] = str(meta.get("title") or "")[:240] or None
        envelope["rule"] = str(meta.get("rule") or "")[:200] or None
        envelope["severity"] = meta.get("severity")
        envelope["time"] = meta.get("time")
        envelope["techniques"] = list(meta.get("techniques") or [])[:6]


def _merge_send_report(attribution: dict[str, Any], label: str, report: dict[str, Any]) -> None:
    """Fold one pass's send report into the run-level one the panel reads."""

    rolled = attribution.get("send")
    if not isinstance(rolled, dict):
        rolled = {"eligible": 0, "deferred": 0, "sent": [], "rejected": [], "failed": [], "phases": {}}
        attribution["send"] = rolled
    for key in ("sent", "rejected", "failed"):
        rolled.setdefault(key, []).extend(report.get(key) or [])
    rolled["eligible"] = int(rolled.get("eligible") or 0) + int(report.get("eligible") or 0)
    rolled["deferred"] = int(rolled.get("deferred") or 0) + int(report.get("deferred") or 0)
    if report.get("stopped"):
        rolled["stopped"] = report["stopped"]
    if report.get("error"):
        rolled["error"] = report["error"]
    rolled.setdefault("phases", {})[label] = {
        "eligible": int(report.get("eligible") or 0),
        "sent": len(report.get("sent") or []),
        "rejected": len(report.get("rejected") or []),
        "failed": len(report.get("failed") or []),
        "deferred": int(report.get("deferred") or 0),
        "stopped": report.get("stopped"),
    }


#: Envelope keys the live panel renders. Everything else (fact samples,
#: limitations) is the weight of the payload, not something a row displays.
_LEAN_KEYS = (
    "alert_id",
    "row_id",
    "title",
    "rule",
    "severity",
    "time",
    "techniques",
    "status",
    "entity_id",
    "facts",
    "synthetic_facts",
    "pass",
    "error",
    "deduplicated",
    "occurrence_count",
)


def _lean_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    return {key: envelope.get(key) for key in _LEAN_KEYS}


def _provisional_payload(
    *,
    attribution: dict[str, Any],
    bundle: dict[str, Any],
    engine_verdict: str | None,
    cfg: Any,
    duration_ms: int,
    label: str | None,
) -> dict[str, Any]:
    """Score the attribution as it stands *right now*, without storing it.

    This is the number the panel shows while the run is in flight. It uses the
    same rubric as the stored row (:func:`evidence_floor` + :func:`reconcile`),
    so confidence grows as alerts resolve instead of appearing only at the end —
    and it is what a cancelled run persists, so minutes of work are not lost.
    """

    total = len(bundle["payload"]["alerts"])
    passes = attribution.get("passes") or {"none": 0, "unconfirmed": 0, "corroborated": 0, "contextualized": 0}
    floor = evidence_floor(
        total_alerts=total,
        passes=passes,
        synthetic_only=bool(attribution.get("synthetic_only")),
    )
    merged = reconcile(floor=floor, judged=None, engine_verdict=engine_verdict)
    return {
        "evaluation_id": None,
        "status": "provisional",
        "reason_codes": [],
        "verdict": merged["verdict"],
        "confidence": merged["confidence"],
        "passes": merged["passes"],
        "agree": merged["agree"],
        "reasons": merged["reasons"],
        "attribution": {
            "alerts": [_lean_envelope(envelope) for envelope in attribution.get("alerts") or []],
            "send": attribution.get("send"),
            "passes": passes,
            "resolved": attribution.get("resolved", 0),
            "facts": attribution.get("facts", 0),
            "real_facts": attribution.get("real_facts", 0),
            "synthetic_facts": attribution.get("synthetic_facts", 0),
            "synthetic_only": attribution.get("synthetic_only", False),
            "partial": attribution.get("partial", False),
            "phase": label,
        },
        "input_payload": None,
        "kb_id": cfg.kb_id or None,
        "profile": C.PROFILE,
        "created_at": datetime.now(UTC).isoformat(),
        "stats": {
            "alerts": total,
            "resolved": attribution.get("resolved", 0),
            "coverage": floor["coverage"],
            "provisional": True,
            "phase": label,
            "duration_ms": duration_ms,
        },
    }


async def persist_provisional(db: Any, job: progress.RunJob | None) -> dict[str, Any] | None:
    """Store the live provisional result so a stopped run keeps its work.

    A cancel or a failure used to store nothing, which threw away every alert the
    run had already resolved and scored. The row is ``partial`` and carries
    :data:`constants.R_RUN_STOPPED_PARTIAL`, so it reads as "stopped early", not
    as a finished verdict.
    """

    if job is None or not job.partial or not job.partial_store:
        return None
    hint = job.partial_store
    partial = job.partial
    attribution = partial.get("attribution") or {}
    row = await _persist(
        db,
        tenant_id=hint["tenant_id"],
        case_id=hint["case_id"],
        requested_by=hint.get("requested_by"),
        status="partial",
        reason_codes=[C.R_RUN_STOPPED_PARTIAL],
        detail="The run was stopped before it finished; this row holds what it had scored.",
        engine_verdict=hint.get("engine_verdict"),
        verdict=partial.get("verdict"),
        confidence=partial.get("confidence"),
        passes=partial.get("passes"),
        agree=partial.get("agree"),
        payload_fingerprint=hint.get("fingerprint"),
        input_payload=None,
        attribution=attribution,
        reasons=partial.get("reasons") or [],
        kb_id=hint.get("kb_id"),
        profile=C.PROFILE,
        alert_count=int(hint.get("alert_count") or 0),
        resolved_count=int(attribution.get("resolved") or 0),
        duration_ms=int(hint.get("duration_ms") or 0),
        created_at=datetime.utcnow(),
    )
    return _result(
        row,
        stats={
            "alerts": hint.get("alert_count") or 0,
            "resolved": attribution.get("resolved") or 0,
            "provisional": True,
            "stopped": True,
        },
    )


async def _interruptible_sleep(seconds: float, job: progress.RunJob | None) -> None:
    """Sleep, but wake within half a second when the operator cancels or stops waiting."""

    remaining = max(0.0, float(seconds))
    while remaining > 0:
        if job is not None and (job.cancelled or job.skip_wait.is_set()):
            return
        step = min(0.5, remaining)
        await asyncio.sleep(step)
        remaining -= step


async def _wait_for_materialisation(
    tkg: TkgClient,
    *,
    attribution: dict[str, Any],
    synthetic_ids: set[str],
    poll_s: float,
    timeout_s: float,
    job: progress.RunJob | None,
    label: str,
    on_progress: Any = None,
) -> dict[str, Any]:
    """Re-probe queued alerts until they are projected, the graph gives up, or we stop.

    Four endings, and none of them is a silent timer: ``drained`` (the normal
    case), ``skipped`` (the operator pressed *stop waiting*), ``timeout``
    (``AISOC_TKG_WAIT_TIMEOUT_S`` elapsed) and ``failed`` (the graph itself
    reported every queued document as failed).

    ``skipped`` and ``timeout`` are not errors: the run still judges and stores,
    because a few hundred witnesses stuck in the graph's queue must not make the
    verdict unreachable. A full run cancel keeps using the same checkpoint as
    every other stage, and still stores nothing.
    """

    pending = int(attribution.get("pending") or 0)
    outcome: dict[str, Any] = {
        "ended": "drained",
        "phase": label,
        "waves": 0,
        "probes": 0,
        "pending": pending,
        "seconds": 0.0,
        "timeout_s": timeout_s,
    }
    if pending <= 0:
        attribution["wait"] = outcome
        return outcome
    if attribution.get("partial"):
        outcome["ended"] = "partial_first_pass"
        attribution["wait"] = outcome
        return outcome

    started = time.monotonic()
    wave_budget_s = max(10.0, poll_s * 2)
    probe_cursor = 0
    probed_total = 0
    wave = 0
    while int(attribution.get("pending") or 0) > 0:
        wave += 1
        progress.checkpoint(job)
        if job is not None and job.skip_wait.is_set():
            outcome["ended"] = "skipped"
            break
        elapsed = time.monotonic() - started
        if timeout_s > 0 and elapsed >= timeout_s:
            outcome["ended"] = "timeout"
            break
        if job is not None:
            job.touch(
                stage="materialise",
                wave=wave,
                wait_left_s=max(0, int(round(timeout_s - elapsed))) if timeout_s > 0 else -1,
                message=(
                    f"{label}: wave {wave} — {attribution['pending']} alert(s) accepted, "
                    "not projected yet (stop waiting to score what is resolved)"
                ),
            )
        await _interruptible_sleep(poll_s, job)
        progress.checkpoint(job)
        if job is not None and job.skip_wait.is_set():
            outcome["ended"] = "skipped"
            break

        queued = [
            str(envelope["alert_id"])
            for envelope in attribution["alerts"]
            if str(envelope.get("status") or "") == "pending_materialization"
        ]
        if not queued:
            break
        # Rotate through the queue so every alert is re-probed even when the queue
        # is larger than one wave's slice.
        if probe_cursor >= len(queued):
            probe_cursor = 0
        slice_ids = queued[probe_cursor : probe_cursor + WAVE_PROBE_LIMIT]
        if len(slice_ids) < WAVE_PROBE_LIMIT:
            slice_ids += queued[: WAVE_PROBE_LIMIT - len(slice_ids)]
        probe_cursor = (probe_cursor + len(slice_ids)) % max(1, len(queued))
        retry = await attribute_alerts(tkg, slice_ids, synthetic_doc_ids=synthetic_ids, budget_s=wave_budget_s)
        probed_this_wave = sum(1 for item in retry["alerts"] if str(item.get("error") or "") != C.R_BUDGET)
        probed_total += probed_this_wave
        rolled = _merge_attribution(attribution, retry)
        # Merge in place: the caller keeps the same dict, so the statuses the
        # judge and the stored row read are the ones this wave just probed.
        attribution.clear()
        attribution.update(rolled)
        pending_now = int(attribution.get("pending") or 0)
        if pending_now:
            failures = await _graph_failures(tkg, attribution=attribution, send_report=attribution.get("send"))
            if failures:
                attribution["graph_failures"] = failures
                outcome["ended"] = "failed"
                if job is not None:
                    job.touch(
                        stage="judge",
                        pending=pending_now,
                        message=(
                            f"the graph gave up on {failures['count']} document(s) "
                            f"({failures['error']}): the extractor is rate-limited, so "
                            "waiting cannot materialise them — refresh those documents in "
                            "the TKG Library, then re-run"
                        ),
                    )
                break
        if on_progress is not None:
            on_progress()
        if job is not None:
            job.touch(
                pending=pending_now,
                resolved=attribution["resolved"],
                facts=attribution["facts"],
                message=(
                    f"{label}: all queued alerts materialised after {wave} wave(s)"
                    if not pending_now
                    else (
                        f"{label}: wave {wave} probed {probed_this_wave}/{len(slice_ids)} "
                        f"of the queued set before the wave budget "
                        f"({probed_total} re-probes so far); {pending_now} still queued"
                        if probed_this_wave < len(slice_ids)
                        else (f"{label}: wave {wave}, {probed_total} re-probes so far, {pending_now} still queued in the graph")
                    )
                ),
            )

    outcome["waves"] = wave
    outcome["probes"] = probed_total
    outcome["pending"] = int(attribution.get("pending") or 0)
    outcome["seconds"] = round(time.monotonic() - started, 1)
    attribution["wait"] = outcome
    if job is not None:
        job.touch(stage="judge", pending=outcome["pending"])
    return outcome


async def _score_and_store(
    db: Any,
    *,
    tenant_id: UUID,
    case_id: UUID,
    requested_by: UUID | None,
    engine_verdict: str | None,
    bundle: dict[str, Any],
    alerts: list[dict[str, Any]],
    attribution: dict[str, Any],
    started: float,
    call_llm: LlmCall | None,
    cfg: Any,
    fingerprint: str | None,
    job: progress.RunJob | None,
    label: str,
    interim: bool,
) -> dict[str, Any]:
    """Score the attribution as it stands and store one row.

    Called once per pass. ``interim`` marks the canonical-only row that exists so
    a verdict is available before the witnesses are pushed; the second pass
    supersedes it with the full evaluation.
    """

    attribution["phase"] = label
    floor = evidence_floor(
        total_alerts=len(bundle["payload"]["alerts"]),
        passes=attribution["passes"],
        synthetic_only=attribution["synthetic_only"],
    )
    progress.checkpoint(job)

    judged: dict[str, Any] | None = None
    judge_error: str | None = None
    if call_llm is not None:
        outcome = await run_judge(
            {"case": bundle["payload"]["case"], "facts": attribution.get("fact_samples")},
            attribution,
            call_llm,
        )
        judged = outcome.get("judged")
        judge_error = outcome.get("error")

    merged = reconcile(floor=floor, judged=judged, engine_verdict=engine_verdict)

    codes: list[str] = []
    if attribution.get("graph_failures"):
        codes.append(C.R_TKG_EXTRACTION_FAILED)
    wait = attribution.get("wait") or {}
    if wait.get("ended") == "skipped":
        codes.append(C.R_WAIT_SKIPPED)
    elif wait.get("ended") == "timeout":
        codes.append(C.R_WAIT_TIMEOUT)
    if interim:
        codes.append(C.R_CANONICAL_ONLY)
    if attribution["partial"]:
        codes.append(C.R_PARTIAL)
    if attribution["synthetic_only"]:
        codes.append(C.R_SYNTHETIC_ONLY)
    if floor["coverage"] < C.MIN_COVERAGE_FOR_CONFIRM:
        codes.append(C.R_LOW_COVERAGE)
    if floor["coverage"] == 0:
        codes.append(C.R_EMPTY_CONTEXT)
    if judge_error:
        codes.append(C.R_JUDGE_INVALID if "invalid" in judge_error else C.R_JUDGE_UNAVAILABLE)

    progress.checkpoint(job)
    if job is not None:
        job.touch(stage="persist")

    duration_ms = int((time.perf_counter() - started) * 1000)
    row = await _persist(
        db,
        tenant_id=tenant_id,
        case_id=case_id,
        requested_by=requested_by,
        status="partial" if (attribution["partial"] or interim) else "ok",
        reason_codes=codes,
        detail=judge_error,
        engine_verdict=engine_verdict,
        verdict=merged["verdict"],
        confidence=merged["confidence"],
        passes=merged["passes"],
        agree=merged["agree"],
        payload_fingerprint=fingerprint,
        input_payload=bundle.get("payload"),
        attribution=attribution,
        reasons=merged["reasons"],
        kb_id=cfg.kb_id or None,
        profile=C.PROFILE,
        alert_count=len(alerts),
        resolved_count=attribution["resolved"],
        duration_ms=duration_ms,
        created_at=datetime.utcnow(),
    )
    return _result(
        row,
        stats={
            **(bundle.get("stats") or {}),
            "resolved": attribution["resolved"],
            "facts": attribution["facts"],
            "real_facts": attribution["real_facts"],
            "synthetic_facts": attribution["synthetic_facts"],
            "passes": attribution["passes"],
            "deduplicated": (bundle.get("stats") or {}).get("deduplicated", 0),
            "coverage": floor["coverage"],
            "duration_ms": duration_ms,
            "phase": label,
            "interim": interim,
            "pending": int(attribution.get("pending") or 0),
            "wait": attribution.get("wait"),
        },
    )


async def run_evaluation(
    db: Any,
    *,
    tenant_id: UUID,
    case_id: UUID,
    requested_by: UUID | None = None,
    engine_verdict: str | None = None,
    refresh: bool = False,
    client: TkgClient | None = None,
    settings_obj: Any | None = None,
    call_llm: LlmCall | None = None,
    job: progress.RunJob | None = None,
    send_missing: bool = True,
) -> dict[str, Any]:
    """Evaluate one case. Returns the persisted payload (never raises on TKG errors).

    ``job`` is the live-progress handle the panel polls: every stage transition
    and every finished alert is written to it, and a cancelled job aborts the run
    at the next checkpoint.

    ``send_missing`` lets one button do everything: when the deployment enabled
    ``AISOC_TKG_ALLOW_SEND``, a run first pushes the alerts the graph does not
    know (a bounded, spaced batch), then resolves them like the rest. With the
    flag off the run stays read-only and those alerts come back ``not_found``.
    """

    started = time.perf_counter()
    cfg = config_from_settings(settings_obj)
    max_alerts = int(getattr(settings_obj, "AISOC_TKG_MAX_ALERTS", C.MAX_ALERTS) or C.MAX_ALERTS)
    budget_ms = int(getattr(settings_obj, "AISOC_TKG_BUDGET_MS", C.DEFAULT_BUDGET_MS) or C.DEFAULT_BUDGET_MS)
    ttl_s = int(getattr(settings_obj, "AISOC_TKG_CACHE_TTL_S", 900) or 0)
    synthetic_docs = getattr(settings_obj, "AISOC_TKG_SYNTHETIC_DOC_IDS", "") or ""
    synthetic_ids = {value.strip() for value in str(synthetic_docs).split(",") if value.strip()}

    case = await load_case(db, case_id, tenant_id)
    if not case:
        raise LookupError("Case not found.")

    excluded, filters = await load_case_scope(db, case_id, tenant_id)
    alerts = await load_alerts(db, tenant_id, case_id, [str(value) for value in case["alert_ids"]], set(excluded))

    bundle = build_bundle(case=case, alerts=alerts, scope={"excluded": excluded, "filters": filters}, max_alerts=max_alerts)
    fingerprint = (bundle.get("stats") or {}).get("fingerprint")

    if job is not None:
        job.touch(stage="precheck", total=len(alerts))
        if fingerprint:
            job.touch(message="checking the cache")

    if not refresh and fingerprint:
        cached = await _cached(db, case_id, tenant_id, fingerprint, ttl_s)
        if cached:
            return cached

    progress.checkpoint(job)

    def _reject(status: str, codes: list[str], detail: str) -> dict[str, Any]:
        return {
            "evaluation_id": None,
            "status": status,
            "reason_codes": codes,
            "verdict": None,
            "confidence": None,
            "passes": None,
            "agree": None,
            "reasons": [],
            "attribution": {},
            "input_payload": None,
            "kb_id": cfg.kb_id or None,
            "profile": C.PROFILE,
            "created_at": datetime.now(UTC).isoformat(),
            "detail": detail,
            "stats": (bundle.get("stats") or {}),
        }

    pre = precheck(bundle) if bundle.get("ok") else {"eligible": False, "checks": []}
    if not bundle.get("ok") or not pre.get("eligible"):
        codes = [bundle.get("reason") or C.R_PRECHECK_FAILED]
        codes.extend(f"precheck:{check['id']}" for check in pre.get("checks", []) if not check.get("ok"))
        # The bundle's own explanation ("12 distinct alerts exceed the cap") is the
        # one the operator can act on; the rubric checks are appended after it.
        detail_parts = [check["detail"] for check in pre.get("checks", []) if not check.get("ok")]
        if bundle.get("detail"):
            detail_parts.insert(0, str(bundle["detail"]))
        detail = "; ".join(detail_parts) or None
        if alerts:
            await _persist(
                db,
                tenant_id=tenant_id,
                case_id=case_id,
                requested_by=requested_by,
                status="ineligible",
                reason_codes=codes,
                detail=detail,
                engine_verdict=engine_verdict,
                kb_id=cfg.kb_id or None,
                profile=C.PROFILE,
                alert_count=len(alerts),
                payload_fingerprint=fingerprint,
                attribution={"precheck": pre},
            )
        return _reject("ineligible", codes, detail or "precheck refused the run")

    own_client = client is None
    tkg = client or TkgClient(cfg)
    try:
        if not cfg.configured and own_client:
            codes = [C.R_TKG_NOT_CONFIGURED]
            row = await _persist(
                db,
                tenant_id=tenant_id,
                case_id=case_id,
                requested_by=requested_by,
                status="unavailable",
                reason_codes=codes,
                engine_verdict=engine_verdict,
                kb_id=None,
                profile=C.PROFILE,
                alert_count=len(alerts),
                payload_fingerprint=fingerprint,
                input_payload=bundle.get("payload"),
            )
            payload = _result(row, stats=bundle.get("stats"))
            payload["detail"] = "Set AISOC_TKG_URL / EMAIL / PASSWORD / KB_ID to enable evaluation."
            return payload

        # Graph-level readiness only. A single alert that never made it into the
        # graph is a *finding* (low coverage), not a reason to refuse the run.
        readiness = await tkg.readiness()
        if not readiness.get("ready"):
            # Keep the distinction the probe already made: a 404 on a KB path
            # (or an id that is not a UUID) is ``tkg_kb_missing`` — a setting the
            # operator can fix in a minute — while a timeout, a 5xx or a
            # rejected login stays ``tkg_unreachable``. Collapsing both into
            # "the graph did not answer" hides the fixable one. A graph that
            # answered with zero entities is also a KB problem.
            error = readiness.get("error")
            if error == C.R_TKG_KB_MISSING or not error:
                codes = [C.R_TKG_KB_MISSING]
            else:
                codes = [C.R_TKG_UNREACHABLE]
            row = await _persist(
                db,
                tenant_id=tenant_id,
                case_id=case_id,
                requested_by=requested_by,
                status="unavailable",
                reason_codes=codes,
                engine_verdict=engine_verdict,
                kb_id=cfg.kb_id or None,
                profile=C.PROFILE,
                alert_count=len(alerts),
                payload_fingerprint=fingerprint,
                input_payload=bundle.get("payload"),
                attribution={"readiness": readiness},
            )
            payload = _result(row, stats=bundle.get("stats"))
            payload["detail"] = "; ".join(check["detail"] for check in readiness.get("checks", []) if not check.get("ok"))
            return payload

        alert_meta = {str(alert.get("notable_id") or alert["alert_id"]): alert for alert in bundle["payload"]["alerts"]}

        if job is not None:
            job.touch(stage="resolve", total=len(bundle["payload"]["alerts"]), message=None)
            job.partial_store = {
                "tenant_id": tenant_id,
                "case_id": case_id,
                "requested_by": requested_by,
                "engine_verdict": engine_verdict,
                "fingerprint": fingerprint,
                "kb_id": cfg.kb_id or None,
                "alert_count": len(alerts),
            }

        # The live evaluation: envelopes as they come back, then the rolled-up
        # attribution once the resolve stage ends. `publish_live` re-scores it with
        # the same rubric as a stored row, so the panel's confidence and rows move
        # while the run is in flight and a cancel keeps the work.
        live: dict[str, Any] = {"envelopes": [], "attribution": None, "label": None}
        last_publish = [0.0]

        def publish_live(force: bool = False) -> None:
            if job is None:
                return
            now = time.monotonic()
            if not force and now - last_publish[0] < 0.5:
                return
            last_publish[0] = now
            attribution_now = live["attribution"]
            if attribution_now is not None:
                # Re-aggregate: a send or a re-probe mutates the envelopes without
                # rewriting the rolled-up totals, and the live numbers must follow.
                rolled = aggregate(attribution_now.get("alerts") or [])
                _decorate(rolled, alert_meta)
                for key in ("send", "wait", "phase", "graph_failures", "partial"):
                    if key in attribution_now:
                        rolled[key] = attribution_now[key]
                attribution_now = rolled
            else:
                if not live["envelopes"]:
                    return
                attribution_now = aggregate(live["envelopes"])
                _decorate(attribution_now, alert_meta)
            job.touch(
                partial=_provisional_payload(
                    attribution=attribution_now,
                    bundle=bundle,
                    engine_verdict=engine_verdict,
                    cfg=cfg,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                    label=live["label"],
                )
            )

        async def track(envelope: dict[str, Any]) -> None:
            """Move the panel's counters as each alert comes back."""

            if job is None:
                return
            job.touch(probed=job.probed + 1)
            if envelope.get("entity_id"):
                job.touch(resolved=job.resolved + 1, stage="context")
            if envelope.get("facts"):
                job.touch(facts=job.facts + int(envelope.get("facts") or 0))
            live["envelopes"].append(envelope)
            publish_live()

        attribution = await attribute_alerts(
            tkg,
            [
                # Resolve the notable id the graph was fed with, not AiSOC's row
                # id: the ingest used the Splunk notable id from the payload.
                str(alert.get("notable_id") or alert["alert_id"])
                for alert in bundle["payload"]["alerts"]
            ],
            synthetic_doc_ids=synthetic_ids,
            budget_s=budget_ms / 1000,
            on_envelope=track if job is not None else None,
        )

        _decorate(attribution, alert_meta)
        live["envelopes"] = list(attribution["alerts"])
        live["attribution"] = attribution
        publish_live(force=True)

        # Two passes, canonical first. On a real correlation case most of the set
        # is soft-dedup witnesses (89 of 98), and a witness the graph has not
        # projected yet must not hold the verdict the canonical members already
        # earned: pass 1 resolves, sends, waits and *stores* a verdict, pass 2
        # pushes the witnesses and re-scores. Ending the wait early — the button,
        # the timeout or a graph-side failure — never aborts the run: the later
        # stages still run and the row records what was left queued.
        poll_s = float(getattr(settings_obj, "AISOC_TKG_MATERIALISE_POLL_S", 5) or 5)
        wait_timeout_s = float(getattr(settings_obj, "AISOC_TKG_WAIT_TIMEOUT_S", WAIT_TIMEOUT_DEFAULT_S) or 0)
        send_delay_s = float(getattr(settings_obj, "AISOC_TKG_SEND_DELAY_S", 1.0) or 0)
        has_dedup = any(_phase_of(envelope) == "dedup" for envelope in attribution["alerts"])
        passes_to_run = ("canonical", "dedup") if has_dedup else ("canonical",)
        if job is not None:
            job.touch(
                wait_timeout_s=int(wait_timeout_s) if wait_timeout_s > 0 else -1,
                max_waves=0,
            )

        # How many alerts each pass is responsible for: the one number that
        # makes "3 canonical members, then 1009 witnesses" visible while the run
        # is in flight.
        phase_totals = {label: sum(1 for envelope in attribution["alerts"] if _phase_of(envelope) == label) for label in passes_to_run}

        stored: dict[str, Any] | None = None
        for position, label in enumerate(passes_to_run, start=1):
            attribution["phase"] = label
            live["label"] = label
            if job is not None:
                job.skip_wait.clear()
                job.touch(
                    stage="materialise",
                    phase=label,
                    phase_index=position,
                    phase_count=len(passes_to_run),
                    phase_total=phase_totals.get(label, 0),
                    pending=int(attribution.get("pending") or 0),
                    wait_left_s=int(wait_timeout_s) if wait_timeout_s > 0 else -1,
                )
            if send_missing and cfg.allow_send:
                report = await _send_unknown_alerts(
                    tkg,
                    attribution={"alerts": [envelope for envelope in attribution["alerts"] if _phase_of(envelope) == label]},
                    raw_by_row={str(row["id"]): row for row in alerts},
                    delay=send_delay_s,
                    job=job,
                    on_progress=lambda: publish_live(force=True),
                )
                _merge_send_report(attribution, label, report)
                publish_live(force=True)
                if report.get("sent"):
                    # A record the graph just accepted is ``pending_materialization``,
                    # not missing: re-read those ids so this pass waits on them
                    # instead of reporting them as never sent.
                    retry = await attribute_alerts(
                        tkg,
                        [item["notable_id"] for item in report["sent"]],
                        synthetic_doc_ids=synthetic_ids,
                        budget_s=max(10.0, budget_ms / 1000),
                    )
                    rolled = _merge_attribution(attribution, retry)
                    attribution.clear()
                    attribution.update(rolled)
                    _decorate(attribution, alert_meta)
                    publish_live(force=True)

            wait = await _wait_for_materialisation(
                tkg,
                attribution=attribution,
                synthetic_ids=synthetic_ids,
                poll_s=poll_s,
                timeout_s=wait_timeout_s,
                job=job,
                label=label,
                on_progress=lambda: publish_live(force=True),
            )
            publish_live(force=True)
            if wait.get("ended") in ("skipped", "timeout") and job is not None:
                job.touch(
                    message=(
                        f"{label}: stopped waiting after {wait['waves']} wave(s) — "
                        f"{wait['pending']} alert(s) are still queued in the graph; "
                        "they will be re-read on the next run"
                    )
                )

            publish_live(force=True)
            stored = await _score_and_store(
                db,
                tenant_id=tenant_id,
                case_id=case_id,
                requested_by=requested_by,
                engine_verdict=engine_verdict,
                bundle=bundle,
                alerts=alerts,
                attribution=attribution,
                started=started,
                call_llm=call_llm,
                cfg=cfg,
                fingerprint=fingerprint,
                job=job,
                label=label,
                interim=label == "canonical" and has_dedup,
            )
            if job is not None:
                pending_left = int((stored.get("stats") or {}).get("pending") or 0)
                if (attribution.get("wait") or {}).get("ended") == "failed":
                    # Keep the graph's own explanation for why the wait ended: it is
                    # the one message that tells the operator what to fix.
                    job.touch(pending=pending_left)
                else:
                    job.touch(
                        message=(
                            f"{label} pass stored: {stored.get('verdict') or 'scored'} · "
                            f"confidence {stored.get('confidence')}" + (f" · {pending_left} alert(s) still queued" if pending_left else "")
                        )
                    )
            # A run cancelled between the passes must not start the next one:
            # checkpoint() raises RunCancelled, which the endpoint turns into
            # "cancelled, nothing stored".
            progress.checkpoint(job)

        return stored if stored is not None else {}
    finally:
        if own_client:
            await tkg.aclose()
