"""Deterministic rubric behind every TKG verdict.

Two guarantees this module exists for:

* **The floor never depends on the model.** A run whose LLM judge is down still
  yields a defensible verdict from what the graph actually returned, marked
  ``evidence_only``.
* **Synthetic evidence cannot confirm a case.** Facts that trace back to
  synthetic documents may corroborate, never confirm; any verdict resting on
  them is capped and labelled.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.services.tkg_evaluation.constants import (
    CORROBORATION_MIN_FACTS,
    MIN_COVERAGE_FOR_CONFIRM,
    SCORE_BANDS,
    SYNTHETIC_CONFIDENCE_CAP,
    VERDICTS,
)

#: Alert needs at least this share of its extraction keys present to be usable.
MIN_EVIDENCE_RATIO = 0.5

#: How strong a claim each verdict makes. Deliberately *not* the tuple order:
#: ``insufficient`` is the weakest position (no answer), ``benign`` is a real
#: claim, and ``needs_more_evidence`` sits between them for clamping purposes.
_STRENGTH = {"insufficient": 0, "benign": 1, "needs_more_evidence": 2, "likely_tp": 3, "true_positive": 4}
_BY_STRENGTH = {strength: verdict for verdict, strength in _STRENGTH.items()}
MAX_BAND_JUMP = 1


def precheck(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Rubric gate: is this case judgeable at all?

    Cheap, deterministic, and explainable — the panel shows these checks as the
    reason a run is refused, instead of an opaque "unavailable".
    """

    payload = (bundle or {}).get("payload") or {}
    alerts = payload.get("alerts") or []
    checks: list[dict[str, Any]] = []

    checks.append(
        {
            "id": "alerts_present",
            "ok": len(alerts) >= 1,
            "detail": f"{len(alerts)} alert(s)",
        }
    )

    usable = [
        alert
        for alert in alerts
        if alert.get("title") and (alert.get("techniques") or alert.get("hosts") or alert.get("users") or alert.get("ips"))
    ]
    ratio = (len(usable) / len(alerts)) if alerts else 0.0
    checks.append(
        {
            "id": "evidence_ratio",
            "ok": ratio >= MIN_EVIDENCE_RATIO,
            "detail": f"{len(usable)}/{len(alerts)} alerts carry a title plus a correlation key",
        }
    )

    times = [alert.get("time") for alert in alerts if alert.get("time")]
    checks.append(
        {
            "id": "timeline",
            "ok": bool(times),
            "detail": f"{len(times)}/{len(alerts)} alerts have a timestamp",
        }
    )

    ids = [alert.get("alert_id") for alert in alerts]
    checks.append(
        {
            "id": "unique_ids",
            "ok": len(set(ids)) == len(ids),
            "detail": f"{len(set(ids))} unique of {len(ids)}",
        }
    )

    return {
        "eligible": all(check["ok"] for check in checks),
        "checks": checks,
        "coverage_ratio": ratio,
    }


def passes_for_alert(facts: int, *, synthetic: bool = False, corroborated: bool = False) -> str:
    """Map one alert's TKG context to a pass in ``PASSES``."""

    if facts <= 0:
        return "none"
    if synthetic:
        # Synthetic facts prove the pipeline ran; they cannot corroborate.
        return "unconfirmed"
    if corroborated or facts >= CORROBORATION_MIN_FACTS:
        return "corroborated"
    return "unconfirmed"


def verdict_for_score(score: int) -> str:
    for ceiling, verdict in SCORE_BANDS:
        if score >= ceiling:
            return verdict
    return "insufficient"


def evidence_floor(
    *,
    total_alerts: int,
    passes: Mapping[str, int],
    synthetic_only: bool = False,
) -> dict[str, Any]:
    """The verdict the graph alone supports, with its reason codes.

    ``passes`` counts alerts per pass (``none``/``unconfirmed``/``corroborated``/
    ``contextualized``). Coverage below :data:`MIN_COVERAGE_FOR_CONFIRM` cannot
    confirm anything, so the strongest available claim is
    ``needs_more_evidence``.
    """

    reasons: list[dict[str, Any]] = []
    total = max(int(total_alerts), 1)
    resolved = total_alerts - int(passes.get("none", 0))
    corroborated = int(passes.get("corroborated", 0)) + int(passes.get("contextualized", 0))
    coverage = resolved / total

    score = 0
    score += int(coverage * 45)
    score += min(corroborated, 4) * 12
    if passes.get("contextualized"):
        score += 10
    score = max(0, min(score, 100))

    reasons.append(
        {
            "code": "coverage",
            "detail": f"{resolved}/{total_alerts} alerts resolved in TKG ({coverage:.0%})",
        }
    )
    if corroborated:
        reasons.append({"code": "corroboration", "detail": f"{corroborated} alert(s) corroborated by graph facts"})
    else:
        reasons.append({"code": "no_corroboration", "detail": "graph facts did not corroborate any alert"})

    verdict = verdict_for_score(score)
    if coverage < MIN_COVERAGE_FOR_CONFIRM and _STRENGTH[verdict] < _STRENGTH["needs_more_evidence"]:
        verdict = "needs_more_evidence"
        reasons.append(
            {
                "code": "low_coverage",
                "detail": f"coverage {coverage:.0%} is below the {MIN_COVERAGE_FOR_CONFIRM:.0%} confirm threshold",
            }
        )
    if resolved == 0:
        verdict = "insufficient"

    if synthetic_only:
        # Synthetic facts may raise the case to "needs more evidence" and no
        # further: a demo graph cannot assert that a real intrusion happened.
        if _STRENGTH[verdict] > _STRENGTH["needs_more_evidence"]:
            verdict = "needs_more_evidence"
        score = min(score, SYNTHETIC_CONFIDENCE_CAP)
        reasons.append(
            {
                "code": "synthetic_evidence_only",
                "detail": "every supporting fact traces to a synthetic document; cannot confirm",
            }
        )

    return {
        "verdict": verdict,
        "score": score,
        "confidence": score,
        "coverage": round(coverage, 3),
        "corroborated": corroborated,
        "reasons": reasons,
        "synthetic_only": synthetic_only,
    }


def reconcile(
    *,
    floor: Mapping[str, Any],
    judged: Mapping[str, Any] | None,
    engine_verdict: str | None,
) -> dict[str, Any]:
    """Merge the evidence floor with the (optional) judge verdict.

    Disagreement is recorded, not hidden: the merged verdict may not jump two
    steps away from the floor on the model's say-so alone, and a synthetic-only
    floor caps the final confidence regardless of what the model claimed.
    """

    reasons = list(floor.get("reasons") or [])
    verdict = str(floor.get("verdict") or "insufficient")
    confidence = int(floor.get("confidence") or 0)
    passes = "corroborated" if floor.get("corroborated") else ("unconfirmed" if floor.get("coverage") else "none")

    if judged and _STRENGTH[verdict] == 0:
        # No alert resolved: the judge has no graph facts to reason from, so its
        # verdict is not a second opinion, it is a guess. Keep the floor.
        reasons.append({"code": "judge_no_evidence", "detail": "no graph facts were attributed; judge verdict ignored"})
        judged = None

    if judged:
        judged_verdict = str(judged.get("verdict") or "")
        if judged_verdict in VERDICTS:
            floor_strength = _STRENGTH[verdict]
            judged_strength = _STRENGTH[judged_verdict]
            if judged_strength < floor_strength:
                # Absence of graph evidence is not disproof: the judge may not
                # weaken the floor, it may only be more specific than it.
                reasons.append(
                    {
                        "code": "judge_below_floor",
                        "detail": f"judge said {judged_verdict}; graph floor was {verdict}; kept the floor",
                    }
                )
                judged_strength = floor_strength
            elif judged_strength - floor_strength > MAX_BAND_JUMP:
                reasons.append(
                    {
                        "code": "judge_out_of_band",
                        "detail": f"judge said {judged_verdict}; floor said {verdict}; raised only one band",
                    }
                )
                judged_strength = floor_strength + MAX_BAND_JUMP
            verdict = _BY_STRENGTH[judged_strength]
            confidence = max(confidence, int(judged.get("confidence") or 0))
            for reason in judged.get("reasons") or []:
                reasons.append({"code": "judge", "detail": str(reason)[:300]})
            passes = "contextualized" if floor.get("corroborated") else passes

    if floor.get("synthetic_only"):
        confidence = min(confidence, SYNTHETIC_CONFIDENCE_CAP)
        if _STRENGTH[verdict] > _STRENGTH["needs_more_evidence"]:
            verdict = "needs_more_evidence"

    agree: bool | None
    if engine_verdict:
        engine_positive = engine_verdict in {"true_positive", "likely_tp", "escalate"}
        ours_positive = verdict in {"true_positive", "likely_tp"}
        agree = engine_positive == ours_positive
    else:
        agree = None

    return {
        "verdict": verdict,
        "confidence": max(0, min(confidence, 100)),
        "passes": passes,
        "agree": agree,
        "reasons": reasons,
    }
