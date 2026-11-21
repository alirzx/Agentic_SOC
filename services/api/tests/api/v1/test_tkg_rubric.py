"""Rubric tests: the evidence floor, synthetic caps and reconciliation rules."""

from __future__ import annotations

from app.services.tkg_evaluation.rubric import evidence_floor, precheck, reconcile, verdict_for_score


def test_verdict_bands_are_monotonic():
    assert verdict_for_score(90) == "true_positive"
    assert verdict_for_score(75) == "likely_tp"
    assert verdict_for_score(55) == "needs_more_evidence"
    assert verdict_for_score(35) == "benign"
    assert verdict_for_score(0) == "insufficient"


def test_no_resolution_is_insufficient():
    floor = evidence_floor(total_alerts=5, passes={"none": 5, "unconfirmed": 0, "corroborated": 0})
    assert floor["verdict"] == "insufficient"
    assert floor["coverage"] == 0.0


def test_low_coverage_cannot_confirm():
    floor = evidence_floor(
        total_alerts=10, passes={"none": 7, "unconfirmed": 2, "corroborated": 1}
    )
    assert floor["verdict"] == "needs_more_evidence"
    assert any(reason["code"] == "low_coverage" for reason in floor["reasons"])


def test_full_coverage_with_corroboration_confirms():
    floor = evidence_floor(
        total_alerts=4, passes={"none": 0, "unconfirmed": 1, "corroborated": 3}
    )
    assert floor["verdict"] in {"true_positive", "likely_tp"}
    assert floor["coverage"] == 1.0


def test_synthetic_only_caps_confidence_and_blocks_confirmation():
    floor = evidence_floor(
        total_alerts=4,
        passes={"none": 0, "unconfirmed": 0, "corroborated": 4},
        synthetic_only=True,
    )
    assert floor["verdict"] == "needs_more_evidence"
    assert floor["confidence"] <= 55
    assert any(reason["code"] == "synthetic_evidence_only" for reason in floor["reasons"])


def test_judge_cannot_jump_two_bands():
    floor = {
        "verdict": "insufficient",
        "confidence": 10,
        "coverage": 0.0,
        "corroborated": 0,
        "reasons": [],
        "synthetic_only": False,
    }
    merged = reconcile(
        floor=floor,
        judged={"verdict": "true_positive", "confidence": 95, "reasons": ["wide campaign"]},
        engine_verdict=None,
    )
    assert merged["verdict"] in {"insufficient", "needs_more_evidence"}
    # With nothing resolved there are no facts to reason from: the judge is
    # ignored outright rather than band-clamped.
    assert any(reason["code"] == "judge_no_evidence" for reason in merged["reasons"])


def test_judge_is_clamped_to_one_band_when_floor_has_evidence():
    floor = {
        "verdict": "needs_more_evidence",
        "confidence": 50,
        "coverage": 0.8,
        "corroborated": 1,
        "reasons": [],
        "synthetic_only": False,
    }
    merged = reconcile(
        floor=floor,
        judged={"verdict": "true_positive", "confidence": 99, "reasons": []},
        engine_verdict=None,
    )
    assert merged["verdict"] == "likely_tp"
    assert any(reason["code"] == "judge_out_of_band" for reason in merged["reasons"])


def test_agreement_is_compared_with_engine_verdict():
    floor = {
        "verdict": "benign",
        "confidence": 40,
        "coverage": 1.0,
        "corroborated": 0,
        "reasons": [],
        "synthetic_only": False,
    }
    merged = reconcile(floor=floor, judged=None, engine_verdict="true_positive")
    assert merged["agree"] is False


def test_precheck_rejects_case_without_usable_evidence():
    bundle = {
        "payload": {
            "alerts": [
                {"alert_id": "a", "title": "one", "time": None},
                {"alert_id": "b", "title": "two", "time": None},
            ]
        }
    }
    result = precheck(bundle)
    assert result["eligible"] is False
    failing = {check["id"] for check in result["checks"] if not check["ok"]}
    assert {"evidence_ratio", "timeline"} <= failing
