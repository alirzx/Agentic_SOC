"""Auto-triage verdict summary and the candidates queue's triage filter.

The correlation engine only *excludes* auto-closed alerts; it never scored with
the surviving verdicts. The queue therefore had no way to answer "does this
campaign contain a confirmed true positive?" — these tests lock the display-side
aggregation and the filter semantics that fix that.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.services.candidate_discovery import (
    TRIAGE_FILTERS,
    CandidateDiscovery,
    Observation,
    drop_cased_observations,
    filter_candidates,
)


def alert(disposition: str | None, confidence: int | None = None) -> dict:
    return {
        "created_at": datetime(2026, 11, 11, 13, 0, tzinfo=UTC),
        "event_time": datetime(2026, 11, 11, 13, 0, tzinfo=UTC),
        "severity": "medium",
        "disposition": disposition,
        "confidence": confidence,
    }


def test_summary_counts_verdicts_and_unreviewed() -> None:
    discovery = CandidateDiscovery(session=None)
    summary = discovery._triage_summary(
        [
            alert("true_positive", 88),
            alert("true_positive", 72),
            alert("needs_review", 40),
            alert(None, None),
            alert("", None),
        ]
    )

    assert summary["true_positive"] == 2
    assert summary["needs_review"] == 1
    assert summary["likely_tp"] == 0
    assert summary["reviewed"] == 3
    assert summary["unreviewed"] == 2
    assert summary["verdicts"] == {"true_positive": 2, "needs_review": 1}
    assert summary["max_confidence"] == 88
    assert summary["avg_confidence"] == 67  # (88 + 72 + 40) / 3


def test_summary_without_triage_data_reports_zero_confidences() -> None:
    discovery = CandidateDiscovery(session=None)
    summary = discovery._triage_summary([alert(None), alert(None)])

    assert summary["reviewed"] == 0
    assert summary["unreviewed"] == 2
    assert summary["max_confidence"] is None
    assert summary["avg_confidence"] is None
    assert set(TRIAGE_FILTERS) <= set(summary)


def candidate(key: str, **triage: int) -> dict:
    summary = dict.fromkeys(TRIAGE_FILTERS, 0)
    summary.update(triage)
    summary["reviewed"] = sum(summary[b] for b in TRIAGE_FILTERS if b != "unreviewed")
    return {
        "candidate_key": key,
        "campaign_theme": "APT_ACTIVITY_CREDENTIAL_THEFT",
        "score": 5,
        "alert_count": 4,
        "entities": {"hosts": ["dc01"], "users": ["administrator"], "ips": [], "domains": []},
        "techniques": ["T1003.006"],
        "time_first": datetime(2026, 11, 11, 13, 0, tzinfo=UTC),
        "time_last": datetime(2026, 11, 11, 13, 30, tzinfo=UTC),
        "severity": "high",
        "triage": summary,
    }


def test_triage_filter_keeps_any_requested_bucket() -> None:
    candidates = [
        candidate("has-tp", true_positive=2),
        candidate("needs-review", needs_review=3),
        candidate("unreviewed", unreviewed=4),
    ]

    assert [c["candidate_key"] for c in filter_candidates(candidates, triage=["true_positive"])] == [
        "has-tp"
    ]
    # Two selected buckets mean "either", which is how a verdict facet reads.
    assert {
        c["candidate_key"] for c in filter_candidates(candidates, triage=["true_positive", "needs_review"])
    } == {"has-tp", "needs-review"}
    assert [
        c["candidate_key"] for c in filter_candidates(candidates, triage=["unreviewed"])
    ] == ["unreviewed"]


def test_triage_filter_ignores_unknown_buckets() -> None:
    candidates = [candidate("has-tp", true_positive=1)]

    # A typo must not silently hide every candidate.
    assert filter_candidates(candidates, triage=["not_a_verdict"])[0]["candidate_key"] == "has-tp"


def observation(key: str, alert_ids: list[str]) -> Observation:
    return Observation(
        signature=key,
        alert_ids=list(alert_ids),
        role=None,
        techniques=[],
        hosts=[],
        users=[],
        ips=[],
        domains=[],
    )


def test_cased_alerts_are_trimmed_from_observations() -> None:
    observations = {
        "obs-a": observation("obs-a", ["a1", "a2"]),
        "obs-b": observation("obs-b", ["b1"]),
    }

    kept = drop_cased_observations(observations, ["a2", "b1"])

    # The partially-cased observation survives with its remaining alert; the
    # fully-cased one disappears so a promoted campaign leaves the queue.
    assert list(kept) == ["obs-a"]
    assert kept["obs-a"].alert_ids == ["a1"]


def test_no_cased_alerts_leaves_observations_untouched() -> None:
    observations = {"obs-a": observation("obs-a", ["a1"])}

    assert drop_cased_observations(observations, []) is observations


def test_triage_filter_keeps_candidates_without_a_summary() -> None:
    legacy = candidate("legacy", true_positive=0)
    del legacy["triage"]

    # Rows built before this field existed must not disappear from the queue.
    assert filter_candidates([legacy], triage=["unreviewed"]) == []
    assert filter_candidates([legacy], triage=[]) == [legacy]
