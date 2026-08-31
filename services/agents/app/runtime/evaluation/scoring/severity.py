"""Deterministic severity ladder scoring (Phase 8)."""

from __future__ import annotations

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
    "emergency": 4,
}

MAX_SEVERITY_DISTANCE = 4


def normalize_severity(value: str | None) -> str:
    if not value:
        return "medium"
    lowered = str(value).strip().lower()
    if lowered in {"info", "low"}:
        return "low"
    if lowered in SEVERITY_RANK:
        return lowered
    return "medium"


def severity_rank(value: str | None) -> int:
    return SEVERITY_RANK.get(normalize_severity(value), 1)


def score_severity(ground_truth: str | None, predicted: str | None) -> float:
    """Documented: score = max(0, 1 - 0.25 * |gt - pred|)."""
    distance = abs(severity_rank(ground_truth) - severity_rank(predicted))
    return max(0.0, 1.0 - 0.25 * distance)
