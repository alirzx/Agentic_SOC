"""Deterministic classification scoring (Phase 8). No LLM."""

from __future__ import annotations

RELATED_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {
        ("likely_compromise", "confirmed_compromise"),
        ("needs_review", "likely_compromise"),
        ("false_positive", "benign"),
        ("new_incident", "likely_compromise"),
        ("block_indicator", "block_ioc"),
        ("isolate_host", "isolate_asset"),
        ("disable_account", "disable_user"),
    }
)


def normalize_classification(value: str | None) -> str:
    if not value:
        return ""
    text = str(value).strip().lower()
    if text.startswith("decision="):
        text = text.split("=", 1)[1].split()[0].strip()
    return text.replace("-", "_").replace(" ", "_")


def _parent_category(label: str) -> str:
    for sep in (":", "/", "_"):
        if sep in label:
            return label.split(sep, 1)[0]
    return label


def score_classification(ground_truth: str | None, predicted: str | None) -> float:
    gt = normalize_classification(ground_truth)
    pred = normalize_classification(predicted)
    if not gt or not pred:
        return 0.0 if gt else 1.0
    if gt == pred:
        return 1.0
    if _parent_category(gt) == _parent_category(pred) and _parent_category(gt):
        return 0.75
    pair = (gt, pred)
    if pair in RELATED_PAIRS or (pred, gt) in RELATED_PAIRS:
        return 0.5
    if gt in pred or pred in gt:
        return 0.5
    return 0.0
