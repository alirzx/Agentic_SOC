"""Correlation grouping evaluation (Phase 8)."""

from __future__ import annotations

from .set_metrics import f1_score


def _group_to_pairs(group: list[str]) -> set[frozenset[str]]:
    items = sorted({str(x) for x in group if x})
    pairs: set[frozenset[str]] = set()
    for i, left in enumerate(items):
        for right in items[i + 1:]:
            pairs.add(frozenset({left, right}))
    return pairs


def score_correlation(
    ground_truth_group: list[str] | None,
    predicted_groups: list[list[str]] | None,
) -> dict[str, float]:
    gt_pairs = _group_to_pairs(ground_truth_group or [])
    pred_pairs: set[frozenset[str]] = set()
    for group in predicted_groups or []:
        pred_pairs |= _group_to_pairs(group)
    if not gt_pairs and not pred_pairs:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "over_splitting": 0.0, "over_merging": 0.0}
    inter = len(gt_pairs & pred_pairs)
    precision = inter / len(pred_pairs) if pred_pairs else 0.0
    recall = inter / len(gt_pairs) if gt_pairs else 0.0
    f1 = f1_score({str(p) for p in pred_pairs}, {str(p) for p in gt_pairs}) if gt_pairs else 0.0
    over_split = max(0.0, len(pred_pairs) - len(gt_pairs)) / max(1, len(gt_pairs))
    over_merge = max(0.0, len(gt_pairs) - len(pred_pairs)) / max(1, len(gt_pairs))
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "over_splitting": over_split,
        "over_merging": over_merge,
    }
