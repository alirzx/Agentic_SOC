"""Set precision / recall / F1 (Phase 8)."""

from __future__ import annotations


def normalize_set(values: list[str] | None) -> set[str]:
    if not values:
        return set()
    return {str(v).strip().upper() for v in values if str(v).strip()}


def precision_recall_f1(predicted: set[str], ground_truth: set[str]) -> dict[str, float]:
    if not ground_truth and not predicted:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    if not predicted:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    if not ground_truth:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    inter = len(predicted & ground_truth)
    precision = inter / len(predicted)
    recall = inter / len(ground_truth)
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def f1_score(predicted: set[str], ground_truth: set[str]) -> float:
    return precision_recall_f1(predicted, ground_truth)["f1"]
