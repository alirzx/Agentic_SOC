"""MITRE technique scoring (Phase 8)."""

from __future__ import annotations

from .set_metrics import f1_score, normalize_set, precision_recall_f1


def score_mitre(
    ground_truth: list[str] | None,
    predicted: list[str] | None,
    existing: list[str] | None = None,
) -> dict[str, float | dict[str, float]]:
    gt = normalize_set(ground_truth)
    pred = normalize_set(predicted)
    ex = normalize_set(existing)
    agentic = precision_recall_f1(pred, gt)
    existing_metrics = precision_recall_f1(ex, gt)
    return {
        "agentic_f1": agentic["f1"],
        "existing_f1": existing_metrics["f1"],
        "precision": agentic["precision"],
        "recall": agentic["recall"],
        "f1": agentic["f1"],
        "existing": existing_metrics,
        "agentic": agentic,
    }
