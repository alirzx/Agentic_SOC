"""Risk comparison metrics (Phase 8). Ground truth is not assumed from existing SOC."""

from __future__ import annotations

import math
from typing import Sequence


def mae(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return sum(abs(v) for v in values) / len(values)


def rmse(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return math.sqrt(sum(v * v for v in values) / len(values))


def calibration_error(predicted: Sequence[float], actual: Sequence[float]) -> float:
    if not predicted or not actual or len(predicted) != len(actual):
        return 0.0
    bins = 10
    total = len(predicted)
    error = 0.0
    for i in range(bins):
        low = i * 10
        high = (i + 1) * 10
        idx = [j for j, p in enumerate(predicted) if low <= p < high or (i == bins - 1 and p == 100)]
        if not idx:
            continue
        mean_pred = sum(predicted[j] for j in idx) / len(idx)
        mean_actual = sum(actual[j] for j in idx) / len(idx)
        error += (len(idx) / total) * abs(mean_pred - mean_actual)
    return error


def score_risk_distance(ground_truth: float | None, predicted: float | None) -> float:
    if ground_truth is None or predicted is None:
        return 0.0
    diff = abs(float(ground_truth) - float(predicted))
    return max(0.0, 1.0 - diff / 100.0)
