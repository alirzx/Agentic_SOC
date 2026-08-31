"""IOC normalization and scoring (Phase 8)."""

from __future__ import annotations

import re

from .set_metrics import f1_score, normalize_set, precision_recall_f1

_IOC_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b[a-z0-9][-a-z0-9]*\.[a-z]{2,}\b", re.I),
    "hash": re.compile(r"\b[a-f0-9]{32,64}\b", re.I),
    "url": re.compile(r"https?://[^\s]+", re.I),
}


def normalize_ioc(value: str) -> str:
    text = str(value).strip().lower()
    if text.startswith("http"):
        return text.split("?")[0]
    return text


def classify_ioc(value: str) -> str:
    text = str(value).strip()
    for kind, pattern in _IOC_PATTERNS.items():
        if pattern.fullmatch(text) or pattern.search(text):
            return kind
    if "@" in text:
        return "user"
    if text:
        return "host"
    return "unknown"


def score_iocs(
    ground_truth: list[str] | None,
    predicted: list[str] | None,
    existing: list[str] | None = None,
) -> dict[str, float | dict[str, float]]:
    gt = {normalize_ioc(v) for v in (ground_truth or []) if v}
    pred = {normalize_ioc(v) for v in (predicted or []) if v}
    ex = {normalize_ioc(v) for v in (existing or []) if v}
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
