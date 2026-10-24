"""Near-duplicate similarity — shadow evaluation only (Phase 2).

Exact fingerprint dedup remains authoritative. This module scores textual /
entity overlap for observability and shadow comparison; it must NEVER merge
alerts or suppress production decisions on its own.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import Any

from app.core.config import settings

_TOKEN_RE = re.compile(r"[a-z0-9]+", re.I)


def near_dup_shadow_enabled() -> bool:
    """Off by default — enable with ``AISOC_NEAR_DUP_SHADOW=1``."""
    return os.getenv("AISOC_NEAR_DUP_SHADOW", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def similarity_threshold() -> float:
    return float(getattr(settings, "dedup_similarity_threshold", 0.85) or 0.85)


@dataclass(frozen=True)
class NearDupAssessment:
    score: float
    above_threshold: bool
    shared_tokens: int
    entity_conflict: bool
    rationale: str
    shadow_only: bool = True


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "") if len(t) > 2}


def assess_near_duplicate(left: dict[str, Any], right: dict[str, Any]) -> NearDupAssessment:
    """Jaccard title-token similarity with hard entity-conflict veto."""
    left_title = str(left.get("title") or "")
    right_title = str(right.get("title") or "")
    a, b = _tokens(left_title), _tokens(right_title)
    if not a or not b:
        return NearDupAssessment(0.0, False, 0, False, "empty title tokens", True)
    shared = a & b
    union = a | b
    score = len(shared) / len(union) if union else 0.0

    # Critical entity mismatch blocks operational merge recommendation.
    conflicts: list[str] = []
    for field in ("username", "hostname", "src_ip", "rule_id"):
        lv, rv = left.get(field), right.get(field)
        if lv and rv and str(lv).lower() != str(rv).lower():
            conflicts.append(field)
    entity_conflict = bool(conflicts)
    thr = similarity_threshold()
    above = score >= thr and not entity_conflict
    rationale = (
        f"jaccard={score:.2f} shared={len(shared)} threshold={thr:.2f}"
        + (f" entity_conflict={','.join(conflicts)}" if conflicts else "")
        + " (shadow-only; fingerprint remains authoritative)"
    )
    return NearDupAssessment(score, above, len(shared), entity_conflict, rationale, True)


def stable_pair_id(left_id: str, right_id: str) -> str:
    a, b = sorted([str(left_id), str(right_id)])
    return hashlib.sha256(f"{a}|{b}".encode()).hexdigest()[:16]
