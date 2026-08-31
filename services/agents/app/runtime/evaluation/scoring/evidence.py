"""Evidence support and hallucination detection (Phase 8). Deterministic only."""

from __future__ import annotations

from typing import Any


def _claim_keywords(claim: str) -> set[str]:
    tokens = [t.lower() for t in claim.replace("_", " ").split() if len(t) > 3]
    return set(tokens)


def evidence_supports_claim(claim: str, evidence: list[dict[str, Any]]) -> bool:
    if not claim:
        return False
    keywords = _claim_keywords(claim)
    if not keywords:
        return bool(evidence)
    for item in evidence:
        blob = " ".join(
            str(v)
            for v in (
                item.get("type"),
                item.get("source"),
                str(item.get("data", {})),
            )
        ).lower()
        if any(kw in blob for kw in keywords):
            return True
    return False


def score_evidence(
    claims: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
) -> dict[str, float]:
    if not claims:
        return {
            "evidence_support_rate": 1.0,
            "unsupported_claim_rate": 0.0,
            "supported": 0,
            "partial": 0,
            "unsupported": 0,
            "total": 0,
        }
    supported = 0
    partial = 0
    unsupported = 0
    for claim_row in claims:
        text = str(claim_row.get("claim") or claim_row.get("statement") or "")
        refs = claim_row.get("evidence") or claim_row.get("evidence_ids") or []
        has_refs = bool(refs)
        if has_refs and evidence_supports_claim(text, evidence):
            supported += 1
        elif has_refs:
            partial += 1
        elif evidence_supports_claim(text, evidence):
            partial += 1
        else:
            unsupported += 1
    total = len(claims)
    support_rate = (supported + 0.5 * partial) / total
    unsupported_rate = unsupported / total
    return {
        "evidence_support_rate": support_rate,
        "unsupported_claim_rate": unsupported_rate,
        "supported": supported,
        "partial": partial,
        "unsupported": unsupported,
        "total": total,
    }


def score_hallucination(claims: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> float:
    """Higher is better (1 = no hallucination). Inverse of unsupported rate."""
    metrics = score_evidence(claims, evidence)
    return max(0.0, 1.0 - metrics["unsupported_claim_rate"])
