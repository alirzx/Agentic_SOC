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
                item.get("id"),
                str(item.get("data", {})),
            )
        ).lower()
        if any(kw in blob for kw in keywords):
            return True
    return False


def resolve_evidence_refs(
    refs: list[Any],
    evidence: list[dict[str, Any]],
    telemetry_events: list[dict[str, Any]] | None = None,
) -> bool:
    """Verify evidence references resolve to known evidence or telemetry events."""
    if not refs:
        return False
    evidence_ids = {str(item.get("id") or "") for item in evidence}
    event_ids = {str(row.get("eventId") or row.get("event_id") or row.get("id") or "") for row in telemetry_events or []}
    for ref in refs:
        ref_str = str(ref)
        if ref_str in evidence_ids:
            return True
        if ref_str in event_ids:
            return True
        for item in evidence:
            if ref_str and ref_str in str(item.get("data", {})):
                return True
    return False


def score_evidence(
    claims: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    telemetry_events: list[dict[str, Any]] | None = None,
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
        refs_resolved = resolve_evidence_refs(refs, evidence, telemetry_events) if has_refs else False
        if has_refs and refs_resolved and evidence_supports_claim(text, evidence):
            supported += 1
        elif has_refs and refs_resolved:
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
