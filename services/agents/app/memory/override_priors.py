"""Bridge analyst ``override:v2:*`` memory into auto-triage suppression.

API ``override_learning`` writes institutional rows keyed by a coarse
alert signature. The Kafka worker looks those up so a human FP/benign
correction actually shrinks future volume (product funnel Phase 4).
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.agents.dispositions import AUTO_CLOSEABLE_DISPOSITIONS, normalize_disposition
from app.memory.institutional import institutional_get
from app.memory.outcomes import HUMAN


def coarse_signature_key(alert: dict[str, Any]) -> str | None:
    """Match ``AlertSignature.memory_key()`` in the API override service."""
    category = str(alert.get("category") or "").lower().strip()
    connector = str(alert.get("connector_type") or "").lower().strip()
    techniques = alert.get("mitre_techniques") or []
    primary = ""
    if isinstance(techniques, list) and techniques:
        primary = str(techniques[0]).upper().strip()
    severity = str(alert.get("severity") or "").lower().strip()
    if not (category or connector or primary):
        return None
    raw = f"{category}|{connector}|{primary}|{severity}"
    digest = hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"override:v2:{digest}"


async def lookup_human_override(tenant_id: str, alert: dict[str, Any]) -> dict[str, Any] | None:
    """Return the institutional override payload, or None."""
    key = coarse_signature_key(alert)
    if not key:
        return None
    prior = await institutional_get(tenant_id, key)
    return prior if isinstance(prior, dict) else None


def should_suppress_from_override(prior: dict[str, Any] | None) -> bool:
    """Human FP/benign corrections suppress; TP never auto-closes."""
    if not isinstance(prior, dict):
        return False
    corrected = normalize_disposition(
        str(prior.get("corrected_verdict") or prior.get("disposition") or ""),
        default="",
    )
    if corrected not in AUTO_CLOSEABLE_DISPOSITIONS:
        return False
    # Prefer explicit human marker; override rows are always analyst-authored.
    author = str(prior.get("author") or HUMAN).lower()
    provenance = prior.get("provenance") if isinstance(prior.get("provenance"), dict) else {}
    prov_author = str(provenance.get("author") or "").lower()
    return author == HUMAN or "human" in prov_author or prior.get("analyst_id") is not None
