"""Evidence and MITRE validation for LLM investigation output (Phase 8.6.2)."""

from __future__ import annotations

import re
from typing import Iterable

from .models import Claim, InvestigationOutput

_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_MITRE_TACTIC_RE = re.compile(r"^TA\d{4}$", re.IGNORECASE)


def is_valid_mitre_technique_id(value: str) -> bool:
    return bool(_MITRE_TECHNIQUE_RE.match(value.strip()))


def is_valid_mitre_tactic_id(value: str) -> bool:
    return bool(_MITRE_TACTIC_RE.match(value.strip()))


def normalize_attack_chain(entries: Iterable[str]) -> tuple[list[str], list[str]]:
    """Keep tactic labels; accept well-formed MITRE technique/tactic IDs only."""
    kept: list[str] = []
    rejected: list[str] = []
    for raw in entries:
        label = str(raw).strip()
        if not label:
            continue
        upper = label.upper()
        if _MITRE_TECHNIQUE_RE.match(upper) or _MITRE_TACTIC_RE.match(upper):
            if is_valid_mitre_technique_id(upper) or is_valid_mitre_tactic_id(upper):
                kept.append(upper)
            else:
                rejected.append(label)
        else:
            kept.append(label)
    return kept, rejected


def ground_claims(claims: list[Claim], available_evidence_ids: set[str]) -> list[Claim]:
    """Mark claims unsupported when evidence IDs are missing or unknown."""
    grounded: list[Claim] = []
    for row in claims:
        claim = row if isinstance(row, Claim) else Claim.model_validate(row)
        if not claim.evidence_ids:
            claim.status = "unsupported"
        elif not available_evidence_ids:
            claim.status = "insufficient_evidence"
        elif any(eid not in available_evidence_ids for eid in claim.evidence_ids):
            claim.status = "unsupported"
        else:
            claim.status = "supported"
        grounded.append(claim)
    return grounded


def validate_investigation_output(
    output: InvestigationOutput,
    *,
    available_evidence_ids: set[str],
) -> InvestigationOutput:
    """Apply deterministic grounding and MITRE format checks."""
    output.claims = ground_claims(output.claims, available_evidence_ids)
    kept, rejected = normalize_attack_chain(output.attack_chain)
    output.attack_chain = kept
    if rejected:
        output.uncertainties = list(output.uncertainties) + [
            f"rejected_mitre_identifiers:{','.join(rejected[:5])}"
        ]
    return output
