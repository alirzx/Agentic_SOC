"""Bridge tool results to structured Evidence (Phase 8.6)."""

from __future__ import annotations

from typing import Any

from app.runtime.contracts import AgentContext, Evidence, EvidenceProvenance


def evidence_from_tool_result(
    context: AgentContext,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    result: Any,
    agent_name: str,
    agent_version: str,
    relevance: str = "",
) -> Evidence:
    payload: dict[str, Any] = {
        "tool": tool_name,
        "arguments": arguments,
        "result": result,
        "relevance": relevance,
    }
    event_id = None
    if isinstance(result, dict):
        event_id = result.get("event_id") or result.get("eventId") or result.get("id")
    if event_id:
        payload["event_id"] = str(event_id)
    return Evidence(
        incident_id=context.incident_id,
        type="tool_result",
        source=tool_name.split(".")[0] if "." in tool_name else tool_name,
        data=payload,
        confidence=0.7,
        provenance=EvidenceProvenance(
            agent=agent_name,
            agent_version=agent_version,
            tool=tool_name,
            source=tool_name,
        ),
    )


def normalize_claims(claims: list[Any], available_evidence_ids: set[str] | None = None) -> list[Any]:
    from .models import Claim
    from .validation import ground_claims

    parsed = [row if isinstance(row, Claim) else Claim.model_validate(row) for row in claims]
    if available_evidence_ids is None:
        for claim in parsed:
            if not claim.evidence_ids:
                claim.status = "unsupported"
        return parsed
    return ground_claims(parsed, available_evidence_ids)
