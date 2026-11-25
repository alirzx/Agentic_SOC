"""Bounded historical evidence for the authorized Investigation Ledger."""

from .recon import prompt_evidence
from .tools import case_grant, grant


def history_for_ledger(state):
    history = state.recon.history
    case = case_grant.get()
    scope = case or grant.get()
    if not history or scope is None or str(scope[0]) != state.tenant_id:
        return None

    evidence, facts, entities, candidates = [], {}, {}, {}
    observations = history.get("evidence", [])
    for item, view in zip(observations[:25], prompt_evidence(observations[:25]), strict=True):
        kb = view["kb_id"]
        data = item.get("data") or {}
        evidence.append({
            "tool": view["tool"], "status": view["status"], "seed_id": view.get("seed_id"),
            "duration_ms": item.get("duration_ms"), "fact_count": len(view["facts"]),
            "truncated": view["truncated"],
        })
        if view["tool"] == "tkg.resolve_entity" and view["status"] == "resolved":
            for entry in view["candidates"]:
                if entity := entry.get("entity_id"):
                    entities[(kb, entity)] = {"id": entity, "kb_id": kb}
        for row in view["facts"]:
            if not (fact_id := row.get("id")) or not kb or len(facts) >= 30:
                continue
            facts.setdefault((kb, fact_id), {
                "id": fact_id, "kb_id": kb, "root_id": view.get("subject_id"),
                **{key: row[key] for key in (
                    "other_id", "direction", "predicate_key", "other_type", "valid_from", "valid_to",
                    "recorded_at", "contested", "stale", "inferred", "citation_ref",
                ) if key in row},
                "knowledge_time": view.get("knowledge_time"),
                "sources": [{"document_id": ref["document_id"], "chunk_id": ref["chunk_id"]}
                            for ref in view["evidence_references"] if ref["fact_id"] == fact_id][:5],
            })
        if view["tool"] == "tkg.search_history" and kb:
            for entry in data.get("results", []):
                if entry.get("document_id") and entry.get("chunk_id") and len(candidates) < 15:
                    candidates[(kb, entry["chunk_id"])] = {"kb_id": kb, "document_id": entry["document_id"],
                                                            "chunk_id": entry["chunk_id"]}
    visible_refs = {item["citation_ref"] for item in facts.values() if item.get("citation_ref")}
    claims = [row for row in history.get("historical_claims", []) if set(row["citations"]) <= visible_refs][:8]
    return {
        "resource_kind": "case" if case else "alert", "resource_id": str(scope[1]),
        "history": {
            **{key: history[key] for key in (
                "profile", "historical_status", "stop_reason", "coverage", "tool_calls", "tool_requests",
                "llm_calls", "provider_calls", "reserved_tokens_charged", "estimated_cost_usd", "limits",
                "planner_attempts", "preflight_tool_calls", "assessment_status",
            ) if key in history},
            "tools": evidence, "facts": list(facts.values()), "entities": list(entities.values())[:25],
            "candidates": list(candidates.values()), "claims": claims,
            "truncated": len(observations) > len(evidence) or len(facts) == 30 or len(candidates) == 15,
        },
    }
