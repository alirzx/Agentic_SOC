"""Bounded historical lookup and reassessment inside the investigator Recon node."""

import asyncio
import hmac
import json
import os
from typing import Literal
from uuid import UUID

import asyncpg
import httpx
import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from openai import APIError
from pydantic import BaseModel, ConfigDict, Field

from app.investigator.prompt_sanitizer import sanitize_text, sanitize_value, wrap_untrusted
from app.investigator.tools import extract_iocs
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model
from app.llm.prompt_registry import default_registry
from app.privacy.context import PrivacyConfigurationError, current_privacy_gateway, privacy_required
from app.privacy.remote import RemotePrivacyError
from app.runtime.tools import ToolContext

from .binding import Binding, BindingError, tls_context
from .budget import ModelBudgetStop
from .tools import SCHEMAS, Limits, Session, active, case_grant, grant

logger = structlog.get_logger()


def verify_grant(signature, workspace, resource, *, case=False):
    key = os.getenv("AISOC_AGENTS_TENANT_SIGNING_KEY", "").encode()
    if len(key) < 32 or not signature or len(signature) != 64 or not signature.isascii():
        return None
    try:
        pair = UUID(workspace), UUID(resource)
    except (ValueError, TypeError):
        return None
    purpose = "tkg-case-v1" if case else "tkg-read-v1"
    expected = hmac.digest(key, f"{purpose}/{pair[0]}/{pair[1]}".encode(), "sha256").hex()
    return pair if hmac.compare_digest(expected, signature) else None


def protected(workspace):
    gateway = current_privacy_gateway()
    return privacy_required() and gateway is not None and str(gateway.tenant_id) == str(workspace)


def prompt_evidence(items, excerpt_chars=360):
    """Project selected graph fields and bounded untrusted Search excerpts for DLP."""
    import re
    from datetime import datetime

    result = []
    for item in items:
        doc = item.get("data") or {}
        view = {
            "kb_id": item.get("kb_id"),
            "source_id": item.get("source_id"),
            "tool": item["tool"],
            "status": item["status"],
            "truncated": doc.get("truncated") is True or (doc.get("bounds") or {}).get("truncated") is True,
            "entity_type": doc.get("entity_type"),
            "conflict": bool(doc.get("conflicts")),
            "evidence_status": (doc.get("evidence") or {}).get("status"),
            "evidence_references": [],
            "facts": [],
            "candidates": [],
        }
        if item.get("seed_id"):
            view["seed_id"] = item["seed_id"]
        if doc.get("knowledge_time"):
            view["knowledge_time"] = doc["knowledge_time"]
        if doc.get("requested_entity") or doc.get("entity_id"):
            view["subject_id"] = doc.get("requested_entity") or doc.get("entity_id")
        retrieval = doc.get("retrieval") or {}
        if item["tool"] == "tkg.search_history" and isinstance(retrieval, dict):
            view["retrieval"] = {field: retrieval[field] for field in (
                "dense_executed", "lexical_method", "reranker_status", "score_type", "fallback_reason", "final_order",
            ) if isinstance(retrieval.get(field), (str, bool))}
        for target, rows in (
            ("facts", doc.get("facts", [])),
            ("candidates", doc.get("candidates", [])),
            ("candidates", doc.get("results", [])),
        ):
            for rank, row in enumerate(rows[:20], 1):
                entry = {}
                for key in ("id", "entity_id", "subject_id", "object_id", "other_id", "fact_id", "document_id", "chunk_id"):
                    try:
                        entry[key] = str(UUID(str(row.get(key))))
                    except ValueError:
                        pass
                for key in ("valid_from", "valid_to", "recorded_at", "invalidated_at"):
                    if isinstance(row.get(key), str):
                        try:
                            entry[key] = datetime.fromisoformat(row[key]).isoformat()
                        except ValueError:
                            pass
                if row.get("direction") in ("in", "out"):
                    entry["direction"] = row["direction"]
                for flag in ("inferred", "stale", "corrected"):
                    if isinstance(row.get(flag), bool):
                        entry[flag] = row[flag]
                if row.get("contested"):
                    entry["contested"] = True
                literal = row.get("object_value")
                if type(literal) in (bool, int, float):
                    entry["object_value"] = literal
                for key in ("predicate_key", "predicate_label", "other_type", "entity_type"):
                    value = row.get(key)
                    if isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_ -]{0,63}", value):
                        entry[key] = value
                documents = []
                for candidate in row.get("document_ids", [])[:10]:
                    try:
                        documents.append(str(UUID(str(candidate))))
                    except ValueError:
                        continue
                if documents:
                    entry["document_ids"] = documents
                host = row.get("other_name")
                if (
                    str(row.get("other_type", "")).lower() in {"host", "hostname"}
                    and isinstance(host, str)
                    and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host)
                ):
                    entry["endpoint"] = "host=" + host
                if item["tool"] == "tkg.search_history" and row.get("document_id"):
                    entry["rank"] = rank
                    if row.get("candidate_id"):
                        entry["candidate_id"] = row["candidate_id"]
                    text = row.get("text")
                    # Credentials can be arbitrary text. Omit suspicious excerpts locally
                    # and send the remaining bounded untrusted content through DLP.
                    if isinstance(text, str) and not re.search(
                        r"(?i)password|credential|api[_ -]?key|token|secret|bearer|private key", text
                    ):
                        entry["semantic_excerpt"] = sanitize_text(text, max_len=excerpt_chars)
                    elif isinstance(text, str):
                        entry["excerpt_status"] = "omitted_by_local_filter"
                    entry["identity_status"] = "unverified"
                view[target].append(entry)
        references = doc.get("evidence_references") or (doc.get("evidence") or {}).get("references", [])
        for reference in references[:20]:
            if not isinstance(reference, dict):
                continue
            source = reference.get("source") or reference
            try:
                view["evidence_references"].append(
                    {
                        "fact_id": str(UUID(reference["fact_id"])),
                        "document_id": str(UUID(source["document_id"])),
                        "chunk_id": str(UUID(source["chunk_id"])),
                    }
                )
            except (KeyError, ValueError, TypeError):
                continue
        linked = {row["fact_id"] for row in view["evidence_references"]}
        if view["kb_id"] and not view["conflict"]:
            for fact in view["facts"]:
                fact_id = fact.get("id") or fact.get("fact_id")
                if fact_id in linked and not (fact.get("contested") or fact.get("stale")):
                    fact["citation_ref"] = f"{view['kb_id']}/{fact_id}"
        result.append(view)
    return result


def pack_context(metadata, observations, budget, *, selected=None):
    """Keep the wire JSON complete even when observations exceed the budget."""
    def render(value):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)

    core = ("stop_reason", "historical_status", "coverage", "tool_calls_left", "requests_left", "examined")
    state = {key: sanitize_value(metadata[key]) for key in core if key in metadata}
    packed = {"state": state, "evidence": [], "omitted": len(observations), "omitted_state_fields": 0}
    # Reserve the structural fields; add optional metadata one field at a time.
    for key in ("objectives", "seeds", "alert", "queries_completed", "retryable_queries"):
        if key in metadata:
            state[key] = sanitize_value(metadata[key], max_field_len=1000)
            if len(render(packed).encode()) > budget:
                state.pop(key)
                packed["omitted_state_fields"] += 1
    seen = set()
    examined = set(metadata.get("examined") or ())
    ranked = sorted(reversed(observations), key=lambda item: (
        not (item.get("conflict") or any(fact.get("contested") for fact in item.get("facts", []))),
        not (item.get("seed_id") in examined),
    ))
    for observation in ranked:
        projected = sanitize_value(observation, max_field_len=1000)
        key = render(projected)
        if key in seen:
            continue
        packed["evidence"].append(projected)
        packed["omitted"] -= 1
        if len(render(packed).encode()) > budget:
            packed["evidence"].pop()
            packed["omitted"] += 1
        else:
            seen.add(key)
    if selected is not None:
        selected.extend(packed["evidence"])
    return wrap_untrusted(render(packed), label="tkg_evidence")


def history_prompt(state, *, assessment=False):
    history = state.recon.history
    if not history or not protected(state.tenant_id):
        return ""
    prompt_name = "recon.final_assessment" if assessment else "recon.evidence_policy"
    prompt = default_registry().get(prompt_name).text
    selected = []
    content = pack_context(history, prompt_evidence(history.get("evidence", []), history.get("excerpt_chars", 360)),
                           history.get("context_tokens", 8000), selected=selected)
    if not assessment:
        return "\n" + prompt + content
    history["citation_evidence"] = {}
    for observation in selected:
        for fact in observation.get("facts", []):
            ref = fact.get("citation_ref")
            if not ref:
                continue
            history["citation_evidence"][ref] = {
                "entities": [uid for uid in (observation.get("subject_id"), fact.get("subject_id"), fact.get("other_id"),
                                             fact.get("object_id")) if uid],
                "knowledge_time": observation.get("knowledge_time"),
            }
    return "\n" + prompt + content


def references(evidence):
    refs = []
    for item in evidence:
        doc = item.get("data") or {}
        for field in ("facts", "results"):
            for row in doc.get(field, []):
                if not isinstance(row, dict):
                    continue
                value = row.get("id") or row.get("fact_id") or row.get("document_id")
                try:
                    ref = f"{item['kb_id']}/{UUID(str(value))}"
                except ValueError:
                    continue
                if ref not in refs:
                    refs.append(ref)
    return refs


def validate_historical_claims(value, history):
    """Retain bounded claims whose supplied citations all belong to this run."""
    if not isinstance(value, list):
        return []
    permitted = history.get("citation_evidence", {})
    accepted = []
    for claim in value[:8]:
        if not isinstance(claim, dict):
            continue
        text, citations = claim.get("claim"), claim.get("citations")
        if not isinstance(text, str) or not text.strip() or not isinstance(citations, list) or not 1 <= len(citations) <= 5:
            continue
        if any(not isinstance(ref, str) or ref not in permitted for ref in citations):
            continue
        entity = claim.get("entity_id")
        knowledge_time = claim.get("knowledge_time")
        if entity and not all(entity in permitted[ref]["entities"] for ref in citations):
            continue
        if knowledge_time and not all(knowledge_time == permitted[ref]["knowledge_time"] for ref in citations):
            continue
        accepted.append({"claim": sanitize_text(text, max_len=400), "citations": list(dict.fromkeys(citations)),
                         "status": "requires_analyst_review"})
    return accepted


async def choose(state, session):
    limits = session.limits
    schemas = {k: v.model_json_schema() for k, v in SCHEMAS.items()}
    prompts = default_registry()
    guidance = "\n".join(prompts.get("recon." + name).text for name in (
        "system", "planner", "tool_guide", "evidence_policy", "case_investigation"
    )) + json.dumps(schemas)
    content = pack_context(
        {"alert": state.alert_summary[:1000], "seeds": session.seed_metadata or list(session.seeds),
         "examined": sorted(session.examined), "tool_calls_left": limits.max_tool_calls - session.calls,
         "requests_left": limits.max_transport_requests - session.requests, "objectives": session.objectives,
         "queries_completed": len(session.seen), "retryable_queries": len(session.memory.retryable_queries)},
        prompt_evidence(session.evidence, limits.semantic_excerpt_chars), limits.history_context_tokens,
    )
    llm = make_chat_model(
        "recon", temperature=0, max_tokens=limits.max_planner_output_tokens,
        max_retries=0, timeout=limits.planner_timeout_seconds,
    )
    response = await safe_ainvoke(
        llm, [SystemMessage(content=guidance), HumanMessage(content=content)],
        admit_provider_call=session.model_budget.guard(final=False),
    )
    return response.content


class ReasoningStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["call_tool", "conclude", "insufficient_evidence", "budget_stop"]
    tool: str | None = None
    arguments: dict = Field(default_factory=dict)
    objective_id: str | None = Field(None, max_length=40)
    evidence_gap: str | None = Field(None, max_length=240)
    expected_observation: str | None = Field(None, max_length=240)
    hypothesis: str | None = Field(None, max_length=240)
    question_status: Literal["open", "resolved"] = "open"


def coverage(session):
    resolved = {}
    pending = {seed for seed, metadata in session.seed_metadata.items() if metadata.get("pending")}
    contexts, complete_contexts = set(), set()
    for item in session.evidence:
        seed = item.get("seed_id")
        doc = item.get("data") or {}
        if seed and item["status"] == "resolved" and doc.get("candidates"):
            resolved[seed] = (item.get("binding_id"), doc["candidates"][0]["entity_id"])
        elif seed and item["status"] == "pending_materialization":
            pending.add(seed)
        elif item.get("current_context") and item["status"] in {"complete", "partial"}:
            pair = (item.get("binding_id"), doc.get("requested_entity"))
            contexts.add(pair)
            if item["status"] == "complete":
                complete_contexts.add(pair)
    pending.difference_update(resolved)
    retained = len(session.seeds)
    examined = len(session.examined)
    omitted = session.case_eligible - retained
    complete = bool(retained and not omitted and examined == retained)
    return {
        "case_alerts": session.case_total,
        "eligible_seeds": session.case_eligible,
        "eligible_seeds_retained": retained,
        "examined_seeds": examined,
        "resolved_seeds": len(resolved),
        "unresolved_seeds": examined - len(set(resolved) | (pending & session.examined)),
        "pending_seeds": len(pending),
        "context_seeds": sum(pair in contexts for pair in resolved.values()),
        "complete_context_seeds": sum(pair in complete_contexts for pair in resolved.values()),
        "omitted_seeds": omitted,
        "binding_count": len(session.bindings),
        "omitted_bindings": session.omitted_bindings,
        "complete_seed_examination": complete,
        "complete_case_coverage": bool(complete and session.case_total == retained and not session.omitted_bindings),
    }


def history_status(stats, observations, stop):
    if stop in {"cancelled", "privacy_unavailable", "invalid_configuration", "unauthorized_scope"}:
        return stop
    usable = [item for item in observations if item.get("data")]
    if not usable and stats["pending_seeds"]:
        return "pending_materialization"
    if not usable:
        if stop.endswith(("budget", "deadline")):
            return "budget_exhausted"
        return "empty" if stop == "no_authorized_seed" else "unavailable"
    if all(item["status"] in {"empty", "not_found", "unresolved", "no_match"} for item in usable):
        return "pending_materialization" if stats["pending_seeds"] else "empty"
    if stats["complete_seed_examination"] and stats["complete_context_seeds"] == stats["eligible_seeds_retained"] and not any(
        item["status"] in {"partial", "unavailable", "context_truncated"} or (item.get("data") or {}).get("truncated")
        for item in observations
    ) and not stats["omitted_bindings"] and stop in {"assessed", "conclude"}:
        return "complete"
    return "partial"


def public_history_observations(observations):
    # Preserve candidate provenance in the run evidence. Free-form Search text
    # is specific to the bounded protected model turn.
    return [
        {**item, "data": {**item["data"], "results": [
            {key: row[key] for key in ("document_id", "chunk_id", "candidate_id") if key in row}
            for row in item["data"]["results"]
        ]}}
        if item["tool"] == "tkg.search_history" and item.get("data") else item
        for item in observations
    ]


async def reason(state, session, registry, assess, planner=choose):
    limits = session.limits
    ctx = ToolContext(
        tenant_id=str(session.workspace), incident_id=state.case_id, agent_name="ReconAgent", max_tool_calls=limits.max_tool_calls,
    )
    token = active.set(session)
    clock = asyncio.get_running_loop()
    started = clock.time()
    deadline = started + limits.timeout_seconds
    reserve = min(limits.assessment_timeout_seconds, limits.timeout_seconds)
    llm_calls = 0
    repair_available = True
    no_progress = 0
    outcome = "iteration_budget" if limits.loop_enabled else "assessed"

    def snapshot(*, final=False):
        stats = coverage(session)
        # Preserve an assessment's model-visible citation catalog across finalization.
        scoped = state.recon.history.get("citation_evidence", {})
        return {
            "evidence": public_history_observations(session.evidence) if final else session.evidence,
            "citations": references(session.evidence),
            "citation_evidence": scoped,
            "status": outcome,
            "stop_reason": outcome,
            "historical_status": history_status(stats, session.evidence, outcome),
            "context_tokens": limits.history_context_tokens,
            "excerpt_chars": limits.semantic_excerpt_chars,
            "coverage": stats,
            "tool_calls": session.calls,
            "tool_requests": session.requests,
            "llm_calls": llm_calls,
            "provider_calls": session.model_budget.provider_calls,
            "reserved_tokens_charged": session.model_budget.tokens,
            "estimated_cost_usd": session.model_budget.estimated_cost,
        }

    async def explore(name, args):
        async with asyncio.timeout(max(0, deadline - clock.time() - reserve)):
            return await registry.execute("tkg." + name, args, ctx)

    try:
        try:
            if limits.preflight_enabled and session.bindings:
                for seed_id in list(session.seeds)[:min(limits.preflight_seeds, max(0, limits.max_tool_calls - 1))]:
                    await explore("resolve_entity", {} if seed_id == "seed-1" else {"seed_id": seed_id})
                for entity in dict.fromkeys(entity for _, entity in session.depth):
                    if session.calls >= max(0, limits.max_tool_calls - 1):
                        break
                    await explore("get_entity_context", {"entity": entity})
                iocs = extract_iocs(state.alert_summary)
                if iocs and session.calls < limits.max_tool_calls - 1:
                    await explore("search_history", {"q": iocs[0]["value"], "top_k": limits.max_results})
            for _ in range(limits.max_iterations if limits.loop_enabled and session.bindings else 0):
                if clock.time() >= deadline - reserve:
                    outcome = "exploration_deadline"
                    break
                if session.calls >= limits.max_tool_calls:
                    outcome = "tool_budget"
                    break
                if session.requests >= limits.max_transport_requests:
                    outcome = "transport_budget"
                    break
                if llm_calls + 1 >= limits.max_llm_calls:
                    outcome = "llm_budget"
                    break
                llm_calls += 1
                try:
                    async with asyncio.timeout(min(limits.planner_timeout_seconds, max(0, deadline - clock.time() - reserve))):
                        step = ReasoningStep.model_validate_json(await planner(state, session))
                    if step.action != "call_tool":
                        if step.tool or step.arguments:
                            raise ValueError("unexpected arguments")
                        outcome = step.action
                        break
                    if step.tool not in SCHEMAS:
                        raise ValueError("unknown tool")
                    output = await explore(step.tool, step.arguments)
                except (ValueError, TypeError):
                    if not repair_available:
                        outcome = "invalid_reasoning_step"
                        break
                    repair_available = False
                    session.evidence.append({"tool": "planner", "status": "invalid_action_use_schema"})
                    continue
                if step.objective_id:
                    session.objectives[step.objective_id] = {
                        "evidence_gap": sanitize_text(step.evidence_gap or "", max_len=240),
                        "expected_observation": sanitize_text(step.expected_observation or "", max_len=240),
                        "hypothesis": sanitize_text(step.hypothesis or "", max_len=240),
                        "question_status": step.question_status,
                        "last_outcome": output[0]["status"] if output else "empty",
                    }
                stalled = not output or all(row["status"] in {
                    "visited_or_depth_limit", "call_budget", "unverified_entity", "unauthorized_seed", "no_source_binding",
                } for row in output)
                no_progress = no_progress + 1 if stalled else 0
                if no_progress >= 2:
                    outcome = "no_progress"
                    break
        except TimeoutError:
            outcome = "exploration_deadline"
        except ModelBudgetStop as exc:
            outcome = str(exc)
        except (PrivacyConfigurationError, RemotePrivacyError):
            outcome = "privacy_unavailable"
            return {"summary": "Historical assessment paused because the private model boundary was unavailable."}
        except (asyncpg.PostgresError, httpx.TransportError, APIError) as exc:
            outcome = "history_dependency_unavailable"
            logger.warning("tkg.recon.degraded", error_type=type(exc).__name__)
        if not session.seeds:
            outcome = "no_authorized_seed"
        elif not session.bindings:
            outcome = "no_workspace_binding"
        llm_calls += 1
        session.memory.stop_reason = outcome
        state.recon.history = snapshot()
        try:
            async with asyncio.timeout(min(limits.assessment_timeout_seconds, max(0, deadline - clock.time()))):
                return await assess(state)
        except ModelBudgetStop as exc:
            outcome = str(exc)
        except TimeoutError:
            outcome = "assessment_deadline"
        except (PrivacyConfigurationError, RemotePrivacyError):
            outcome = "privacy_unavailable"
        return {"summary": "Historical assessment could not complete within its configured protections."}
    except asyncio.CancelledError:
        outcome = "cancelled"
        raise
    except Exception:
        outcome = "internal_error"
        raise
    finally:
        session.memory.stop_reason = outcome
        state.recon.history = snapshot(final=True)
        active.reset(token)
        logger.info("tkg.recon.completed", run_id=str(state.run_id), stop_reason=outcome,
                    elapsed_ms=round((clock.time() - started) * 1000), tool_calls=session.calls,
                    requests=session.requests, provider_calls=session.model_budget.provider_calls)


CASE_SEEDS = """
WITH owned_case AS (
    SELECT id,alert_ids FROM aisoc_cases WHERE id=$2 AND tenant_id=$1
), members AS (
    SELECT a.id,a.connector_id,a.connector_type,a.severity,a.event_time
    FROM alerts a CROSS JOIN owned_case c
    WHERE a.tenant_id=$1 AND (a.case_id=c.id OR
          (a.case_id IS NULL AND a.id=ANY(c.alert_ids)))
), eligible AS (
    SELECT m.* FROM members m
    WHERE EXISTS (SELECT 1 FROM workspace_tkg_bindings b
                  WHERE b.tenant_id=$1 AND b.connector_id=m.connector_id AND b.enabled AND b.source_system='splunk')
      AND NOT EXISTS (SELECT 1 FROM case_alert_scopes s WHERE s.tenant_id=$1 AND s.case_id=$2
                      AND s.excluded_alert_ids ? m.id::text)
), ranked AS (
    SELECT e.*, row_number() OVER (PARTITION BY connector_id ORDER BY
      CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
      event_time DESC NULLS LAST,id) AS source_rank
    FROM eligible e
)
SELECT roots.*,(SELECT count(*) FROM members) AS total,(SELECT count(*) FROM eligible) AS eligible,
       EXISTS (SELECT 1 FROM owned_case) AS owned,
       EXISTS (SELECT 1 FROM tkg_alert_deliveries d WHERE d.tenant_id=$1 AND d.alert_row_id=roots.id
               AND d.state='pending_materialization') AS pending
FROM (VALUES (1)) anchor(dummy)
LEFT JOIN LATERAL (
    SELECT * FROM ranked ORDER BY source_rank,
        CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
        event_time DESC NULLS LAST,id LIMIT $3
) roots ON TRUE
"""


async def create_session(scope, case_scope, limits, state):
    from app.investigator.ledger import get_pool

    async with asyncio.timeout(10):
        pool = await get_pool()
    if pool is None:
        raise ConnectionError("investigation database unavailable")
    case_total = case_eligible = None
    async with asyncio.timeout(10), pool.acquire() as conn, conn.transaction():
        await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(scope[0]))
        if case_scope:
            rows = await conn.fetch(CASE_SEEDS, *scope, limits.max_case_seeds)
            case_total, case_eligible = rows[0]["total"], rows[0]["eligible"]
            if not rows[0]["owned"]:
                return None
        else:
            rows = await conn.fetch(
                """SELECT a.id,a.connector_id,a.connector_type,a.severity,a.event_time,
                    EXISTS (SELECT 1 FROM tkg_alert_deliveries d WHERE d.tenant_id=$1 AND d.alert_row_id=a.id
                            AND d.state='pending_materialization') AS pending
                    FROM alerts a WHERE a.tenant_id=$1 AND a.id=$2""",
                *scope,
            )
            if not rows:
                return None
        roots = {f"seed-{index}": row for index, row in enumerate((r for r in rows if r["id"]), 1)}
        seeds = {key: (row["id"], row["connector_id"]) for key, row in roots.items()}
        metadata = {key: {
            "severity": row["severity"], "source": row["connector_type"],
            "observed": row["event_time"].isoformat() if row["event_time"] else None, "pending": row["pending"],
        } for key, row in roots.items()}
        binding_rows = []
        if seeds:
            connector_ids = sorted({connector for _, connector in seeds.values() if connector})
            binding_rows = await conn.fetch(
                """SELECT *,count(*) OVER () AS active_count FROM workspace_tkg_bindings WHERE tenant_id=$1 AND enabled
                ORDER BY coalesce(connector_id=ANY($2::uuid[]),false) DESC,kb_id,id LIMIT $3""",
                scope[0], connector_ids, limits.max_bindings,
            )
    omitted_bindings = binding_rows[0]["active_count"] - len(binding_rows) if binding_rows else 0
    bindings = [Binding.from_row(row, scope[0]) for row in binding_rows]
    alert_id, connector = next(iter(seeds.values()), (None, None))
    return Session(pool, None, scope[0], alert_id, connector, bindings, limits,
                   seeds=seeds, case_total=case_total, case_eligible=case_eligible, seed_metadata=metadata,
                   omitted_bindings=omitted_bindings, investigation_id=str(state.run_id))


async def assess_with_history(state, assess):
    case_scope = case_grant.get()
    scope = case_scope or grant.get()
    if not scope or str(scope[0]) != state.tenant_id:
        return await assess(state)
    try:
        limits = Limits()
    except ValueError:
        state.recon.history.update(status="invalid_configuration", historical_status="invalid_configuration")
        return await assess(state)
    if not limits.enabled:
        return await assess(state)
    if not protected(scope[0]):
        state.recon.history.update(status="privacy_unavailable", historical_status="privacy_unavailable")
        return {"summary": "Historical Recon requires a protected workspace context."}
    try:
        session = await create_session(scope, case_scope, limits, state)
        tls = tls_context()
    except (asyncpg.PostgresError, BindingError, OSError, TimeoutError) as exc:
        logger.warning("tkg.recon.initialization_unavailable", error_type=type(exc).__name__)
        state.recon.history.update(status="initialization_unavailable", historical_status="unavailable")
        return await assess(state)
    if session is None:
        state.recon.history.update(status="unauthorized_scope", historical_status="unauthorized_scope")
        return await assess(state)
    from app.runtime.catalog import build_tool_registry

    async with httpx.AsyncClient(
        trust_env=False, timeout=httpx.Timeout(limits.search_timeout_seconds, connect=5), verify=tls,
    ) as http:
        session.http = http
        return await reason(state, session, build_tool_registry(), assess)
