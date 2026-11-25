"""Bounded historical lookup and reassessment inside the investigator Recon node."""

import asyncio
import hmac
import json
import os
from typing import Literal
from uuid import UUID

import httpx
import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field

from app.core.cost_telemetry import current_cost_tracker
from app.investigator.prompt_sanitizer import sanitize_text, sanitize_value, wrap_untrusted
from app.investigator.tools import extract_iocs
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model
from app.llm.prompt_registry import default_registry
from app.privacy.context import current_privacy_gateway, privacy_required
from app.runtime.tools import ToolContext

from .binding import Binding, tls_context
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
        retrieval = doc.get("retrieval") or {}
        if item["tool"] == "tkg.search_history" and isinstance(retrieval, dict):
            view["retrieval"] = {field: retrieval[field] for field in (
                "dense_executed", "lexical_method", "reranker_status", "score_type",
            ) if isinstance(retrieval.get(field), (str, bool))}
        for target, rows in (
            ("facts", doc.get("facts", [])),
            ("candidates", doc.get("candidates", [])),
            ("candidates", doc.get("results", [])),
        ):
            for row in rows[:20]:
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
                    if row.get("candidate_id"):
                        entry["candidate_id"] = row["candidate_id"]
                    text = row.get("text")
                    # Credentials can be arbitrary text. Omit suspicious excerpts locally
                    # and send the remaining bounded untrusted content through DLP.
                    if isinstance(text, str) and not re.search(
                        r"(?i)password|credential|api[_ -]?key|token|secret|bearer|private key", text
                    ):
                        entry["semantic_excerpt"] = sanitize_text(text, max_len=excerpt_chars)
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
        result.append(view)
    return result


def pack_context(metadata, observations, budget):
    """Keep the wire JSON complete even when observations exceed the budget."""
    packed = {"state": sanitize_value(metadata), "evidence": [], "omitted": len(observations)}
    def render(value):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    # UTF-8 byte count gives a conservative upper bound on BPE token count.
    if len(render(packed).encode()) > budget:
        packed["state"] = {"status": "metadata_truncated"}
    for observation in reversed(observations):
        packed["evidence"].append(sanitize_value(observation, max_field_len=1000))
        packed["omitted"] -= 1
        if len(render(packed).encode()) > budget:
            packed["evidence"].pop()
            packed["omitted"] += 1
    return wrap_untrusted(render(packed), label="tkg_evidence")


def history_prompt(state):
    history = state.recon.history
    if not history or not protected(state.tenant_id):
        return ""
    prompt = default_registry().get("recon.final_assessment").text
    metadata = {key: value for key, value in history.items() if key != "evidence"}
    return "\n" + prompt + pack_context(metadata, prompt_evidence(history.get("evidence", []), history.get("excerpt_chars", 360)),
                                           history.get("context_tokens", 8000))


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
    permitted = set(history.get("citations", []))
    accepted = []
    for claim in value[:8]:
        if not isinstance(claim, dict):
            continue
        text, citations = claim.get("claim"), claim.get("citations")
        if not isinstance(text, str) or not text.strip() or not isinstance(citations, list) or not 1 <= len(citations) <= 5:
            continue
        if any(not isinstance(ref, str) or ref not in permitted for ref in citations):
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
        {"alert": state.alert_summary[:2000], "seed_ids": list(session.seeds),
         "examined": sorted(session.examined), "tool_calls_left": limits.max_tool_calls - session.calls,
         "requests_left": limits.max_transport_requests - session.requests, "objectives": session.objectives},
        prompt_evidence(session.evidence, limits.semantic_excerpt_chars), limits.history_context_tokens,
    )
    llm = make_chat_model("recon", temperature=0, max_tokens=limits.max_planner_output_tokens)
    response = await safe_ainvoke(llm, [SystemMessage(content=guidance), HumanMessage(content=content)])
    return response.content


class ReasoningStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["call_tool", "conclude", "insufficient_evidence", "budget_stop"]
    tool: str | None = None
    arguments: dict = Field(default_factory=dict)
    objective_id: str | None = Field(None, max_length=40)
    evidence_gap: str | None = Field(None, max_length=240)
    expected_observation: str | None = Field(None, max_length=240)


async def reason(state, session, registry, assess, planner=choose):
    limits = session.limits
    ctx = ToolContext(
        tenant_id=str(session.workspace), incident_id=state.case_id, agent_name="ReconAgent", max_tool_calls=limits.max_tool_calls
    )

    async def call(name, args):
        return await registry.execute("tkg." + name, args, ctx)

    token = active.set(session)
    clock = asyncio.get_running_loop()
    deadline = clock.time() + limits.timeout_seconds
    reserve = min(limits.assessment_timeout_seconds, limits.timeout_seconds / 3)
    llm_calls = 0
    repair_available = True

    def history():
        outcomes = {item["seed_id"]: item["status"] for item in session.evidence if "seed_id" in item}
        return {
            "evidence": session.evidence,
            "citations": references(session.evidence),
            "status": outcome,
            "stop_reason": outcome,
            "historical_status": "partial" if session.evidence else "unavailable",
            "context_tokens": limits.history_context_tokens,
            "excerpt_chars": limits.semantic_excerpt_chars,
            "coverage": {
                "case_alerts": session.case_total,
                "eligible_seeds_retained": len(session.seeds),
                "examined_seeds": len(session.examined),
                "resolved_seeds": sum(value == "resolved" for value in outcomes.values()),
                "pending_seeds": sum(value == "pending_materialization" for value in outcomes.values()),
                "binding_count": len(session.bindings),
                "complete_case_coverage": False,
            },
            "tool_calls": session.calls, "tool_requests": session.requests, "llm_calls": llm_calls,
        }

    async def explore(name,args):
        async with asyncio.timeout(max(0, deadline - clock.time() - reserve)):
            return await call(name,args)

    outcome = "iteration_budget" if limits.loop_enabled else "assessed"
    try:
        try:
            if limits.preflight_enabled:
                for seed_id in list(session.seeds)[:2]:
                    await explore("resolve_entity", {} if seed_id == "seed-1" else {"seed_id":seed_id})
            for entity in dict.fromkeys(entity for _,entity in session.depth):
                if session.calls >= limits.max_tool_calls:
                    break
                await explore("get_entity_context", {"entity":entity})
            iocs = extract_iocs(state.alert_summary)
            if limits.preflight_enabled and iocs and session.calls < limits.max_tool_calls:
                await explore("search_history", {"q": iocs[0]["value"], "top_k": limits.max_results})
        except TimeoutError:
            outcome = "exploration_deadline"
        tracker = current_cost_tracker()
        initial_tokens = tracker.total_tokens if tracker else 0
        for _ in range(limits.max_iterations if limits.loop_enabled else 0):
            if clock.time() >= deadline - reserve:
                outcome = "exploration_deadline"
                break
            if tracker and tracker.total_tokens - initial_tokens + limits.assessment_tokens + limits.history_context_tokens >= limits.max_model_tokens:
                outcome = "model_token_budget"
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
            if tracker and tracker.total_cost_usd >= limits.max_cost_usd:
                outcome = "cost_budget"
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
                if step.objective_id:
                    session.objectives[step.objective_id] = {
                        "evidence_gap": step.evidence_gap or "",
                        "expected_observation": step.expected_observation or "",
                        "last_outcome": output[0]["status"] if output else "empty",
                    }
                if not output or all(i["status"] in {"visited_or_depth_limit", "call_budget"} for i in output):
                    outcome = "no_progress"
                    break
            except (ValueError, TypeError):
                outcome = "invalid_reasoning_step"
                if not repair_available:
                    break
                repair_available = False
                session.evidence.append({"tool": "planner", "status": "invalid_action_use_schema"})
            except TimeoutError:
                outcome = "exploration_deadline"
                break
        if tracker and tracker.total_cost_usd >= limits.max_cost_usd:
            outcome = "cost_budget"
            return {"summary": "Historical assessment stopped at the configured cost limit."}
        llm_calls += 1
        state.recon.history = history()
        try:
            async with asyncio.timeout(min(limits.assessment_timeout_seconds, max(0, deadline - clock.time()))):
                return await assess(state)
        except TimeoutError:
            outcome = "assessment_deadline"
            return {"summary": "Historical assessment did not complete before its deadline."}
    finally:
        active.reset(token)
        state.recon.history = history()


async def assess_with_history(state, assess):
    case_scope = case_grant.get()
    scope = case_scope or grant.get()
    if not scope or str(scope[0]) != state.tenant_id:
        return await assess(state)
    try:
        limits = Limits()
    except ValueError:
        state.recon.history["status"] = "invalid_configuration"
        return await assess(state)
    if not limits.enabled:
        return await assess(state)
    try:
        from app.investigator.ledger import get_pool
        from app.runtime.catalog import build_tool_registry

        if not protected(scope[0]):
            raise ValueError("privacy context unavailable")
        pool = await get_pool()
        case_total = None
        async with asyncio.timeout(10), pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(scope[0]))
            if case_scope:
                # Include only active case membership and the trusted connector bindings. Rank
                # each connector's strongest recent alert first before repeating a connector.
                rows = await conn.fetch(
                    """WITH members AS (
                        SELECT a.id,a.connector_id,a.severity,a.event_time
                        FROM alerts a JOIN aisoc_cases c ON c.id=$2 AND c.tenant_id=a.tenant_id
                        WHERE a.tenant_id=$1 AND (a.case_id=c.id OR
                            (a.case_id IS NULL AND to_jsonb(c.alert_ids) ? a.id::text))
                    ), ranked AS (
                        SELECT m.*, row_number() OVER (PARTITION BY connector_id ORDER BY
                            CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                            event_time DESC NULLS LAST,id) AS source_rank
                        FROM members m WHERE EXISTS (SELECT 1 FROM workspace_tkg_bindings b
                            WHERE b.tenant_id=$1 AND b.connector_id=m.connector_id AND b.enabled)
                    ) SELECT id,connector_id,(SELECT count(*) FROM members) AS total
                        FROM ranked ORDER BY source_rank,
                         CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                         event_time DESC NULLS LAST,id LIMIT $3""",
                    *scope, limits.max_case_seeds,
                )
                case_total = rows[0]["total"] if rows else None
            else:
                rows = await conn.fetch("SELECT id,connector_id FROM alerts WHERE tenant_id=$1 AND id=$2", *scope)
            seeds = {f"seed-{i}": (row["id"], row["connector_id"]) for i,row in enumerate(rows, 1)}
            if seeds:
                connector_ids = sorted({connector for _,connector in seeds.values() if connector})
                rows = await conn.fetch(
                    """SELECT * FROM workspace_tkg_bindings WHERE tenant_id=$1 AND enabled
                    ORDER BY coalesce(connector_id=ANY($2::uuid[]),false) DESC,kb_id,id LIMIT $3""",
                    scope[0], connector_ids, limits.max_bindings + 1,
                )
        if not seeds or not rows:
            state.recon.history["status"] = "no_workspace_binding" if seeds else "no_authorized_seed"
        elif len(rows) > limits.max_bindings:
            state.recon.history["status"] = "binding_limit"
        else:
            bindings = [Binding.from_row(row, scope[0]) for row in rows]
            alert_id, connector = next(iter(seeds.values()))
            async with httpx.AsyncClient(
                trust_env=False, timeout=httpx.Timeout(limits.search_timeout_seconds, connect=5), verify=tls_context()
            ) as http:
                session = Session(pool, http, scope[0], alert_id, connector, bindings, limits,
                                  seeds=seeds, case_total=case_total)
                return await reason(state, session, build_tool_registry(), assess)
    except Exception as exc:
        logger.warning("tkg.recon.unavailable", error_type=type(exc).__name__)
        state.recon.history["status"] = "unavailable"
    return await assess(state)
