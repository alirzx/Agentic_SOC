"""LLM-backed triage agent (Phase 8.6)."""

from __future__ import annotations

import os
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from app.investigator.prompt_sanitizer import sanitize_text, wrap_untrusted
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model, resolve_base_url
from app.llm.provider_errors import classify_llm_exception, is_auth_failure, is_retryable, sanitize_error_message
from app.prompt_serialization import format_extra_fields_for_llm
from app.prompting.envelope import make_nonce, scan_evidence_fields, system_rule
from app.runtime.contracts import AgentContext, AgentResult, Finding, NextTask

from .models import TriageResult
from .prompts import TRIAGE_SYSTEM_PROMPT, triage_prompt_meta
from .tool_runner import list_tools_for_agent, parse_json_response

logger = structlog.get_logger()

MAX_TRIAGE_RETRIES = int(os.getenv("AGENTIC_LLM_PARSE_RETRIES", "2"))


def is_llm_configured() -> bool:
    return bool(resolve_base_url()) and bool(os.getenv("OPENAI_API_KEY", "").strip())


def _build_alert_context(context: AgentContext) -> str:
    raw = dict(context.state.raw_alert or {})
    parts = [
        f"Title: {sanitize_text(str(context.objective or ''))}",
        f"Severity: {sanitize_text(str(context.state.severity or 'unknown'))}",
    ]
    if raw.get("description"):
        parts.append(f"Description: {sanitize_text(str(raw['description']))}")
    telemetry = raw.get("telemetry") or []
    if telemetry:
        parts.append(f"Telemetry events: {len(telemetry)}")
    extra = {k: v for k, v in raw.items() if k not in {"telemetry", "title", "description"}}
    if extra:
        parts.append("Additional fields:\n" + format_extra_fields_for_llm(extra))
    return wrap_untrusted("\n".join(parts), label="alert_telemetry")


async def run_llm_triage(
    context: AgentContext,
    registry: Any,
    *,
    agent_name: str = "triage",
    agent_version: str = "2.0",
) -> AgentResult:
    """Execute LLM triage; raises on hard failure (caller may fallback)."""
    raw = context.state.raw_alert or {}
    injection = scan_evidence_fields((str(k), v) for k, v in raw.items() if isinstance(v, (str, int, float, list, dict)))
    nonce = make_nonce()
    tools = list_tools_for_agent(registry, agent_name)
    tool_names = [t["name"] for t in tools]
    alert_blob = _build_alert_context(context)
    user_prompt = (
        f"{alert_blob}\n\nAvailable read-only tools: {', '.join(tool_names)}\n"
        "Respond with JSON only."
    )
    llm = make_chat_model("triage", temperature=0.0, max_tokens=768)
    triage_result: TriageResult | None = None
    last_error: str | None = None
    for attempt in range(MAX_TRIAGE_RETRIES + 1):
        try:
            response = await safe_ainvoke(
                llm,
                [
                    SystemMessage(content=TRIAGE_SYSTEM_PROMPT + "\n\n" + system_rule(nonce)),
                    HumanMessage(content=user_prompt),
                ],
            )
            data = parse_json_response(str(response.content))
            triage_result = TriageResult.model_validate(data)
            break
        except Exception as exc:  # noqa: BLE001
            classified = classify_llm_exception(exc)
            last_error = sanitize_error_message(str(exc))
            if is_auth_failure(classified):
                raise classified
            if not is_retryable(classified) or attempt >= MAX_TRIAGE_RETRIES:
                logger.warning("llm_triage_failed", attempt=attempt, error=last_error, category=classified.category)
                break
            logger.warning("llm_triage_retry", attempt=attempt, error=last_error, category=classified.category)
    if triage_result is None:
        raise RuntimeError(last_error or "llm_triage_failed")
    uncertainties = list(triage_result.uncertainties)
    if injection.should_demote_to_l0:
        uncertainties.append("prompt_injection_detected_in_telemetry")
    finding = Finding(
        statement=f"classification={triage_result.classification}",
        evidence_ids=[],
        confidence=triage_result.confidence,
        mitre_techniques=[],
    )
    context.metadata["triage_result"] = triage_result.model_dump(mode="json")
    context.metadata["execution_mode"] = "LLM"
    context.metadata["prompt_meta"] = triage_prompt_meta()
    reasoning_summary = (
        f"LLM triage classification={triage_result.classification} "
        f"confidence={triage_result.confidence:.2f} "
        f"hypotheses={len(triage_result.hypotheses)}"
    )
    return AgentResult(
        status="success",
        findings=[finding],
        evidence=[],
        next_tasks=[NextTask(agent="investigation", objective="collect_evidence", priority=1)],
        confidence=triage_result.confidence,
        reasoning=reasoning_summary,
        uncertainty=uncertainties,
    )
