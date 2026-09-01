"""LLM-backed tool-using investigation agent (Phase 8.6 / 8.6.2)."""

from __future__ import annotations

import time
from typing import Any

import structlog

from app.core.cost_telemetry import current_cost_tracker
from app.investigator.prompt_sanitizer import sanitize_text, wrap_untrusted
from app.llm.factory import make_chat_model
from app.prompting.envelope import make_nonce
from app.runtime.contracts import AgentContext, AgentResult, Finding, NextTask
from app.runtime.playbooks import playbook_guidance_for_context, resolve_soc_doc_playbook_from_context

from .execution_errors import InvestigationExecutionMeta, InvestigationStructuredOutputError
from .limits import max_cost_per_incident, max_investigation_iterations, max_investigation_seconds, max_llm_calls
from .models import InvestigationOutput, StructuredInvestigationState
from .prompts import investigation_prompt_meta
from .structured_step import invoke_investigation_step
from .tool_runner import execute_registry_tool, list_tools_for_agent
from .validation import validate_investigation_output

logger = structlog.get_logger()


def _budget_exceeded(state: StructuredInvestigationState, started: float, tool_calls: int) -> bool:
    if time.monotonic() - started > max_investigation_seconds():
        return True
    if state.llm_calls >= max_llm_calls():
        return True
    if tool_calls >= max_investigation_iterations():
        return True
    tracker = current_cost_tracker()
    cap = max_cost_per_incident()
    if tracker is not None and cap is not None and tracker.total_cost_usd > cap:
        return True
    return False


def _state_summary(state: StructuredInvestigationState, evidence: list[Any]) -> str:
    lines = [
        f"Incident: {state.incident_id}",
        f"Observations: {len(state.observations)}",
        f"Evidence collected: {len(evidence)}",
    ]
    for ev in evidence[-8:]:
        lines.append(f"evidence_id={ev.id}: source={ev.source} tool={ev.provenance.tool if ev.provenance else ev.source}")
    if state.observations:
        lines.append("Recent observations:")
        for obs in state.observations[-5:]:
            lines.append(f"  - {sanitize_text(obs, max_len=200)}")
    return wrap_untrusted("\n".join(lines), label="investigation_context")


def _tool_unavailable_reason(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None
    splunk_status = str(result.get("status") or "")
    if splunk_status.startswith("SPLUNK_") and splunk_status not in {
        "SUCCESS_WITH_RESULTS",
        "SUCCESS_NO_RESULTS",
        "SPLUNK_RESULT_TRUNCATED",
    }:
        return splunk_status
    detail = str(result.get("detail") or result.get("error") or "")
    lowered = detail.lower()
    if "getaddrinfo" in lowered or "network" in lowered or "dns" in lowered:
        return "DNS/NETWORK"
    if result.get("error") in {"tool_execution_failed", "tool_not_found"}:
        return str(result.get("error"))
    return None


async def run_llm_investigation(
    context: AgentContext,
    registry: Any,
    *,
    agent_name: str = "investigation",
    agent_version: str = "2.0",
) -> AgentResult:
    started = time.monotonic()
    triage_payload = context.metadata.get("triage_result") or {}
    exec_meta = InvestigationExecutionMeta(execution_mode="LLM")
    state = StructuredInvestigationState(
        incident_id=context.incident_id,
        investigation_plan=triage_payload.get("investigation_plan") or [],
        hypotheses=triage_payload.get("hypotheses") or [],
        execution_mode="LLM",
    )
    tools = list_tools_for_agent(registry, agent_name)
    tool_names = [t["name"] for t in tools]
    soc_playbook = resolve_soc_doc_playbook_from_context(context)
    soc_playbook_guidance = playbook_guidance_for_context(context) or ""
    if soc_playbook is not None:
        context.metadata["soc_doc_playbook_id"] = soc_playbook.id
        context.metadata["soc_doc_playbook_mitre"] = soc_playbook.mitre_id
    if soc_playbook_guidance:
        context.metadata["soc_doc_playbook_guidance"] = soc_playbook_guidance
    nonce = make_nonce()
    llm = make_chat_model("investigation", temperature=0.0, max_tokens=1024)
    collected_evidence: list[Any] = list(context.evidence)
    tool_call_count = 0
    output: InvestigationOutput | None = None
    last_error: str | None = None
    step_index = 0

    while not _budget_exceeded(state, started, tool_call_count):
        playbook_section = ""
        if soc_playbook_guidance:
            playbook_section = f"SOC analyst playbook guidance:\n{soc_playbook_guidance}\n"
        user_content = (
            f"Objective: {sanitize_text(context.objective or '')}\n"
            f"Allow-listed tools: {', '.join(tool_names)}\n"
            f"{playbook_section}"
            f"{_state_summary(state, collected_evidence)}\n"
            "Respond with JSON only."
        )
        try:
            step = await invoke_investigation_step(
                llm,
                nonce=nonce,
                user_content=user_content,
                attempt_index=step_index + 1,
                exec_meta=exec_meta,
            )
            state.llm_calls = exec_meta.llm_calls
            step_index += 1
        except InvestigationStructuredOutputError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            logger.warning("llm_investigation_step_failed", error=last_error)
            break
        if step.action == "conclude" and step.output is not None:
            available_ids = {ev.id for ev in collected_evidence}
            output = validate_investigation_output(step.output, available_evidence_ids=available_ids)
            break
        if step.action == "tool" and step.tool:
            tool_call_count += 1
            result, evidence = await execute_registry_tool(
                registry,
                context,
                agent_name=agent_name,
                agent_version=agent_version,
                tool_name=step.tool,
                arguments=step.arguments,
                tool_call_count=tool_call_count,
                reason=step.reason,
            )
            unavailable = _tool_unavailable_reason(result)
            evidence_items = evidence if isinstance(evidence, list) else ([evidence] if evidence else [])
            splunk_status = result.get("status") if isinstance(result, dict) else None
            tool_ok = bool(evidence_items) or splunk_status in {
                "SUCCESS_NO_RESULTS",
                "SUCCESS_WITH_RESULTS",
                "SPLUNK_RESULT_TRUNCATED",
            }
            state.tool_calls.append(
                {
                    "tool_name": step.tool,
                    "arguments": step.arguments,
                    "permission": "READ_SECURITY_DATA",
                    "result": "ok" if tool_ok else "error",
                    "tool_status": "UNAVAILABLE" if unavailable else ("ok" if tool_ok else "error"),
                    "unavailable_reason": unavailable,
                    "splunk_status": splunk_status,
                    "dry_run": bool(context.metadata.get("shadow_mode")),
                    "timestamp": time.time(),
                }
            )
            if evidence_items:
                for ev in evidence_items:
                    collected_evidence.append(ev)
                    state.evidence_ids.append(ev.id)
                ids_preview = ", ".join(ev.id for ev in evidence_items[:5])
                state.observations.append(
                    f"Tool {step.tool} returned {len(evidence_items)} evidence item(s) [{ids_preview}]: "
                    f"{sanitize_text(step.reason, max_len=120)}"
                )
            elif splunk_status == "SUCCESS_NO_RESULTS":
                state.observations.append(
                    f"Tool {step.tool} completed with no matching SIEM events: "
                    f"{sanitize_text(step.reason, max_len=120)}"
                )
            else:
                reason_label = unavailable or "error"
                state.observations.append(
                    f"Tool {step.tool} failed ({reason_label}): {sanitize_text(str(result), max_len=200)}"
                )
            continue
        state.observations.append(f"Unrecognized LLM step: {step.action}")
        break

    if output is None:
        output = InvestigationOutput(
            status="INSUFFICIENT_EVIDENCE",
            uncertainties=[last_error or "investigation limits reached"],
        )
    claims = output.claims
    state.claims = claims
    state.uncertainties = list(output.uncertainties)
    state.open_questions = list(output.open_questions)
    state.risk_signals = output.risk_signals
    context.metadata["investigation_state"] = state.model_dump(mode="json")
    context.metadata["investigation_execution"] = exec_meta.as_dict()
    context.metadata.setdefault("splunk_tool_calls", int(context.metadata.get("splunk_tool_calls", 0)))
    context.metadata.setdefault("splunk_events", int(context.metadata.get("splunk_events", 0)))
    context.metadata.setdefault("splunk_status", context.metadata.get("splunk_status", "NOT_USED"))
    context.metadata["risk_signals"] = output.risk_signals.model_dump()
    if state.llm_calls > 0 and exec_meta.parse_status == "VALID":
        context.metadata["execution_mode"] = "LLM"
        context.metadata["prompt_meta"] = investigation_prompt_meta()
    elif context.metadata.get("execution_mode") != "FALLBACK_HEURISTIC":
        context.metadata["execution_mode"] = "FAILED"
    findings = [
        Finding(
            statement=claim.claim,
            evidence_ids=list(claim.evidence_ids),
            confidence=claim.confidence,
            mitre_techniques=[],
        )
        for claim in claims
    ]
    if not findings:
        findings = [
            Finding(
                statement=f"investigation status={output.status}",
                evidence_ids=state.evidence_ids[:10],
                confidence=0.4,
            )
        ]
    return AgentResult(
        status="success" if output.status == "completed" else "failed",
        findings=findings,
        evidence=[ev for ev in collected_evidence if ev not in context.evidence],
        next_tasks=[NextTask(agent="threat-intel", objective="enrich_iocs", priority=1)],
        confidence=max((c.confidence for c in claims), default=0.4),
        reasoning=f"LLM investigation status={output.status} tool_calls={tool_call_count} llm_calls={state.llm_calls}",
        uncertainty=list(output.uncertainties),
    )
