"""Versioned adapters over existing agent runners (spec §11–14). Do not replace façades."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import structlog

from .contracts import (
    Agent,
    AgentAction,
    AgentContext,
    AgentResult,
    Evidence,
    EvidenceProvenance,
    Finding,
    NextTask,
)
from .hypothesis import Hypothesis, reject_hypothesis, support_hypothesis
from .llm_agents.execution_errors import InvestigationStructuredOutputError
from .llm_agents import is_llm_configured, run_llm_investigation, run_llm_triage
from .tools import SocToolRegistry

logger = structlog.get_logger()


def _uuid_or_new(value: str) -> UUID:
    try:
        return UUID(value)
    except (ValueError, TypeError):
        return uuid4()


def _investigation_state(context: AgentContext) -> Any:
    from app.models.state import AgentStatus, InvestigationState

    tenant = context.tenant_id or str(uuid4())
    return InvestigationState(
        incident_id=_uuid_or_new(context.incident_id),
        tenant_id=_uuid_or_new(tenant),
        alert_summary=context.objective or str(context.state.summary),
        raw_alert=dict(context.state.raw_alert),
        status=AgentStatus.PENDING,
    )


def _evidence_from_state(
    context: AgentContext,
    source: str,
    payload: dict[str, Any],
    agent: str,
    version: str,
) -> Evidence:
    return Evidence(
        incident_id=context.incident_id,
        type=source,
        source=source,
        data=payload,
        confidence=0.6,
        provenance=EvidenceProvenance(
            agent=agent,
            agent_version=version,
            tool=source,
            source=source,
        ),
    )


async def _heuristic_triage(agent: Agent, context: AgentContext) -> AgentResult:
    from app.agents.triage_agent import run_triage

    state = await run_triage(_investigation_state(context))
    evidence = _evidence_from_state(
        context,
        "triage",
        {
            "findings": state.findings,
            "mitre": state.mitre_mappings,
            "raw_alert": state.raw_alert,
        },
        agent.name,
        agent.version,
    )
    text = " ".join(state.findings).lower()
    hypothesis = Hypothesis(name="initial", statement=context.objective or "unspecified", confidence=0.5)
    if "false positive" in text or "benign" in text:
        hypothesis = reject_hypothesis(hypothesis, evidence_ids=[evidence.id], reason="triage classified benign/FP")
    else:
        hypothesis = support_hypothesis(hypothesis, evidence_ids=[evidence.id], reason="triage escalated for investigation")
    finding = Finding(
        statement="; ".join(state.findings) or "triage complete",
        evidence_ids=[evidence.id],
        confidence=float(getattr(state, "confidence", 0.5) or 0.5),
        mitre_techniques=list(state.mitre_mappings),
    )
    context.metadata.setdefault("execution_mode", "HEURISTIC")
    return AgentResult(
        status="success",
        findings=[finding],
        evidence=[evidence],
        next_tasks=[NextTask(agent="investigation", objective="collect_evidence", priority=1)],
        confidence=finding.confidence,
        reasoning=f"heuristic hypothesis={hypothesis.status}",
        uncertainty=[] if state.findings else ["triage produced no findings"],
    )


async def _heuristic_investigation(agent: Agent, context: AgentContext) -> AgentResult:
    from app.agents.investigation_agent import run_investigation

    state = await run_investigation(_investigation_state(context))
    evidence = _evidence_from_state(
        context,
        "investigation",
        {"findings": state.findings, "mitre": state.mitre_mappings},
        agent.name,
        agent.version,
    )
    actions = [
        AgentAction(
            name=action.action_type,
            tool=f"response.{action.action_type}",
            input=dict(action.parameters),
            risk_level="medium",
        )
        for action in state.proposed_actions
    ]
    finding = Finding(
        statement="; ".join(state.findings) or "investigation complete",
        evidence_ids=[evidence.id],
        confidence=float(getattr(state, "confidence", 0.5) or 0.5),
        mitre_techniques=list(state.mitre_mappings),
    )
    context.metadata.setdefault("execution_mode", "HEURISTIC")
    return AgentResult(
        status="success",
        findings=[finding],
        evidence=[evidence, *context.evidence],
        actions=actions,
        next_tasks=[NextTask(agent="threat-intel", objective="enrich_iocs", priority=1)],
        confidence=finding.confidence,
        reasoning="heuristic investigation adapter",
        uncertainty=[] if state.findings else ["investigation produced no findings"],
    )


class TriageRuntimeAgent(Agent):
    """LLM-backed triage with explicit heuristic fallback (Phase 8.6)."""

    name = "triage"
    version = "2.0"

    def __init__(self, tool_registry: SocToolRegistry) -> None:
        self._tools = tool_registry

    async def execute(self, context: AgentContext) -> AgentResult:
        if context.metadata.get("force_heuristic"):
            return await _heuristic_triage(self, context)
        if not is_llm_configured():
            context.metadata["execution_mode"] = "FALLBACK_HEURISTIC"
            return await _heuristic_triage(self, context)
        try:
            return await run_llm_triage(
                context,
                self._tools,
                agent_name=self.name,
                agent_version=self.version,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("triage.llm_failed_fallback", error=str(exc))
            context.metadata["execution_mode"] = "FALLBACK_HEURISTIC"
            context.metadata["llm_error"] = str(exc)
            return await _heuristic_triage(self, context)


class InvestigationRuntimeAgent(Agent):
    """LLM tool-using investigation with heuristic fallback (Phase 8.6)."""

    name = "investigation"
    version = "2.0"

    def __init__(self, tool_registry: SocToolRegistry) -> None:
        self._tools = tool_registry

    async def execute(self, context: AgentContext) -> AgentResult:
        if context.metadata.get("force_heuristic"):
            return await _heuristic_investigation(self, context)
        if not is_llm_configured():
            context.metadata["execution_mode"] = "FALLBACK_HEURISTIC"
            return await _heuristic_investigation(self, context)
        try:
            return await run_llm_investigation(
                context,
                self._tools,
                agent_name=self.name,
                agent_version=self.version,
            )
        except InvestigationStructuredOutputError as exc:
            logger.warning(
                "investigation.structured_output_fallback",
                reason=exc.reason,
                detail=str(exc.detail or "")[:200],
            )
            context.metadata["execution_mode"] = "FALLBACK_HEURISTIC"
            context.metadata["fallback_reason"] = exc.reason
            context.metadata["llm_error"] = exc.reason
            if exc.meta is not None:
                exc.meta.fallback = True
                exc.meta.execution_mode = "FALLBACK_HEURISTIC"
                context.metadata["investigation_execution"] = exc.meta.as_dict()
            return await _heuristic_investigation(self, context)
        except Exception as exc:  # noqa: BLE001
            logger.warning("investigation.llm_failed_fallback", error=str(exc))
            context.metadata["execution_mode"] = "FALLBACK_HEURISTIC"
            context.metadata["llm_error"] = str(exc)
            return await _heuristic_investigation(self, context)


class ThreatIntelRuntimeAgent(Agent):
    name = "threat-intel"
    version = "1.0"

    async def execute(self, context: AgentContext) -> AgentResult:
        from app.investigator.tools import enrich_ioc, extract_iocs

        blob = context.objective + " " + str(context.state.raw_alert)
        iocs = extract_iocs(blob)
        evidence_items: list[Evidence] = []
        for ioc in iocs[: context.constraints.max_tool_calls]:
            ioc_type = str(ioc.get("type") or "ip")
            value = str(ioc.get("value") or "")
            if not value:
                continue
            result = await enrich_ioc(value, ioc_type)
            evidence_items.append(
                _evidence_from_state(
                    context,
                    "ti.lookup",
                    {"ioc": value, "type": ioc_type, "result": result},
                    self.name,
                    self.version,
                )
            )
        uncertainty = ["no IOCs extracted"] if not evidence_items else []
        return AgentResult(
            status="success",
            findings=[
                Finding(
                    statement=f"enriched {len(evidence_items)} IOC(s)",
                    evidence_ids=[item.id for item in evidence_items],
                    confidence=0.5 if evidence_items else 0.1,
                )
            ],
            evidence=evidence_items,
            next_tasks=[NextTask(agent="correlation", objective="correlate", priority=1)],
            confidence=0.5 if evidence_items else 0.1,
            reasoning="threat-intel adapter over enrich_ioc",
            uncertainty=uncertainty,
        )


class CorrelationRuntimeAgent(Agent):
    """Deterministic entity correlation over evidence already in context — no LLM."""

    name = "correlation"
    version = "1.0"

    async def execute(self, context: AgentContext) -> AgentResult:
        entities: dict[str, int] = {}
        for item in context.evidence:
            key = str(item.data.get("ioc") or item.data.get("host") or item.source)
            entities[key] = entities.get(key, 0) + 1
        related = {key: count for key, count in entities.items() if count > 1}
        evidence = _evidence_from_state(
            context,
            "correlation",
            {"entity_counts": entities, "related": related},
            self.name,
            self.version,
        )
        finding = Finding(
            statement=f"correlated {len(related)} repeated entities across {len(context.evidence)} evidence items",
            evidence_ids=[evidence.id, *[item.id for item in context.evidence]],
            confidence=0.7 if related else 0.3,
        )
        return AgentResult(
            status="success",
            findings=[finding],
            evidence=[evidence, *context.evidence],
            next_tasks=[NextTask(agent="decision", objective="score_and_decide", priority=1)],
            confidence=finding.confidence,
            reasoning="deterministic entity co-occurrence",
            uncertainty=[] if context.evidence else ["no evidence to correlate"],
        )
