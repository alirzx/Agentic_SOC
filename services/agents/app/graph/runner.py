"""Shared, durable investigation-graph runner (issue #569).

Both the Kafka auto-triage worker and the manual investigations API run the
*same* orchestration through here, so escalated alerts flow through one
implementation instead of two divergent ones:

* the manual API runs the FULL graph (auto-triage → triage → enrichment →
  investigation → attack-path) via :func:`run_full_investigation`;
* the auto-triage worker, having already produced a governed verdict, runs the
  post-triage escalation subgraph via :func:`run_escalation`.

Every node transition is recorded to the Investigation Ledger (append-only,
``ON CONFLICT (run_id, seq) DO NOTHING``), so a restart mid-investigation
re-runs idempotently — it never loses or duplicates the run.

Phase 2: wall-clock, node-step, and token budgets are enforced in this runner
(not only documented in prompts). Exhaustion yields a controlled partial result
with ``needs_review`` — never an invented benign close.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field

import structlog

from app.agents.dispositions import NEEDS_REVIEW
from app.core.cost_telemetry import current_cost_tracker
from app.investigator import ledger as ledger_module
from app.models.state import AgentStatus, InvestigationState
from app.privacy.context import async_privacy_context

logger = structlog.get_logger()


@dataclass
class InvestigationBudget:
    """Resource envelope for one investigation (issue #569 + Phase 2)."""

    max_seconds: float = 120.0
    max_tokens: int = 20_000
    max_tool_calls: int = 8
    max_node_steps: int = 24
    # Mutable runtime counters (not part of frozen identity).
    tokens_used: int = 0
    tool_calls_used: int = 0
    node_steps_used: int = 0
    stop_reason: str | None = field(default=None, compare=False)

    def remaining_tokens(self) -> int:
        return max(0, self.max_tokens - self.tokens_used)

    def can_call_tool(self) -> bool:
        return self.tool_calls_used < self.max_tool_calls and self.stop_reason is None

    def can_step(self) -> bool:
        return self.node_steps_used < self.max_node_steps and self.stop_reason is None

    def record_tool_call(self) -> None:
        self.tool_calls_used += 1
        if self.tool_calls_used >= self.max_tool_calls:
            self.stop_reason = "tool_budget_exhausted"

    def record_node_step(self) -> None:
        self.node_steps_used += 1
        if self.node_steps_used >= self.max_node_steps:
            self.stop_reason = "node_step_budget_exhausted"

    def sync_tokens_from_tracker(self) -> None:
        tracker = current_cost_tracker()
        if tracker is None:
            return
        used = int(getattr(tracker, "total_tokens", 0) or 0)
        self.tokens_used = max(self.tokens_used, used)
        if self.tokens_used >= self.max_tokens:
            self.stop_reason = "token_budget_exhausted"


def default_budget() -> InvestigationBudget:
    return InvestigationBudget(
        max_seconds=float(os.getenv("AISOC_INVESTIGATION_MAX_SECONDS", "120")),
        max_tokens=int(os.getenv("AISOC_MAX_TOKENS_PER_ALERT", "20000")),
        max_tool_calls=int(os.getenv("AISOC_INVESTIGATION_MAX_TOOL_CALLS", "8")),
        max_node_steps=int(os.getenv("AISOC_INVESTIGATION_MAX_NODE_STEPS", "24")),
    )


# Contextvar-friendly budget for tools that check before calling out.
_active_budget: InvestigationBudget | None = None


def current_investigation_budget() -> InvestigationBudget | None:
    return _active_budget


def assert_tool_budget_allows(*, tool_name: str = "tool") -> None:
    """Raise ``BudgetExhausted`` if the active investigation cannot spend a tool call."""
    budget = _active_budget
    if budget is None:
        return
    budget.sync_tokens_from_tracker()
    if not budget.can_call_tool() or budget.stop_reason:
        raise BudgetExhausted(budget.stop_reason or f"tool budget blocked for {tool_name}")


class BudgetExhausted(RuntimeError):
    """Raised when an investigation budget forbids further spend."""


async def _run(
    graph,  # noqa: ANN001 — a compiled LangGraph
    state: InvestigationState,
    *,
    budget: InvestigationBudget | None,
    persist: bool,
    seq_start: int,
) -> InvestigationState:
    global _active_budget
    budget = budget or default_budget()
    _active_budget = budget
    tenant_ref = str(state.tenant_id)
    state_dict = state.to_dict()
    merged: dict = dict(state_dict)

    tenant_uuid = await ledger_module.resolve_tenant(tenant_ref) if persist else None
    if persist:
        await ledger_module.start_run(
            run_id=state.run_id,
            case_id=str(state.incident_id),
            tenant_ref=tenant_ref,
            alert_summary=state.alert_summary or "",
            raw_alert=state.raw_alert or {},
            model_used="graph:investigation",
        )

    seq = seq_start
    timed_out = False
    budget_stopped = False
    try:
        async with asyncio.timeout(budget.max_seconds):
            async with async_privacy_context(tenant_ref):
                async for step in graph.astream(state_dict):
                    if not isinstance(step, dict):
                        continue
                    for node, out in step.items():
                        seq += 1
                        if isinstance(out, dict):
                            merged.update(out)
                        if tenant_uuid is not None:
                            await ledger_module.record_event(
                                run_id=state.run_id,
                                tenant_id=tenant_uuid,
                                seq=seq,
                                kind="graph_step",
                                agent=str(node),
                                summary=f"graph node '{node}' completed",
                                payload={"node": str(node)},
                            )
    except TimeoutError:
        timed_out = True
        budget.stop_reason = budget.stop_reason or "wall_clock_timeout"
        logger.warning("investigation.budget_timeout", run_id=str(state.run_id), max_seconds=budget.max_seconds)
    finally:
        _active_budget = None

    try:
        result = InvestigationState.model_validate(merged)
    except Exception as exc:  # noqa: BLE001 — never let a mapping error lose the run
        logger.warning("investigation.state_rebuild_failed", run_id=str(state.run_id), error=str(exc))
        result = state

    if timed_out or budget_stopped or budget.stop_reason:
        reason = budget.stop_reason or ("wall_clock_timeout" if timed_out else "budget_exhausted")
        result.add_finding(
            f"Investigation incomplete due to budget limit ({reason}): "
            f"steps={budget.node_steps_used}/{budget.max_node_steps} "
            f"tools={budget.tool_calls_used}/{budget.max_tool_calls} "
            f"tokens≈{budget.tokens_used}/{budget.max_tokens}. "
            "Evidence collected so far is preserved; not a benign close."
        )
        if not result.verdict or result.verdict in {"benign", "false_positive", "benign_true_positive"}:
            # Never auto-close as noise solely because we ran out of budget.
            if result.verdict in {"benign", "false_positive", "benign_true_positive"}:
                result.add_finding(
                    f"Prior verdict={result.verdict} overridden to needs_review after budget exhaustion."
                )
            result.verdict = NEEDS_REVIEW
        if result.status is AgentStatus.COMPLETED:
            result.status = AgentStatus.RUNNING
        result.error = result.error or f"budget:{reason}"

    if persist:
        await ledger_module.complete_run(
            run_id=result.run_id,
            tenant_id=tenant_uuid or result.tenant_id,
            status="completed",
            error=result.error,
            iterations=result.iteration_count,
        )
    return result


async def run_full_investigation(
    state: InvestigationState,
    *,
    budget: InvestigationBudget | None = None,
    persist: bool = True,
) -> InvestigationState:
    """Run the FULL graph (auto-triage → … → attack-path). Manual API entry."""
    from app.graph.workflow import investigation_graph  # noqa: PLC0415 — avoid import cycle

    return await _run(investigation_graph, state, budget=budget, persist=persist, seq_start=0)


async def run_escalation(
    state: InvestigationState,
    *,
    budget: InvestigationBudget | None = None,
    persist: bool = True,
    seq_start: int = 1,
) -> InvestigationState:
    """Run the post-triage escalation subgraph (triage → … → attack-path).

    Used by the auto-triage worker after it has produced (and persisted) a
    governed verdict. ``seq_start`` defaults to 1 so the recorded graph steps
    follow the worker's ``triage_verdict`` event (seq 1) without colliding.
    """
    from app.graph.workflow import escalation_graph  # noqa: PLC0415 — avoid import cycle

    return await _run(escalation_graph, state, budget=budget, persist=persist, seq_start=seq_start)
