"""SOC orchestrator core loop (spec §76 / §90). Does not replace LangGraph graphs."""

from __future__ import annotations

from .contracts import AgentContext, AgentResult, hash_payload
from .idempotency import IdempotencyStore
from .incident import IncidentState, IncidentStateMachine
from .registry import AgentRegistry
from .runtime import AgentRuntime


class SocOrchestrator:
    """Drive the spec state machine through versioned agents.

    Set ``context.metadata["skip_investigation"]`` to stay on the
    deterministic correlation → decision path (unit tests, air-gap).
    """

    def __init__(
        self,
        runtime: AgentRuntime,
        registry: AgentRegistry,
        idempotency: IdempotencyStore | None = None,
    ) -> None:
        self._runtime = runtime
        self._registry = registry
        self._idempotency = idempotency or IdempotencyStore()

    async def _run_agent(
        self,
        machine: IncidentStateMachine,
        context: AgentContext,
        agent_name: str,
    ) -> AgentResult:
        context.state.state = machine.state.value
        key = self._idempotency.key(
            tenant_id=context.tenant_id,
            incident_id=context.incident_id,
            agent=f"{agent_name}:{machine.state.value}",
            objective=context.objective,
        )
        if self._idempotency.seen(key):
            return AgentResult(status="success", reasoning="idempotent_replay", uncertainty=["replayed"])
        try:
            result = await self._runtime.run(agent_name, context)
        except Exception as exc:
            if not context.metadata.get("fail_soft"):
                raise
            result = AgentResult(
                status="failed",
                reasoning=f"{type(exc).__name__}: {exc}",
                uncertainty=["agent_exception"],
            )
        self._idempotency.remember(key, hash_payload(result.status))
        context.evidence = [*context.evidence, *result.evidence]
        context.previous_actions = [*context.previous_actions, *result.actions]
        context.iteration += 1
        return result

    async def run(self, context: AgentContext) -> list[AgentResult]:
        tracker = None
        owns_tracker = False
        try:
            from app.core.cost_telemetry import CostTracker, current_cost_tracker

            if current_cost_tracker() is None:
                tracker = CostTracker(
                    run_id=context.correlation_id or context.incident_id,
                    tenant_id=context.tenant_id,
                )
                await tracker.__aenter__()
                owns_tracker = True
        except Exception:  # noqa: BLE001
            tracker = None
            owns_tracker = False
        try:
            return await self._run_pipeline(context)
        finally:
            if tracker is not None and owns_tracker:
                try:
                    await tracker.__aexit__(None, None, None)
                except Exception:  # noqa: BLE001
                    pass

    async def _run_pipeline(self, context: AgentContext) -> list[AgentResult]:
        machine = IncidentStateMachine(IncidentState.NEW)
        results: list[AgentResult] = []
        machine.transition(IncidentState.TRIAGING, reason="orchestrator_start")
        results.append(await self._run_agent(machine, context, "triage"))
        machine.transition(IncidentState.INVESTIGATING, reason="after_triage")
        if not context.metadata.get("skip_investigation"):
            results.append(await self._run_agent(machine, context, "investigation"))
        skip_ti = context.metadata.get("skip_ti")
        if skip_ti is None:
            skip_ti = bool(context.metadata.get("skip_investigation"))
        if not skip_ti:
            results.append(await self._run_agent(machine, context, "threat-intel"))
        machine.transition(IncidentState.CORRELATING, reason="after_investigation")
        results.append(await self._run_agent(machine, context, "correlation"))
        machine.transition(IncidentState.RISK_ASSESSMENT, reason="after_correlation")
        machine.transition(IncidentState.DECISION, reason="after_risk")
        decision = await self._run_agent(machine, context, "decision")
        results.append(decision)
        shadow = bool(context.metadata.get("shadow_mode"))
        awaiting = any(task.objective == "await_approval" for task in decision.next_tasks)
        if awaiting and not shadow:
            machine.transition(IncidentState.WAITING_APPROVAL, reason="policy")
            context.state.state = machine.state.value
            return results
        wants_response = awaiting or any(task.agent == "response" for task in decision.next_tasks)
        if wants_response:
            machine.transition(IncidentState.RESPONDING, reason="approved_or_auto")
            response = await self._run_agent(machine, context, "response")
            results.append(response)
            if response.status == "blocked" and not shadow:
                machine.transition(IncidentState.WAITING_APPROVAL, reason="response_blocked")
                context.state.state = machine.state.value
                return results
            machine.transition(IncidentState.VALIDATING, reason="after_response")
            results.append(await self._run_agent(machine, context, "validation"))
        machine.transition(IncidentState.REPORTING, reason="after_decision")
        results.append(await self._run_agent(machine, context, "report"))
        machine.transition(IncidentState.RESOLVED, reason="pipeline_complete")
        context.state.state = machine.state.value
        return results
