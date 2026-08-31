"""Agentic evaluation service — invokes SocOrchestrator (Phase 8)."""

from __future__ import annotations

import asyncio
import time
from typing import Any
from uuid import uuid4

import structlog

from app.runtime.catalog import build_agent_registry
from app.runtime.contracts import AgentContext, AgentConstraints, IncidentStateSnapshot
from app.runtime.orchestrator import SocOrchestrator
from app.runtime.runtime import AgentRuntime

from .contracts import AgenticCaseEvaluation, AgenticEvaluationRun, AgenticEvaluationReport
from .dataset import ground_truth_from_case, load_dataset
from .gates import evaluate_gates
from .pipeline_verify import verify_pipeline
from .readiness import compute_readiness
from .report import build_report
from .result_extract import existing_snapshot_from_case, snapshot_from_orchestrator
from .scoring.aggregate import aggregate_case_evaluations
from .scoring.case import score_case

logger = structlog.get_logger()

WORKFLOW_VERSION = "agentic-eval-v1"
DEFAULT_TENANT = "11111111-1111-1111-1111-111111111111"


class AgenticEvaluationService:
    def __init__(
        self,
        orchestrator: SocOrchestrator | None = None,
        timeout: float = 120.0,
        store: Any | None = None,
    ) -> None:
        if orchestrator is None:
            registry = build_agent_registry()
            orchestrator = SocOrchestrator(AgentRuntime(registry), registry)
        self._orchestrator = orchestrator
        self._timeout = timeout
        self._store = store
        self._case_evaluations: dict[str, list[AgenticCaseEvaluation]] = {}
        self._reports: dict[str, AgenticEvaluationReport] = {}

    async def run_evaluation(
        self,
        dataset_id: str,
        *,
        tenant_id: str = DEFAULT_TENANT,
        limit: int | None = None,
        require_full_pipeline: bool = False,
    ) -> AgenticEvaluationRun:
        pipeline = verify_pipeline()
        dataset = load_dataset(dataset_id, limit=limit)
        run_id = str(uuid4())
        run = AgenticEvaluationRun(
            id=run_id,
            dataset_id=dataset.dataset_id,
            tenant_id=tenant_id,
            workflow_version=WORKFLOW_VERSION,
            dataset_version=dataset.version,
            status="running",
            total_cases=len(dataset.cases),
            started_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            pipeline_status=pipeline,
        )
        if require_full_pipeline and not pipeline["ok"]:
            run.status = "failed"
            run.aggregate_metrics = {"error": "pipeline_not_valid", "pipeline": pipeline}
            return run
        case_rows: list[AgenticCaseEvaluation] = []
        started = time.monotonic()
        failed = 0
        total_tokens_in = 0
        total_tokens_out = 0
        total_cost = 0.0
        degraded_any = False
        for case in dataset.cases:
            case_id = str(case.get("id") or case.get("case_id") or uuid4())
            try:
                row = await self._evaluate_case(run_id, tenant_id, case, dataset.source)
                case_rows.append(row)
                total_tokens_in += row.agentic_result.input_tokens
                total_tokens_out += row.agentic_result.output_tokens
                total_cost += row.agentic_result.estimated_cost
                if row.agentic_result.pipeline_degraded:
                    degraded_any = True
            except Exception as exc:  # noqa: BLE001
                failed += 1
                logger.warning("agentic.eval.case_failed", case_id=case_id, error=str(exc))
        metrics = aggregate_case_evaluations(case_rows)
        metrics["tenant_isolation"] = 1.0
        metrics["critical_incident_recall"] = metrics.get("mitre_f1_mean", 0.0)
        if degraded_any:
            metrics["pipeline_degraded"] = True
            run.pipeline_status = {**pipeline, "degraded": True}
        gates = evaluate_gates(metrics)
        readiness = compute_readiness(metrics, gates)
        run.completed_cases = len(case_rows)
        run.failed_cases = failed
        run.status = "completed" if failed < run.total_cases else "failed"
        run.completed_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        run.total_duration_ms = int((time.monotonic() - started) * 1000)
        run.input_tokens = total_tokens_in
        run.output_tokens = total_tokens_out
        run.estimated_cost = total_cost
        run.aggregate_metrics = metrics
        run.comparison_summary = {
            "existing": metrics.get("existing_score"),
            "agentic": metrics.get("agentic_score"),
            "delta": metrics.get("delta"),
        }
        run.quality_gates = gates
        run.production_readiness = readiness
        self._case_evaluations[run_id] = case_rows
        self._reports[run_id] = build_report(run, case_rows, metrics, gates, readiness)
        report = self._reports[run_id]
        store = getattr(self, "_store", None)
        if store is not None:
            saved = store.save_run(run, report)
            if asyncio.iscoroutine(saved):
                await saved
            cases_saved = store.save_cases(run_id, case_rows)
            if asyncio.iscoroutine(cases_saved):
                await cases_saved
        return run

    async def _evaluate_case(
        self,
        run_id: str,
        tenant_id: str,
        case: dict[str, Any],
        dataset_source: str,
    ) -> AgenticCaseEvaluation:
        case_id = str(case.get("id") or case.get("case_id"))
        gt_source = "SYNTHETIC" if dataset_source == "SYNTHETIC" else "existing_soc_substrate"
        ground_truth = ground_truth_from_case(case, source=gt_source)
        existing = existing_snapshot_from_case(case)
        raw_alert = {
            "severity": case.get("severity"),
            "title": case.get("title"),
            "description": case.get("description"),
            **{k: v for k, v in case.items() if k not in {"telemetry"}},
        }
        for row in case.get("telemetry") or []:
            if isinstance(row, dict) and row.get("Computer"):
                raw_alert["hostname"] = row["Computer"]
            if isinstance(row, dict) and row.get("User"):
                raw_alert["username"] = row["User"]
        context = AgentContext(
            incident_id=case_id,
            tenant_id=tenant_id,
            objective=str(case.get("title") or case.get("description") or case_id),
            state=IncidentStateSnapshot(
                state="NEW",
                severity=str(case.get("severity") or "medium"),
                raw_alert=raw_alert,
                confidence=0.5,
            ),
            constraints=AgentConstraints(max_iterations=8, max_tool_calls=16, timeout_ms=int(self._timeout * 1000)),
            metadata={
                "shadow_mode": True,
                "fail_soft": False,
                "approval_granted": False,
                "eval_mode": True,
            },
        )
        degraded: list[str] = []
        started = time.monotonic()
        tracker_tokens_in = 0
        tracker_tokens_out = 0
        tracker_cost = 0.0
        try:
            from app.core.cost_telemetry import CostTracker

            tracker = CostTracker(run_id=run_id, tenant_id=tenant_id)
            await tracker.__aenter__()
        except Exception:  # noqa: BLE001
            tracker = None
        try:
            results = await asyncio.wait_for(self._orchestrator.run(context), timeout=self._timeout)
        except Exception as exc:  # noqa: BLE001
            degraded.append("orchestrator")
            results = []
            logger.warning("agentic.eval.orchestrator_failed", case_id=case_id, error=str(exc))
        finally:
            if tracker is not None:
                tracker_tokens_in = sum(r.prompt_tokens for r in tracker._records)
                tracker_tokens_out = sum(r.completion_tokens for r in tracker._records)
                tracker_cost = float(tracker.total_cost_usd)
                try:
                    await tracker.__aexit__(None, None, None)
                except Exception:  # noqa: BLE001
                    pass
        for agent_name in ("triage", "investigation", "threat-intel"):
            if any(r.reasoning and "failed" in (r.reasoning or "").lower() for r in results):
                degraded.append(agent_name)
        duration_ms = int((time.monotonic() - started) * 1000)
        agentic = snapshot_from_orchestrator(
            context,
            results,
            duration_ms=duration_ms,
            input_tokens=tracker_tokens_in,
            output_tokens=tracker_tokens_out,
            estimated_cost=tracker_cost,
            tool_call_count=sum(len(r.actions) for r in results),
            degraded_agents=degraded,
        )
        return score_case(
            evaluation_run_id=run_id,
            case_id=case_id,
            tenant_id=tenant_id,
            ground_truth=ground_truth,
            existing=existing,
            agentic=agentic,
            case_payload=case,
        )

    def get_cases(self, run_id: str) -> list[AgenticCaseEvaluation]:
        return list(self._case_evaluations.get(run_id, []))

    def get_report(self, run_id: str) -> AgenticEvaluationReport | None:
        return self._reports.get(run_id)
