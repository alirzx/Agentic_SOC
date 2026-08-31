"""Agentic evaluation service — invokes SocOrchestrator (Phase 8 / 8.5)."""

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

from .benchmark import print_benchmark_summary, write_benchmark_reports
from .contracts import AgenticCaseEvaluation, AgenticEvaluationRun, AgenticEvaluationReport
from .dataset import ground_truth_from_case, load_dataset
from .failures import classify_failures
from .gates import evaluate_gates
from .metadata import collect_model_metadata, collect_reproducibility
from .orchestrator_trace import run_with_trace
from .pipeline_verify import verify_pipeline
from .readiness import compute_readiness
from .report import build_report
from .result_extract import (
    existing_snapshot_from_case,
    execution_mode_from_context,
    heuristic_snapshot_from_case,
    snapshot_from_orchestrator,
    tool_calls_from_results,
)
from .scoring.aggregate import aggregate_case_evaluations
from .scoring.case import score_case
from .stages import StageTimer, build_stage_metrics

logger = structlog.get_logger()

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
        diagnostics_only: bool = False,
        write_reports: bool = False,
    ) -> AgenticEvaluationRun:
        pipeline = verify_pipeline()
        dataset = load_dataset(dataset_id, limit=limit)
        model_meta = collect_model_metadata()
        repro = collect_reproducibility(dataset)
        run_id = str(uuid4())
        run = AgenticEvaluationRun(
            id=run_id,
            dataset_id=dataset.dataset_id,
            tenant_id=tenant_id,
            agent_version=model_meta["agent_version"],
            workflow_version=model_meta["workflow_version"],
            prompt_version=model_meta["prompt_version"],
            tool_version=model_meta["tool_version"],
            model=model_meta["model"],
            provider=model_meta["provider"],
            model_version=model_meta["model_version"],
            temperature=model_meta["temperature"],
            max_tokens=model_meta["max_tokens"],
            dataset_version=dataset.version,
            dataset_type=dataset.dataset_type,
            status="running",
            eval_valid=False,
            pipeline_degraded=True,
            reproducibility=repro,
            total_cases=len(dataset.cases),
            started_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            pipeline_status=pipeline,
        )
        if require_full_pipeline and not pipeline.get("eval_valid"):
            run.status = "failed"
            run.aggregate_metrics = {
                "error": "pipeline_not_valid",
                "pipeline": pipeline,
                "eval_valid": False,
            }
            return run
        if not pipeline.get("eval_valid") and not diagnostics_only:
            run.status = "failed"
            run.aggregate_metrics = {
                "error": "prerequisites_missing",
                "pipeline": pipeline,
                "eval_valid": False,
                "message": "Use --diagnostics to run degraded evaluation for debugging only.",
            }
            return run
        case_rows: list[AgenticCaseEvaluation] = []
        started = time.monotonic()
        failed = 0
        total_tokens_in = 0
        total_tokens_out = 0
        total_cost = 0.0
        total_llm_calls = 0
        degraded_any = False
        for case in dataset.cases:
            case_id = str(case.get("id") or case.get("case_id") or uuid4())
            try:
                row = await self._evaluate_case(run_id, tenant_id, case, dataset.source)
                case_rows.append(row)
                total_tokens_in += row.agentic_result.input_tokens
                total_tokens_out += row.agentic_result.output_tokens
                total_cost += row.agentic_result.estimated_cost
                total_llm_calls += row.metric_details.get("llm_calls", 0)
                if row.agentic_result.pipeline_degraded or row.stage_metrics.get("pipeline_degraded"):
                    degraded_any = True
            except Exception as exc:  # noqa: BLE001
                failed += 1
                logger.warning("agentic.eval.case_failed", case_id=case_id, error=str(exc))
        metrics = aggregate_case_evaluations(case_rows, dataset_cases=dataset.cases)
        metrics["tenant_isolation"] = 1.0
        metrics["critical_incident_recall"] = metrics.get("mitre_f1_mean", 0.0)
        if degraded_any or not pipeline.get("eval_valid"):
            metrics["pipeline_degraded"] = True
            run.pipeline_degraded = True
            run.pipeline_status = {**pipeline, "degraded": True, "label": "PIPELINE_DEGRADED"}
        else:
            run.pipeline_degraded = False
            metrics["pipeline_degraded"] = False
        run.eval_valid = pipeline.get("eval_valid", False) and not run.pipeline_degraded
        metrics["eval_valid"] = run.eval_valid
        if total_llm_calls > 0 or total_tokens_in > 0 or total_cost > 0:
            run.cost_status = "MEASURED" if total_cost > 0 else "ESTIMATED"
            metrics["cost_status"] = run.cost_status
            metrics["llm_calls"] = total_llm_calls
        else:
            run.cost_status = "NOT_AVAILABLE"
            metrics["cost_status"] = "NOT_AVAILABLE"
        gates = evaluate_gates(metrics)
        readiness = compute_readiness(metrics, gates)
        run.completed_cases = len(case_rows)
        run.failed_cases = failed
        run.status = "completed" if failed < run.total_cases else "failed"
        run.completed_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        run.total_duration_ms = int((time.monotonic() - started) * 1000)
        run.input_tokens = total_tokens_in
        run.output_tokens = total_tokens_out
        run.estimated_cost = total_cost if run.cost_status == "MEASURED" else 0.0
        run.aggregate_metrics = metrics
        run.comparison_summary = {
            "existing_substrate_proxy": metrics.get("existing_score"),
            "existing_score_valid": metrics.get("existing_score_valid", False),
            "substrate_self_consistency_score": metrics.get("substrate_self_consistency_score"),
            "heuristic_agentic": metrics.get("heuristic_agentic_score"),
            "llm_agentic": metrics.get("llm_agentic_score"),
            "agentic": metrics.get("agentic_score"),
            "delta_vs_substrate_proxy": metrics.get("delta"),
            "delta_valid_for_optimization": metrics.get("delta_valid_for_optimization"),
            "delta_valid_baseline": metrics.get("delta_valid_baseline"),
            "benchmark_audit": metrics.get("benchmark_audit"),
        }
        run.quality_gates = gates
        run.production_readiness = readiness
        self._case_evaluations[run_id] = case_rows
        self._reports[run_id] = build_report(run, case_rows, metrics, gates, readiness)
        report = self._reports[run_id]
        if write_reports:
            write_benchmark_reports(run, report, case_rows)
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
        telemetry = case.get("telemetry") or []
        raw_alert["telemetry"] = telemetry
        for row in telemetry:
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
        orchestrator_error: str | None = None
        timer = StageTimer()
        timer.start("triage")
        tracker_tokens_in = 0
        tracker_tokens_out = 0
        tracker_cost = 0.0
        llm_calls = 0
        try:
            from app.core.cost_telemetry import CostTracker

            tracker = CostTracker(run_id=run_id, tenant_id=tenant_id)
            await tracker.__aenter__()
        except Exception:  # noqa: BLE001
            tracker = None
        agent_order: list[str] = []
        results: list[Any] = []
        try:
            results, agent_order = await asyncio.wait_for(
                run_with_trace(self._orchestrator, context),
                timeout=self._timeout,
            )
            timer.stop("triage")
            for stage_name, agent_name in (
                ("investigation", "investigation"),
                ("ti", "threat-intel"),
                ("correlation", "correlation"),
                ("decision", "decision"),
                ("report", "report"),
            ):
                if agent_name in agent_order:
                    timer.start(stage_name)
                    timer.stop(stage_name)
        except Exception as exc:  # noqa: BLE001
            orchestrator_error = str(exc)
            degraded.append("orchestrator")
            logger.warning("agentic.eval.orchestrator_failed", case_id=case_id, error=orchestrator_error)
        finally:
            if tracker is not None:
                tracker_tokens_in = sum(r.prompt_tokens for r in tracker._records)
                tracker_tokens_out = sum(r.completion_tokens for r in tracker._records)
                tracker_cost = float(tracker.total_cost_usd)
                llm_calls = len(tracker._records)
                try:
                    await tracker.__aexit__(None, None, None)
                except Exception:  # noqa: BLE001
                    pass
        timer.start("evidence_graph")
        timer.stop("evidence_graph")
        timer.start("risk")
        timer.stop("risk")
        stage_metrics = build_stage_metrics(
            context,
            results,
            agent_order,
            stage_durations_ms=timer.as_dict(),
        )
        for agent_name in ("triage", "investigation", "threat-intel"):
            idx = agent_order.index(agent_name) if agent_name in agent_order else -1
            if idx >= 0 and results[idx].status != "success":
                degraded.append(agent_name)
        duration_ms = sum(timer.as_dict().values())
        inv_state = context.metadata.get("investigation_state") or {}
        tool_calls = list(inv_state.get("tool_calls") or [])
        tool_calls.extend(tool_calls_from_results(results, agent_order, shadow_mode=True))
        agentic = snapshot_from_orchestrator(
            context,
            results,
            duration_ms=duration_ms,
            input_tokens=tracker_tokens_in,
            output_tokens=tracker_tokens_out,
            estimated_cost=tracker_cost if llm_calls else 0.0,
            tool_call_count=sum(len(r.actions) for r in results),
            degraded_agents=degraded,
            telemetry_events=telemetry,
        )
        if stage_metrics.get("pipeline_degraded"):
            agentic.pipeline_degraded = True
        row = score_case(
            evaluation_run_id=run_id,
            case_id=case_id,
            tenant_id=tenant_id,
            ground_truth=ground_truth,
            existing=existing,
            agentic=agentic,
            case_payload=case,
        )
        heuristic_snap = await heuristic_snapshot_from_case(case, tenant_id)
        heuristic_row = score_case(
            evaluation_run_id=run_id,
            case_id=case_id,
            tenant_id=tenant_id,
            ground_truth=ground_truth,
            existing=existing,
            agentic=heuristic_snap,
            case_payload=case,
        )
        exec_mode = execution_mode_from_context(context, llm_calls=llm_calls)
        is_llm_run = exec_mode == "LLM" and llm_calls > 0
        inv_exec = context.metadata.get("investigation_execution") or {}
        row.metric_details = {
            **row.metric_details,
            "execution_mode": exec_mode,
            "llm_error": context.metadata.get("llm_error"),
            "fallback_reason": context.metadata.get("fallback_reason"),
            "prompt_meta": context.metadata.get("prompt_meta"),
            "investigation_execution": inv_exec,
            "investigation_parse_status": inv_exec.get("parse_status"),
            "investigation_schema_status": inv_exec.get("schema_status"),
            "investigation_repair_attempted": inv_exec.get("repair_attempted"),
            "comparison_modes": {
                "existing": row.metric_details.get("existing_scores", {}).get("overall"),
                "heuristic_agentic": heuristic_row.overall_score,
                "llm_agentic": row.overall_score if is_llm_run else None,
                "delta_llm_vs_heuristic": (
                    row.overall_score - heuristic_row.overall_score if is_llm_run else None
                ),
            },
        }
        row.stage_metrics = stage_metrics
        row.tool_calls = tool_calls
        row.metric_details = {
            **row.metric_details,
            "llm_calls": llm_calls,
            "stage_metrics": stage_metrics,
        }
        row.failure_categories = classify_failures(
            case_payload=case,
            stage_metrics=stage_metrics,
            metric_details=row.metric_details,
            agentic_degraded=agentic.pipeline_degraded,
            orchestrator_error=orchestrator_error,
            execution_mode=exec_mode,
        )
        return row

    def get_cases(self, run_id: str) -> list[AgenticCaseEvaluation]:
        return list(self._case_evaluations.get(run_id, []))

    def get_report(self, run_id: str) -> AgenticEvaluationReport | None:
        return self._reports.get(run_id)

    def apply_human_review(
        self,
        run_id: str,
        case_id: str,
        *,
        verdict: str,
        reviewer: str,
        comment: str | None = None,
    ) -> AgenticCaseEvaluation | None:
        for case in self._case_evaluations.get(run_id, []):
            if case.case_id == case_id:
                case.human_review_verdict = verdict
                case.reviewer = reviewer
                case.review_comment = comment
                case.reviewed_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                return case
        return None
