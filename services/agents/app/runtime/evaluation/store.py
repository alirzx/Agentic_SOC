"""Persist evaluation runs (Phase 8). Best-effort Postgres + in-memory."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from .contracts import AgenticCaseEvaluation, AgenticEvaluationReport, AgenticEvaluationRun


class InMemoryEvaluationStore:
    def __init__(self) -> None:
        self._runs: dict[str, AgenticEvaluationRun] = {}
        self._cases: dict[str, list[AgenticCaseEvaluation]] = {}

    def save_run(self, run: AgenticEvaluationRun, report: AgenticEvaluationReport | None = None) -> AgenticEvaluationRun:
        self._runs[run.id] = run
        if report is not None:
            run.aggregate_metrics = {**run.aggregate_metrics, "report_id": report.evaluation_run_id}
        return run

    def save_cases(self, run_id: str, cases: list[AgenticCaseEvaluation]) -> None:
        self._cases[run_id] = cases

    def get_run(self, run_id: str) -> AgenticEvaluationRun | None:
        return self._runs.get(run_id)

    def list_runs(self, tenant_id: str) -> list[AgenticEvaluationRun]:
        return [r for r in self._runs.values() if r.tenant_id == tenant_id]

    def get_cases(self, run_id: str) -> list[AgenticCaseEvaluation]:
        return list(self._cases.get(run_id, []))


class PostgresEvaluationStore(InMemoryEvaluationStore):
    async def save_run(self, run: AgenticEvaluationRun, report: AgenticEvaluationReport | None = None) -> AgenticEvaluationRun:
        record = super().save_run(run, report)
        try:
            from app.investigator import ledger as ledger_module
        except ImportError:
            return record
        pool = await ledger_module.get_pool()
        if pool is None:
            return record
        try:
            tenant_uuid = UUID(run.tenant_id)
        except ValueError:
            return record
        report_payload = report.model_dump(mode="json") if report else {}
        try:
            async with pool.acquire() as conn:
                await ledger_module._set_rls_context(conn, tenant_uuid)
                await conn.execute(
                    """
                    INSERT INTO agentic_evaluation_runs (
                        id, tenant_id, dataset_id, dataset_version,
                        agent_version, workflow_version, prompt_version, tool_version, model,
                        status, total_cases, completed_cases, failed_cases,
                        started_at, completed_at, total_duration_ms,
                        input_tokens, output_tokens, estimated_cost,
                        aggregate_metrics, comparison_summary, quality_gates,
                        production_readiness, pipeline_status, report, created_at
                    ) VALUES (
                        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
                        $20::jsonb,$21::jsonb,$22::jsonb,$23::jsonb,$24::jsonb,$25::jsonb,$26
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        status = EXCLUDED.status,
                        completed_cases = EXCLUDED.completed_cases,
                        failed_cases = EXCLUDED.failed_cases,
                        completed_at = EXCLUDED.completed_at,
                        total_duration_ms = EXCLUDED.total_duration_ms,
                        aggregate_metrics = EXCLUDED.aggregate_metrics,
                        comparison_summary = EXCLUDED.comparison_summary,
                        quality_gates = EXCLUDED.quality_gates,
                        production_readiness = EXCLUDED.production_readiness,
                        pipeline_status = EXCLUDED.pipeline_status,
                        report = EXCLUDED.report
                    """,
                    UUID(run.id),
                    tenant_uuid,
                    run.dataset_id,
                    run.dataset_version,
                    run.agent_version,
                    run.workflow_version,
                    run.prompt_version,
                    run.tool_version,
                    run.model,
                    run.status,
                    run.total_cases,
                    run.completed_cases,
                    run.failed_cases,
                    run.started_at,
                    run.completed_at,
                    run.total_duration_ms,
                    run.input_tokens,
                    run.output_tokens,
                    run.estimated_cost,
                    json.dumps(run.aggregate_metrics),
                    json.dumps(run.comparison_summary),
                    json.dumps(run.quality_gates),
                    json.dumps(run.production_readiness),
                    json.dumps(run.pipeline_status),
                    json.dumps(report_payload),
                    run.created_at,
                )
        except Exception:  # noqa: BLE001
            return record
        return record

    async def save_cases(self, run_id: str, cases: list[AgenticCaseEvaluation]) -> None:
        super().save_cases(run_id, cases)
        try:
            from app.investigator import ledger as ledger_module
        except ImportError:
            return
        pool = await ledger_module.get_pool()
        if pool is None or not cases:
            return
        try:
            tenant_uuid = UUID(cases[0].tenant_id)
        except ValueError:
            return
        try:
            async with pool.acquire() as conn:
                await ledger_module._set_rls_context(conn, tenant_uuid)
                for case in cases:
                    await conn.execute(
                        """
                        INSERT INTO agentic_case_evaluations (
                            evaluation_run_id, tenant_id, case_id,
                            existing_result, agentic_result, ground_truth,
                            classification_score, severity_score, risk_score_metric,
                            mitre_score, ioc_score, correlation_score,
                            evidence_score, investigation_score, hallucination_score,
                            action_score, overall_score, analyst_review_required,
                            metric_details, created_at
                        ) VALUES (
                            $1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,
                            $7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20
                        )
                        """,
                        UUID(run_id),
                        tenant_uuid,
                        case.case_id,
                        json.dumps(case.existing_result.model_dump(mode="json")),
                        json.dumps(case.agentic_result.model_dump(mode="json")),
                        json.dumps(case.ground_truth.model_dump(mode="json")),
                        case.classification_score,
                        case.severity_score,
                        case.risk_score_metric,
                        case.mitre_score,
                        case.ioc_score,
                        case.correlation_score,
                        case.evidence_score,
                        case.investigation_score,
                        case.hallucination_score,
                        case.action_score,
                        case.overall_score,
                        case.analyst_review_required,
                        json.dumps(case.metric_details),
                        case.created_at,
                    )
        except Exception:  # noqa: BLE001
            return
