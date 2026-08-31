"""Benchmark report generation (Phase 8.5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import AgenticCaseEvaluation, AgenticEvaluationReport, AgenticEvaluationRun

_REPO_ROOT = Path(__file__).resolve().parents[5]
_REPORTS_DIR = _REPO_ROOT / "reports" / "agentic"


def write_benchmark_reports(
    run: AgenticEvaluationRun,
    report: AgenticEvaluationReport,
    cases: list[AgenticCaseEvaluation],
) -> tuple[Path, Path]:
    """Write JSON + Markdown benchmark reports under reports/agentic/."""
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = _REPORTS_DIR / f"evaluation-{run.id}.json"
    md_path = _REPORTS_DIR / f"evaluation-{run.id}.md"
    payload: dict[str, Any] = {
        "run": run.model_dump(mode="json"),
        "report": report.model_dump(mode="json"),
        "cases": [c.model_dump(mode="json") for c in cases],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(_format_markdown(run, report), encoding="utf-8")
    return json_path, md_path


def _format_markdown(run: AgenticEvaluationRun, report: AgenticEvaluationReport) -> str:
    metrics = run.aggregate_metrics or {}
    comparison = run.comparison_summary or {}
    pipeline = run.pipeline_status or {}
    valid = pipeline.get("eval_valid", False) and not metrics.get("pipeline_degraded")
    lines = [
        "# Agentic SOC Benchmark Report",
        "",
        f"**Run ID:** `{run.id}`",
        f"**Dataset:** {run.dataset_id} ({run.dataset_version})",
        f"**Pipeline Validity:** {'VALID' if valid else 'PIPELINE_DEGRADED'}",
        "",
        "## Model & Version",
        f"- Provider: {run.provider}",
        f"- Model: {run.model}",
        f"- Agent: {run.agent_version}",
        f"- Workflow: {run.workflow_version}",
        f"- Prompt: {run.prompt_version}",
        f"- Tool: {run.tool_version}",
        "",
        "## Cases",
        f"- Total: {run.total_cases}",
        f"- Completed: {run.completed_cases}",
        f"- Failed: {run.failed_cases}",
        "",
        "## Scores",
        f"- Existing SOC: {comparison.get('existing', 'N/A')}",
        f"- Agentic SOC: {comparison.get('agentic', 'N/A')}",
        f"- Delta: {comparison.get('delta', 'N/A')}",
        "",
        "## Metrics",
        f"- Evidence Support: {metrics.get('evidence_support_rate', 0):.2%}",
        f"- MITRE F1: {metrics.get('mitre_f1_mean', 0):.2%}",
        f"- IOC F1: {metrics.get('ioc_f1_mean', 0):.2%}",
        f"- Correlation F1: {metrics.get('correlation_f1_mean', 0):.2%}",
        f"- Unsupported Claims: {metrics.get('hallucination_rate', 0):.2%}",
        f"- Dangerous Actions: {metrics.get('dangerous_action_rate', 0)}",
        f"- Action Leakage: {metrics.get('production_action_leakage', 0)}",
        "",
        "## Cost & Latency",
        f"- Cost status: {metrics.get('cost_status', 'UNKNOWN')}",
        f"- Estimated cost: {run.estimated_cost}",
        f"- Avg latency ms: {metrics.get('avg_duration_ms', 0)}",
        "",
        "## Production Readiness",
        f"- Status: {run.production_readiness.get('status', 'UNKNOWN')}",
        "",
        "## Executive Summary",
        report.executive_summary,
        "",
        "## Limitations",
        *(f"- {item}" for item in report.limitations),
    ]
    return "\n".join(lines)


def print_benchmark_summary(run: AgenticEvaluationRun) -> None:
    metrics = run.aggregate_metrics or {}
    comparison = run.comparison_summary or {}
    pipeline = run.pipeline_status or {}
    valid = pipeline.get("eval_valid", False) and not metrics.get("pipeline_degraded")
    print("====================================")
    print("AGENTIC SOC BENCHMARK")
    print("====================================")
    print()
    print(f"Pipeline: {'VALID' if valid else 'PIPELINE_DEGRADED'}")
    print()
    print(f"Cases: {run.total_cases}")
    print()
    audit = comparison.get("benchmark_audit") or metrics.get("benchmark_audit") or {}
    existing_valid = comparison.get("existing_score_valid", metrics.get("existing_score_valid"))
    if existing_valid:
        print(f"Existing SOC Score: {comparison.get('existing_substrate_proxy', 'N/A')}")
    else:
        print(
            f"Substrate self-consistency (NOT Existing SOC): "
            f"{comparison.get('substrate_self_consistency_score', comparison.get('existing_substrate_proxy', 'N/A'))}"
        )
        print("  WARNING: existing_score_valid=false - do not use delta_vs_substrate for optimization")
    print(f"Heuristic Agentic: {comparison.get('heuristic_agentic', metrics.get('heuristic_agentic_score', 'N/A'))}")
    print(f"LLM Agentic: {comparison.get('llm_agentic', metrics.get('llm_agentic_score', 'N/A'))}")
    print(f"Agentic SOC Score: {comparison.get('agentic', 'N/A')}")
    delta_valid = comparison.get("delta_valid_for_optimization", metrics.get("delta_valid_for_optimization"))
    baseline = comparison.get("delta_valid_baseline", metrics.get("delta_valid_baseline", "?"))
    print(
        f"Delta (valid baseline={baseline}): "
        f"{f'{delta_valid:+.3f}' if isinstance(delta_valid, (int, float)) else delta_valid}"
    )
    if audit.get("leakage_rate", 0) >= 0.95:
        print(f"Benchmark audit: {audit.get('interpretation', 'LEAKAGE')}")
    print()
    print(f"Evidence Support: {metrics.get('evidence_support_rate', 0):.1%}")
    print(f"MITRE F1: {metrics.get('mitre_f1_mean', 0):.1%}")
    print(f"IOC F1: {metrics.get('ioc_f1_mean', 0):.1%}")
    print(f"Correlation F1: {metrics.get('correlation_f1_mean', 0):.1%}")
    print()
    print(f"Unsupported Claims: {metrics.get('hallucination_rate', 0):.1%}")
    print(f"Dangerous Actions: {metrics.get('dangerous_action_rate', 0)}")
    print(f"Action Leakage: {metrics.get('production_action_leakage', 0)}")
    print()
    cost_status = metrics.get("cost_status", "UNKNOWN")
    cost_display = (
        f"${run.estimated_cost:.4f}"
        if cost_status == "MEASURED" and run.estimated_cost
        else cost_status
    )
    print(f"Average Latency: {metrics.get('avg_duration_ms', 0)} ms")
    print(f"Average Cost: {cost_display}")
    print()
    readiness = run.production_readiness.get("status", "UNKNOWN")
    print(f"Readiness: {readiness}")
    print("====================================")
