#!/usr/bin/env python3
"""Canonical Agentic SOC evaluation runner (Phase 8.5).

Run from the Poetry environment for services/agents:

    cd services/agents
    poetry run python ../../scripts/run_agentic_eval.py

Or with pip-installed deps:

    python scripts/run_agentic_eval.py --dataset golden --limit 12

Exit codes:
    0  Evaluation completed and eval_valid=true
    1  Evaluation completed but PIPELINE_DEGRADED or gates failed
    2  Prerequisites missing (fail-fast unless --diagnostics)
    3  Import / dependency error
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_AGENTS_ROOT = _REPO_ROOT / "services" / "agents"
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_AGENTS_ROOT))

from scripts.load_repo_dotenv import load_repo_dotenv


async def _run(args: argparse.Namespace) -> int:
    from app.runtime.evaluation.benchmark import print_benchmark_summary
    from app.runtime.evaluation.pipeline_verify import verify_pipeline
    from app.runtime.evaluation.regression import check_regression, update_baseline
    from app.runtime.evaluation.service import AgenticEvaluationService

    pipeline = verify_pipeline()
    print("Pipeline verification:")
    print(f"  eval_valid: {pipeline.get('eval_valid')}")
    if not pipeline.get("eval_valid"):
        print("  Missing prerequisites detected.")
        for key in ("dependencies", "adapters", "ti", "evidence", "risk"):
            block = pipeline.get(key) or {}
            if not block.get("ok", True):
                print(f"  - {key}: {block}")
    if not pipeline.get("eval_valid") and not args.diagnostics:
        print("\nFAIL-FAST: prerequisites missing. Use --diagnostics for degraded run.")
        return 2
    svc = AgenticEvaluationService(timeout=args.timeout)
    run = await svc.run_evaluation(
        args.dataset,
        limit=args.limit,
        require_full_pipeline=args.require_full_pipeline,
        diagnostics_only=args.diagnostics,
        write_reports=True,
    )
    print_benchmark_summary(run)
    regression = check_regression(run.aggregate_metrics)
    if args.update_baseline:
        baseline_result = update_baseline(run.aggregate_metrics, run.pipeline_status)
        print(f"Baseline update: {baseline_result}")
    if not regression["passed"]:
        print(f"Regression check FAILED: {regression['regressions']}")
    if not run.eval_valid:
        return 1
    if not regression["passed"] and args.ci:
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Agentic SOC benchmark runner")
    parser.add_argument("--dataset", default="golden", help="golden | soc-benchmark-v1")
    parser.add_argument("--limit", type=int, default=None, help="Limit cases (1, 12, 200)")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-case timeout seconds")
    parser.add_argument("--diagnostics", action="store_true", help="Allow degraded pipeline run")
    parser.add_argument("--require-full-pipeline", action="store_true", help="Fail if pipeline invalid")
    parser.add_argument("--update-baseline", action="store_true", help="Update regression baseline if valid")
    parser.add_argument("--ci", action="store_true", help="Exit non-zero on regression")
    args = parser.parse_args()
    load_repo_dotenv()
    try:
        code = asyncio.run(_run(args))
    except ImportError as exc:
        print(f"Dependency error: {exc}", file=sys.stderr)
        print("Install agents deps: cd services/agents && poetry install", file=sys.stderr)
        sys.exit(3)
    sys.exit(code)


if __name__ == "__main__":
    main()
