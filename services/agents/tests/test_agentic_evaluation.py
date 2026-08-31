"""Phase 8 Agentic SOC evaluation tests — deterministic scoring."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

import asyncio
import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.runtime.audit import InMemoryAuditSink
from app.runtime.contracts import Agent, AgentContext, AgentResult, NextTask
from app.runtime.evaluation.dataset import load_dataset, load_golden_dataset, ground_truth_from_case
from app.runtime.evaluation.gates import evaluate_gates
from app.runtime.evaluation.pipeline_verify import verify_pipeline
from app.runtime.evaluation.regression import check_regression
from app.runtime.evaluation.scoring.actions import score_actions
from app.runtime.evaluation.scoring.classification import score_classification
from app.runtime.evaluation.scoring.correlation import score_correlation
from app.runtime.evaluation.scoring.evidence import score_evidence, score_hallucination
from app.runtime.evaluation.scoring.ioc import score_iocs
from app.runtime.evaluation.scoring.mitre import score_mitre
from app.runtime.evaluation.scoring.risk import mae, score_risk_distance
from app.runtime.evaluation.scoring.severity import score_severity
from app.runtime.evaluation.service import AgenticEvaluationService
from app.runtime.orchestrator import SocOrchestrator
from app.runtime.registry import AgentRegistry
from app.runtime.runtime import AgentRuntime

TENANT = "11111111-1111-1111-1111-111111111111"


class StubAgent(Agent):
    def __init__(self, name: str) -> None:
        self.name = name
        self.version = "1.0"

    async def execute(self, context: AgentContext) -> AgentResult:
        nxt = "report" if self.name == "decision" else "correlation"
        return AgentResult(
            status="success",
            next_tasks=[NextTask(agent=nxt, objective="write_report" if self.name == "decision" else "go")],
            reasoning=f"{self.name} correlated ldap activity",
            confidence=0.9,
        )


def _stub_orchestrator() -> SocOrchestrator:
    registry = AgentRegistry()
    for name in ("triage", "investigation", "threat-intel", "correlation", "decision", "response", "validation", "report"):
        registry.register(StubAgent(name))
    return SocOrchestrator(AgentRuntime(registry, audit=InMemoryAuditSink()), registry)


def test_dataset_creation() -> None:
    ds = load_golden_dataset()
    assert ds.dataset_id == "golden-benchmark-v1"
    assert len(ds.cases) >= 12
    assert all(c.get("source") == "SYNTHETIC" for c in ds.cases)


def test_classification_scoring() -> None:
    assert score_classification("isolate_host", "isolate_host") == 1.0
    assert score_classification("likely_compromise", "confirmed_compromise") == 0.5
    assert score_classification("benign", "critical") == 0.0


def test_severity_scoring() -> None:
    assert score_severity("critical", "critical") == 1.0
    assert score_severity("critical", "high") == 0.75
    assert score_severity("critical", "low") == 0.25


def test_risk_mae() -> None:
    assert mae([10, 20]) == 15.0
    assert score_risk_distance(90, 80) == 0.9


def test_mitre_f1() -> None:
    out = score_mitre(["T1003"], ["T1003"], [])
    assert out["f1"] == 1.0
    assert out["agentic_f1"] == 1.0


def test_ioc_f1() -> None:
    out = score_iocs(["10.0.0.1"], ["10.0.0.1"], [])
    assert out["f1"] == 1.0


def test_evidence_support() -> None:
    claims = [{"claim": "credential dumping occurred", "evidence_ids": ["e1"]}]
    evidence = [{"type": "auth", "source": "zeek", "data": {"detail": "credential dumping"}}]
    metrics = score_evidence(claims, evidence)
    assert metrics["evidence_support_rate"] >= 0.5


def test_hallucination_detection() -> None:
    claims = [{"claim": "totally unrelated quantum flux", "evidence_ids": []}]
    score = score_hallucination(claims, [])
    assert score < 1.0


def test_correlation_scoring() -> None:
    out = score_correlation(["a", "b", "c"], [["a", "b", "c"]])
    assert out["f1"] >= 0.9


def test_action_scoring_no_leakage() -> None:
    out = score_actions(["isolate_asset"], ["isolate_asset"], shadow_mode=True)
    assert out["production_action_leakage"] == 0.0
    assert out["dangerous_action_rate"] >= 0.0


@pytest.mark.asyncio
async def test_aggregate_metrics_and_versioning() -> None:
    svc = AgenticEvaluationService(orchestrator=_stub_orchestrator(), timeout=5.0)
    run = await svc.run_evaluation("golden", tenant_id=TENANT, limit=2, diagnostics_only=True)
    assert run.workflow_version == "agentic-eval-v1.6"
    assert run.agent_version
    assert run.dataset_version
    assert run.comparison_summary.get("delta") is not None
    assert run.aggregate_metrics.get("production_action_leakage") == 0.0


@pytest.mark.asyncio
async def test_evaluation_run_stub_pipeline() -> None:
    svc = AgenticEvaluationService(orchestrator=_stub_orchestrator(), timeout=5.0)
    run = await svc.run_evaluation("golden", tenant_id=TENANT, limit=1, diagnostics_only=True)
    assert run.status in {"completed", "failed"}
    cases = svc.get_cases(run.id)
    assert len(cases) == 1
    assert cases[0].overall_score >= 0.0


def test_tenant_isolation_in_memory_store() -> None:
    from app.runtime.evaluation.store import InMemoryEvaluationStore
    from app.runtime.evaluation.contracts import AgenticEvaluationRun

    store = InMemoryEvaluationStore()
    run = AgenticEvaluationRun(id=str(uuid4()), dataset_id="golden", tenant_id=TENANT, status="completed")
    store.save_run(run)
    other = store.list_runs(str(uuid4()))
    assert other == []
    assert len(store.list_runs(TENANT)) == 1


def test_regression_thresholds() -> None:
    metrics = {
        "evidence_support_rate": 0.95,
        "dangerous_action_rate": 0.0,
        "production_action_leakage": 0.0,
        "mitre_f1_mean": 0.8,
        "hallucination_rate": 0.01,
    }
    assert check_regression(metrics)["passed"] is True
    bad = dict(metrics)
    bad["dangerous_action_rate"] = 0.1
    assert check_regression(bad)["passed"] is False


def test_quality_gates() -> None:
    gates = evaluate_gates(
        {
            "evidence_support_rate": 0.96,
            "hallucination_rate": 0.01,
            "dangerous_action_rate": 0.0,
            "tenant_isolation": 1.0,
            "production_action_leakage": 0.0,
            "mitre_f1_mean": 0.96,
        }
    )
    assert gates["passed"] is True


def test_pipeline_verify_modules() -> None:
    status = verify_pipeline()
    assert "adapters" in status
    assert "dependencies" in status or "modules" in status
    assert "eval_valid" in status


def test_baseline_contamination_guard() -> None:
    from app.runtime.evaluation.regression import can_update_baseline, update_baseline

    assert can_update_baseline({"eval_valid": False, "pipeline_degraded": True}) is False
    result = update_baseline({"eval_valid": False, "pipeline_degraded": True})
    assert result["updated"] is False


def test_stage_metrics_present() -> None:
    from app.runtime.evaluation.stages import REQUIRED_STAGES

    assert len(REQUIRED_STAGES) == 8


def test_human_review() -> None:
    svc = AgenticEvaluationService(orchestrator=_stub_orchestrator(), timeout=5.0)
    run = asyncio.run(svc.run_evaluation("golden", tenant_id=TENANT, limit=1, diagnostics_only=True))
    cases = svc.get_cases(run.id)
    reviewed = svc.apply_human_review(
        run.id,
        cases[0].case_id,
        verdict="CORRECT",
        reviewer="analyst@test",
        comment="looks good",
    )
    assert reviewed is not None
    assert reviewed.human_review_verdict == "CORRECT"


def test_benchmark_leakage_on_synthetic_substrate() -> None:
    from app.runtime.evaluation.benchmark_audit import audit_case_leakage, audit_dataset
    from app.runtime.evaluation.dataset import load_synthetic_substrate
    from app.runtime.evaluation.result_extract import existing_snapshot_from_case
    from app.runtime.evaluation.scoring.case import score_case
    from app.runtime.evaluation.scoring.classification import score_classification
    from app.runtime.evaluation.scoring.severity import score_severity
    from app.runtime.evaluation.scoring.mitre import score_mitre

    dataset = load_synthetic_substrate(limit=20)
    audit = audit_dataset(dataset.cases)
    assert audit["leakage_rate"] >= 0.95
    assert audit["existing_score_valid"] is False
    assert audit["interpretation"] == "SUBSTRATE_SELF_CONSISTENCY_NOT_EXISTING_SOC"

    case = dataset.cases[0]
    gt = ground_truth_from_case(case)
    existing = existing_snapshot_from_case(case)
    assert score_classification(gt.classification, existing.classification) == 1.0
    assert score_severity(gt.severity, existing.severity) == 1.0
    mitre = score_mitre(gt.mitre_techniques, [], existing.mitre_techniques)
    assert mitre["existing_f1"] == 1.0
    assert audit_case_leakage(case)["leakage_detected"] is True


def test_zero_action_leakage_shadow() -> None:
    out = score_actions(
        ["block_ioc"],
        ["block_ip", "isolate_asset"],
        shadow_mode=True,
    )
    assert out["production_action_leakage"] == 0.0
