"""Load evaluation datasets (Phase 8)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contracts import EvaluationDataset, GroundTruth

_GOLDEN_ROOT = Path(__file__).resolve().parents[3] / "tests" / "evaluation" / "golden"
_EVAL_DATA = Path(__file__).resolve().parents[3] / "tests" / "eval_data" / "synthetic_incidents.json"


def ground_truth_from_case(case: dict[str, Any], source: str = "SYNTHETIC") -> GroundTruth:
    correlation = case.get("expected_correlation_group") or case.get("correlation_group") or []
    if not correlation and case.get("id"):
        correlation = [str(case["id"])]
    actions = case.get("expected_actions") or []
    if not actions and case.get("response_class"):
        actions = [str(case["response_class"])]
    return GroundTruth(
        classification=case.get("classification") or case.get("response_class") or "",
        severity=str(case.get("severity") or "medium"),
        risk_band=str(case.get("risk_band") or case.get("severity") or "medium").upper(),
        risk_score=float(case.get("risk_score") or 0) if case.get("risk_score") is not None else None,
        compromised=bool(case.get("compromised", True)),
        affected_assets=list(case.get("affected_assets") or []),
        affected_users=list(case.get("affected_users") or []),
        iocs=list(case.get("iocs") or []),
        mitre_techniques=list(case.get("expected_techniques") or case.get("mitre_techniques") or []),
        attack_stage=str(case.get("attack_stage") or ""),
        expected_correlation_group=list(correlation),
        expected_actions=list(actions),
        source=source,
        confidence=float(case.get("ground_truth_confidence") or 1.0),
        labels={"template_id": case.get("template_id"), "evidence_keywords": case.get("evidence_keywords")},
    )


def load_golden_dataset() -> EvaluationDataset:
    cases: list[dict[str, Any]] = []
    if _GOLDEN_ROOT.is_dir():
        for path in sorted(_GOLDEN_ROOT.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                payload.setdefault("source", "SYNTHETIC")
                cases.append(payload)
        for path in sorted(_GOLDEN_ROOT.glob("*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                if isinstance(payload, dict):
                    payload.setdefault("source", "SYNTHETIC")
                    cases.append(payload)
    return EvaluationDataset(
        dataset_id="golden-benchmark-v1",
        name="Agentic SOC Golden Benchmark",
        description="Representative synthetic incidents (explicitly SYNTHETIC).",
        source="SYNTHETIC",
        dataset_type="SYNTHETIC",
        version="1.0",
        cases=cases,
    )


def load_synthetic_substrate(limit: int | None = None) -> EvaluationDataset:
    raw = json.loads(_EVAL_DATA.read_text(encoding="utf-8"))
    items = raw[:limit] if limit else raw
    return EvaluationDataset(
        dataset_id="soc-benchmark-v1",
        name="Synthetic incidents substrate",
        description="200-case eval substrate from synthetic_incidents.json",
        source="existing_soc_substrate",
        dataset_type="SYNTHETIC",
        version="1.0",
        cases=items,
    )


def load_golden_siem_case() -> EvaluationDataset:
    path = _GOLDEN_ROOT / "siem_auth_probe.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.setdefault("source", "SYNTHETIC")
    return EvaluationDataset(
        dataset_id="golden-siem-v1",
        name="Golden SIEM Investigation Probe",
        description="Single case requiring Splunk SIEM evidence (SYNTHETIC labels).",
        source="SYNTHETIC",
        dataset_type="SYNTHETIC",
        version="1.0",
        cases=[payload],
    )


def load_dataset(dataset_id: str, limit: int | None = None) -> EvaluationDataset:
    if dataset_id in {"golden-siem", "golden-siem-v1", "siem-golden"}:
        return load_golden_siem_case()
    if dataset_id in {"golden-benchmark-v1", "golden"}:
        dataset = load_golden_dataset()
        if limit is not None:
            dataset.cases = dataset.cases[:limit]
        return dataset
    if dataset_id in {"soc-benchmark-v1", "synthetic"}:
        return load_synthetic_substrate(limit=limit)
    raise KeyError(f"Unknown dataset: {dataset_id}")
