"""Pipeline prerequisite verification (Phase 8)."""

from __future__ import annotations

from typing import Any


def verify_langchain() -> dict[str, Any]:
    try:
        import langchain_core  # noqa: F401
        import langgraph  # noqa: F401

        return {"ok": True, "detail": "langchain_core and langgraph importable"}
    except ImportError as exc:
        return {"ok": False, "detail": str(exc)}


def verify_adapters() -> dict[str, Any]:
    checks: dict[str, bool] = {}
    try:
        from app.runtime.adapters import (
            CorrelationRuntimeAgent,
            InvestigationRuntimeAgent,
            ThreatIntelRuntimeAgent,
            TriageRuntimeAgent,
        )

        checks["triage_adapter"] = TriageRuntimeAgent is not None
        checks["investigation_adapter"] = InvestigationRuntimeAgent is not None
        checks["ti_adapter"] = ThreatIntelRuntimeAgent is not None
        checks["correlation_adapter"] = CorrelationRuntimeAgent is not None
    except ImportError as exc:
        return {"ok": False, "checks": checks, "detail": str(exc)}
    return {"ok": all(checks.values()), "checks": checks}


def verify_runtime_modules() -> dict[str, Any]:
    try:
        from app.runtime.decision import DecisionAgent
        from app.runtime.evidence import build_evidence_graph
        from app.runtime.reports import ReportAgent
        from app.runtime.risk import score_risk

        return {
            "ok": True,
            "checks": {
                "risk_engine": score_risk is not None,
                "evidence_graph": build_evidence_graph is not None,
                "decision_agent": DecisionAgent is not None,
                "report_agent": ReportAgent is not None,
            },
        }
    except ImportError as exc:
        return {"ok": False, "detail": str(exc)}


def verify_pipeline() -> dict[str, Any]:
    langchain = verify_langchain()
    adapters = verify_adapters()
    modules = verify_runtime_modules()
    ok = langchain["ok"] and adapters["ok"] and modules["ok"]
    return {
        "ok": ok,
        "langchain": langchain,
        "adapters": adapters,
        "modules": modules,
        "eval_valid": ok,
    }
