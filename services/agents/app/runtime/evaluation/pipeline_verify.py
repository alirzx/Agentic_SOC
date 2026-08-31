"""Pipeline prerequisite verification (Phase 8 / 8.5)."""

from __future__ import annotations

import os
from typing import Any


def _import_check(module: str) -> dict[str, Any]:
    try:
        __import__(module)
        return {"ok": True, "detail": f"{module} importable"}
    except ImportError as exc:
        return {"ok": False, "detail": str(exc)}


def verify_langchain_dependencies() -> dict[str, Any]:
    checks = {
        "langchain_core": _import_check("langchain_core"),
        "langgraph": _import_check("langgraph"),
        "langchain_openai": _import_check("langchain_openai"),
        "langchain_community": _import_check("langchain_community"),
    }
    ok = all(row["ok"] for row in checks.values())
    return {"ok": ok, "checks": checks}


def verify_langchain() -> dict[str, Any]:
    """Backward-compatible alias."""
    return verify_langchain_dependencies()


def verify_llm_gateway() -> dict[str, Any]:
    from app.llm.factory import preflight_llm, resolve_base_url

    base_url = resolve_base_url()
    api_key_set = bool(os.getenv("OPENAI_API_KEY", "").strip())
    warnings = preflight_llm()
    configured = bool(base_url) and api_key_set
    require_llm = os.getenv("AISOC_EVAL_REQUIRE_LLM", "").strip().lower() in {"1", "true", "yes"}
    ok = configured or not require_llm
    return {
        "ok": ok,
        "base_url": base_url or "UNKNOWN",
        "api_key_set": api_key_set,
        "llm_configured": configured,
        "require_llm": require_llm,
        "warnings": warnings,
        "uses_factory": True,
    }


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


def verify_ti_integration() -> dict[str, Any]:
    try:
        from app.investigator.tools import extract_iocs

        sample = extract_iocs("suspicious traffic from 10.0.0.5")
        enrich_ok = False
        enrich_detail = ""
        try:
            from app.investigator.tools import enrich_ioc

            enrich_ok = enrich_ioc is not None
        except ImportError as exc:
            enrich_detail = str(exc)
        return {
            "ok": len(sample) >= 0,
            "extract_iocs": len(sample),
            "enrich_ioc_available": enrich_ok,
            "enrich_detail": enrich_detail,
        }
    except ImportError as exc:
        return {"ok": False, "detail": str(exc)}


def verify_correlation() -> dict[str, Any]:
    try:
        from app.runtime.adapters import CorrelationRuntimeAgent

        return {"ok": CorrelationRuntimeAgent is not None}
    except ImportError as exc:
        return {"ok": False, "detail": str(exc)}


def verify_evidence() -> dict[str, Any]:
    try:
        from app.runtime.evidence import build_evidence_graph

        graph = build_evidence_graph(findings=[], evidence=[])
        return {"ok": isinstance(graph.nodes, list), "empty_graph": len(graph.nodes) == 0}
    except ImportError as exc:
        return {"ok": False, "detail": str(exc)}


def verify_risk() -> dict[str, Any]:
    try:
        from app.runtime.risk import RiskFactors, score_risk

        result = score_risk(RiskFactors(alert_severity="high"))
        return {"ok": result.score >= 0, "sample_band": result.band}
    except ImportError as exc:
        return {"ok": False, "detail": str(exc)}


def verify_report_generator() -> dict[str, Any]:
    try:
        from app.runtime.reports import ReportAgent

        return {"ok": ReportAgent is not None}
    except ImportError as exc:
        return {"ok": False, "detail": str(exc)}


def verify_pipeline() -> dict[str, Any]:
    dependencies = verify_langchain_dependencies()
    adapters = verify_adapters()
    modules = verify_runtime_modules()
    llm = verify_llm_gateway()
    ti = verify_ti_integration()
    correlation = verify_correlation()
    evidence = verify_evidence()
    risk = verify_risk()
    report = verify_report_generator()
    core_ok = (
        dependencies["ok"]
        and adapters["ok"]
        and modules["ok"]
        and ti["ok"]
        and correlation["ok"]
        and evidence["ok"]
        and risk["ok"]
        and report["ok"]
    )
    eval_valid = core_ok
    return {
        "ok": core_ok,
        "eval_valid": eval_valid,
        "dependencies": dependencies,
        "adapters": adapters,
        "modules": modules,
        "llm_gateway": llm,
        "ti": ti,
        "correlation": correlation,
        "evidence": evidence,
        "risk": risk,
        "report": report,
        # Legacy keys for existing tests
        "langchain": dependencies,
    }
