"""Tests for alert-scoped AI Investigation mapping helpers."""

from __future__ import annotations

from types import SimpleNamespace

from app.api.alert_investigate import (
    AlertInvestigateRequest,
    _build_summary,
    _findings_markdown,
    _map_actions,
    _map_recommendations,
    _resolve_alert_id,
)


def test_resolve_alert_id_prefers_camel_case() -> None:
    req = AlertInvestigateRequest(alertId="abc-123", alert_id="other")
    assert _resolve_alert_id(req) == "abc-123"


def test_build_summary_from_raw_alert() -> None:
    req = AlertInvestigateRequest(
        alertId="a1",
        raw_alert={"title": "Suspicious login", "severity": "high", "description": "MFA bypass"},
    )
    assert _build_summary(req, "a1") == "[high] Suspicious login — MFA bypass"


def test_map_recommendations_and_actions() -> None:
    responder = {
        "recommended_actions": [
            {"action": "Isolate host", "target": "ws-01", "rationale": "C2"},
            {"action": "Reset password", "target": "alice"},
        ],
        "containment_steps": ["Block egress IP"],
    }
    recs = _map_recommendations(responder)
    assert "Isolate host" in recs
    assert "Block egress IP" in recs
    actions = _map_actions(responder)
    assert actions[0].type == "Isolate host"
    assert actions[0].target == "ws-01"
    assert actions[0].status == "proposed"


def test_findings_prefers_report_md() -> None:
    state = SimpleNamespace(
        report_md="# Report\nConfirmed threat.",
        recon=SimpleNamespace(summary="recon", mitre_techniques=["T1078"]),
        forensic=SimpleNamespace(summary="forensic"),
    )
    assert _findings_markdown(state).startswith("# Report")
