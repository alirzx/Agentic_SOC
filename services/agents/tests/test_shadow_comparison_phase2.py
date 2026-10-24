"""Shadow comparison must never claim Case/playbook side effects."""

from __future__ import annotations

from app.runtime.comparison import build_comparison, existing_from_fused
from app.runtime.flags import enabled, shadow_mode


def test_shadow_side_effects_always_false():
    cmp = build_comparison(
        case_id="c1",
        existing={"disposition": "benign", "severity": "low"},
        agentic={"disposition": "true_positive", "severity": "high", "riskScore": 80},
    )
    assert cmp["shadowSideEffects"]["createsCase"] is False
    assert cmp["shadowSideEffects"]["appliesSuppression"] is False
    assert cmp["shadowSideEffects"]["executesPlaybook"] is False
    assert "production_benign_shadow_candidate" in cmp["differenceCategories"]["case_recommendation"]


def test_existing_from_fused_carries_disposition():
    msg = {
        "incident_id": "inc-1",
        "fusion_decision": "correlated",
        "confidence_score": 0.7,
        "alert": {"severity": "medium", "disposition": "needs_review", "hostname": "h1"},
    }
    existing = existing_from_fused(msg)
    assert existing["disposition"] == "needs_review"
    assert existing["correlated"] is True
    assert existing["incidentId"] == "inc-1"


def test_agentic_soc_defaults_disabled(monkeypatch):
    monkeypatch.delenv("AGENTIC_SOC_ENABLED", raising=False)
    assert enabled() is False
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "1")
    monkeypatch.delenv("AGENTIC_SOC_SHADOW_MODE", raising=False)
    assert shadow_mode() is True  # fail-safe: shadow when enabled
