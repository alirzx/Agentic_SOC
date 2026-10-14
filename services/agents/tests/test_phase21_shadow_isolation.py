"""Phase 2.1 — prove Shadow Mode cannot mutate production authority."""

from __future__ import annotations

import inspect

import pytest
from app.runtime import comparison, flags, shadow_service
from app.runtime.comparison import build_comparison
from app.runtime.flags import enabled, must_dry_run_tools, shadow_mode
from app.runtime.shadow_service import AgenticShadowService


def test_shadow_module_does_not_import_case_or_playbook_mutators():
    src = inspect.getsource(shadow_service)
    assert "promote_to_case" not in src
    assert "PlaybookEngine" not in src
    assert "tag_false_positive" not in src
    assert "record_business_context_suppression" not in src
    assert "funnel_stage" not in src


def test_agentic_soc_defaults_keep_production_untouched(monkeypatch):
    monkeypatch.delenv("AGENTIC_SOC_ENABLED", raising=False)
    monkeypatch.delenv("AGENTIC_SOC_SHADOW_MODE", raising=False)
    monkeypatch.delenv("AGENTIC_SOC_AUTO_RESPONSE", raising=False)
    assert enabled() is False
    assert must_dry_run_tools() is True


def test_enabled_without_auto_response_still_dry_run(monkeypatch):
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "1")
    monkeypatch.setenv("AGENTIC_SOC_SHADOW_MODE", "1")
    monkeypatch.setenv("AGENTIC_SOC_AUTO_RESPONSE", "0")
    assert enabled() is True
    assert shadow_mode() is True
    assert must_dry_run_tools() is True


def test_comparison_contract_forbids_side_effects():
    cmp = build_comparison(
        case_id="inc-1",
        existing={"disposition": "true_positive", "suppressed": False},
        agentic={"disposition": "false_positive", "suppressed": True, "riskScore": 10},
    )
    effects = cmp["shadowSideEffects"]
    assert effects == {
        "createsCase": False,
        "appliesSuppression": False,
        "executesPlaybook": False,
    }
    assert "production_candidate_shadow_benign" in cmp["differenceCategories"]["case_recommendation"]


@pytest.mark.asyncio
async def test_shadow_submit_noop_when_disabled(monkeypatch):
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "0")
    svc = AgenticShadowService()
    out = await svc.submit(
        {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "id": "22222222-2222-2222-2222-222222222222",
            "alert": {"id": "22222222-2222-2222-2222-222222222222", "title": "t", "severity": "high"},
        }
    )
    assert out is None


@pytest.mark.asyncio
async def test_shadow_exception_does_not_raise(monkeypatch):
    monkeypatch.setenv("AGENTIC_SOC_ENABLED", "1")
    monkeypatch.setenv("AGENTIC_SOC_SHADOW_MODE", "1")

    class _Boom:
        async def run(self, *_a, **_k):
            raise RuntimeError("shadow boom")

    svc = AgenticShadowService(orchestrator=_Boom())  # type: ignore[arg-type]
    # submit catches and returns None / failed record — must not raise to caller
    out = await svc.submit(
        {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "alert_row_id": "22222222-2222-2222-2222-222222222222",
            "alert": {"id": "22222222-2222-2222-2222-222222222222", "title": "t", "severity": "high"},
        }
    )
    # Either None (isolated_failure) or a failed record — never an exception.
    if out is not None:
        assert out.status in {"failed", "timeout", "completed", "running", "created"}
