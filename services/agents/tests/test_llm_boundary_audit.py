"""Safety regressions for payload-free LLM audit."""
from types import SimpleNamespace
from unittest.mock import MagicMock
from app.investigator.state import InvestigatorState
from app.llm import contract
from app.llm.human_trace import INTERNAL_INPUT, PROVIDER_INPUT, LOCAL_RESPONSE, human_trace_enabled


def test_sensitive_human_trace_blocked_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AISOC_LLM_HUMAN_TRACE_ENABLED", "1")
    assert not human_trace_enabled()


def test_sensitive_human_trace_blocked_with_required_privacy(monkeypatch):
    monkeypatch.setenv("AISOC_LLM_PRIVACY_REQUIRED", "1")
    monkeypatch.setenv("AISOC_LLM_HUMAN_TRACE_ENABLED", "1")
    assert not human_trace_enabled()


def test_boundary_audit_has_no_payload(monkeypatch):
    monkeypatch.setenv("AISOC_LLM_BOUNDARY_AUDIT_ENABLED", "1")
    monkeypatch.setenv("AISOC_LLM_HUMAN_TRACE_ENABLED", "0")
    logger = MagicMock()
    monkeypatch.setattr("app.llm.human_trace.boundary_logger", logger)
    gw = SimpleNamespace(is_remote=True, context_trace_id="a" * 16, policy_version="v1")
    marker = "synthetic-private-host.corp.example"
    for stage in (INTERNAL_INPUT, PROVIDER_INPUT, LOCAL_RESPONSE):
        contract._trace(stage, {"content": marker}, gateway=gw, model="synthetic-model", path="ainvoke")
    assert logger.info.call_count == 3
    for call in logger.info.call_args_list:
        assert call.args[0] == "llm.boundary.stage"
        assert marker not in str(call.kwargs)
        assert "payload" not in call.kwargs
        assert call.kwargs["context_trace_id"] == "a" * 16


def test_production_ledger_never_retains_prompt_or_response(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    state = InvestigatorState(case_id="synthetic")
    sample = "EXAMPLE\\alice at dc01.corp.example"
    digest = state.log_llm_prompt("ReconAgent", [{"role": "user", "content": sample}])
    state.log_llm_response("ReconAgent", sample, prompt_hash=digest)
    first, second = state.audit_log
    assert first.metadata["payload_logged"] is False
    assert second.metadata["payload_logged"] is False
    assert sample not in str(first.metadata)
    assert sample not in str(second.metadata)
