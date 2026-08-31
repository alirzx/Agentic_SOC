"""Tests for LLM gateway config, provider errors, and retry policy (Phase 8.6.1)."""

from __future__ import annotations

import pytest

from app.llm.gateway_config import (
    describe_api_key,
    normalize_openai_base_url,
    sanitize_base_url_for_log,
    validate_gateway_config,
)
from app.llm.provider_errors import (
    AuthenticationError,
    classify_llm_exception,
    failure_causes,
    is_auth_failure,
    is_retryable,
    ModelNotFoundError,
    PermissionError,
    ProviderUnavailableError,
    RateLimitError,
    sanitize_error_message,
    TimeoutError,
)


def test_normalize_openai_base_url_strips_chat_completions_suffix() -> None:
    assert normalize_openai_base_url("http://gw:4000/v1/chat/completions") == "http://gw:4000/v1"


def test_normalize_openai_base_url_trailing_slash() -> None:
    assert normalize_openai_base_url("http://gw:4000/v1/") == "http://gw:4000/v1"


def test_sanitize_base_url_redacts_long_token_segment() -> None:
    token = "yWeeAMwGFG5N84Xyrm4TAzZhwvPIHZpXOtDsvHM4q9NBxEOqa7MGWV8zAxJvWGZNPlGMJeiN0lMJBknqglSFGxIXm1GKlb9vw1"
    url = f"https://arvancloudai.ir/gateway/models/DeepSeek-V4-Flash/{token}/v1"
    sanitized = sanitize_base_url_for_log(url)
    assert token not in sanitized
    assert "DeepSeek-V4-Flash" in sanitized


def test_describe_api_key_never_returns_secret() -> None:
    info = describe_api_key("sk-live-secret-key-value")
    assert info["present"] is True
    assert info["length"] == len("sk-live-secret-key-value")
    assert info["prefix"] == "sk-l"
    assert "secret" not in str(info)


def test_classify_401_as_authentication_error() -> None:
    exc = Exception("Error code: 401 - {'error': 'Unauthorized', 'status': 401}")
    classified = classify_llm_exception(exc)
    assert isinstance(classified, AuthenticationError)
    assert classified.http_status == 401
    assert is_auth_failure(classified)
    assert not is_retryable(classified)


def test_classify_403_as_permission_error() -> None:
    exc = Exception("Error code: 403 - forbidden")
    classified = classify_llm_exception(exc)
    assert isinstance(classified, PermissionError)
    assert is_auth_failure(classified)


def test_classify_404_as_model_not_found() -> None:
    exc = Exception("status code: 404 model not found")
    classified = classify_llm_exception(exc)
    assert isinstance(classified, ModelNotFoundError)
    assert classified.category == "WRONG_MODEL_ENDPOINT"


def test_classify_429_as_rate_limit_retryable() -> None:
    exc = Exception("Error code: 429 - rate limit")
    classified = classify_llm_exception(exc)
    assert isinstance(classified, RateLimitError)
    assert is_retryable(classified)


def test_classify_500_as_provider_unavailable_retryable() -> None:
    exc = Exception("status code: 503 service unavailable")
    classified = classify_llm_exception(exc)
    assert isinstance(classified, ProviderUnavailableError)
    assert is_retryable(classified)


def test_classify_timeout_retryable() -> None:
    exc = TimeoutError("read timeout", category="TIMEOUT")
    assert is_retryable(exc)


def test_sanitize_error_message_redacts_bearer() -> None:
    text = sanitize_error_message("Authorization failed Bearer sk-super-secret-token")
    assert "sk-super-secret-token" not in text
    assert "Bearer ***" in text


def test_failure_causes_for_invalid_key() -> None:
    causes = failure_causes("INVALID_API_KEY")
    assert "invalid token" in causes


@pytest.mark.asyncio
async def test_triage_fail_fast_on_401(monkeypatch) -> None:
    from langchain_core.messages import AIMessage

    from app.runtime.contracts import AgentContext, IncidentStateSnapshot
    from app.runtime.llm_agents.triage import run_llm_triage

    calls = 0

    async def _boom(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AuthenticationError("unauthorized", category="INVALID_API_KEY", http_status=401)

    class _FakeLlm:
        model_name = "test-model"

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost/v1")
    monkeypatch.setattr("app.runtime.llm_agents.triage.make_chat_model", lambda *_a, **_k: _FakeLlm())
    monkeypatch.setattr("app.runtime.llm_agents.triage.safe_ainvoke", _boom)
    context = AgentContext(
        incident_id="c1",
        tenant_id="t1",
        objective="test alert",
        state=IncidentStateSnapshot(state="NEW", severity="high", raw_alert={"title": "test"}),
    )
    registry = type("Registry", (), {"names": lambda self: []})()
    with pytest.raises(AuthenticationError):
        await run_llm_triage(context, registry)
    assert calls == 1


@pytest.mark.asyncio
async def test_safe_ainvoke_records_cost_on_success(monkeypatch) -> None:
    from langchain_core.messages import AIMessage

    from app.core.cost_telemetry import CostTracker
    from app.llm.contract import safe_ainvoke

    class _FakeLlm:
        model_name = "gpt-test"

        async def ainvoke(self, messages, **kwargs):
            msg = AIMessage(content="OK")
            msg.usage_metadata = {"input_tokens": 3, "output_tokens": 1}
            return msg

    async with CostTracker(run_id="r1", tenant_id="t1") as tracker:
        await safe_ainvoke(_FakeLlm(), [{"role": "user", "content": "Return exactly: OK"}])
        assert tracker._records[-1].prompt_tokens == 3
        assert tracker._records[-1].completion_tokens == 1
        assert tracker.total_cost_usd > 0


def test_validate_gateway_config_missing_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    config = validate_gateway_config()
    assert config["api_key"]["present"] is False
    assert config["configuration_category"] == "CONFIGURATION_ERROR"
