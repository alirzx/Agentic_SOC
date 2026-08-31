"""Unit tests for Phase 8.7 Splunk SIEM integration."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.integrations.splunk.client import SplunkClient
from app.integrations.splunk.config import SplunkConfig, load_splunk_config
from app.integrations.splunk.errors import (
    SplunkAuthenticationError,
    SplunkAuthorizationError,
    SplunkQueryValidationError,
    SplunkTimeoutError,
    SplunkUnavailableError,
)
from app.integrations.splunk.normalizer import normalize_splunk_event, normalize_splunk_results
from app.integrations.splunk.spl_policy import validate_spl_query
from app.integrations.splunk.tool import run_splunk_search
from app.runtime.contracts import AgentContext
from app.runtime.llm_agents.tool_runner import execute_registry_tool
from app.runtime.catalog import build_tool_registry


def _cfg(**overrides: object) -> SplunkConfig:
    base = {
        "enabled": True,
        "base_url": "https://splunk.test:8089",
        "username": "api",
        "password": "secret",
        "verify_ssl": False,
        "timeout_seconds": 5.0,
        "max_events_per_query": 100,
        "max_query_window_minutes": 60,
        "max_query_length": 2000,
        "poll_interval_seconds": 0.01,
        "max_poll_seconds": 1.0,
        "max_tool_calls_per_investigation": 5,
    }
    base.update(overrides)
    return SplunkConfig(**base)  # type: ignore[arg-type]


def test_config_missing_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPLUNK_ENABLED", "true")
    monkeypatch.setenv("SPLUNK_BASE_URL", "https://splunk.test:8089")
    monkeypatch.setenv("SPLUNK_USERNAME", "api")
    monkeypatch.setenv("SPLUNK_PASSWORD", "")
    cfg = load_splunk_config()
    assert cfg.password == ""


def test_validate_rejects_empty_query() -> None:
    with pytest.raises(SplunkQueryValidationError):
        validate_spl_query("", max_length=2000, max_window_minutes=60, earliest="-5m", latest="now", max_events=10, max_events_cap=100)


def test_validate_rejects_dangerous_spl() -> None:
    with pytest.raises(SplunkQueryValidationError):
        validate_spl_query("search index=* | delete", max_length=2000, max_window_minutes=60, earliest="-5m", latest="now", max_events=10, max_events_cap=100)


def test_validate_rejects_long_window() -> None:
    with pytest.raises(SplunkQueryValidationError):
        validate_spl_query("search index=*", max_length=2000, max_window_minutes=60, earliest="-90d", latest="now", max_events=10, max_events_cap=100)


def test_evidence_id_generation() -> None:
    event = normalize_splunk_event({"host": "srv1", "src_ip": "10.0.0.1"}, search_id="12345", event_index=2)
    assert event.evidence_id == "splunk:12345:2"
    assert event.host == "srv1"
    assert event.src_ip == "10.0.0.1"


def test_normalize_truncation_flag() -> None:
    rows = [{"host": f"h{i}"} for i in range(5)]
    events, truncated = normalize_splunk_results(rows, search_id="99", max_events=3)
    assert len(events) == 3
    assert truncated is True


@pytest.mark.asyncio
async def test_health_check_success() -> None:
    client = SplunkClient(_cfg())
    with patch.object(client, "_request", new=AsyncMock(return_value={"entry": [{"content": {"version": "9.0.0"}}]})):
        health = await client.health_check()
    assert health["status"] == "HEALTHY"


@pytest.mark.asyncio
async def test_auth_failure() -> None:
    client = SplunkClient(_cfg())
    with patch.object(
        client,
        "_request",
        new=AsyncMock(side_effect=SplunkAuthenticationError("Splunk authentication failed")),
    ):
        health = await client.health_check()
    assert health["status"] == "SPLUNK_AUTH_FAILURE"


@pytest.mark.asyncio
async def test_search_job_lifecycle() -> None:
    with patch("app.integrations.splunk.tool.load_splunk_config", return_value=_cfg()):
        with patch.object(
            SplunkClient,
            "search",
            new=AsyncMock(return_value=("job-1", [{"host": "ws1", "user": "alice"}], 42)),
        ):
            result = await run_splunk_search("index=security user=alice", earliest="-15m", max_events=10)
    assert result.status == "SUCCESS_WITH_RESULTS"
    assert result.event_count == 1
    assert result.events[0].evidence_id == "splunk:job-1:0"


@pytest.mark.asyncio
async def test_search_no_results() -> None:
    with patch("app.integrations.splunk.tool.load_splunk_config", return_value=_cfg()):
        with patch.object(SplunkClient, "search", new=AsyncMock(return_value=("job-2", [], 12))):
            result = await run_splunk_search("index=security missing=1", earliest="-5m")
    assert result.status == "SUCCESS_NO_RESULTS"
    assert result.event_count == 0


@pytest.mark.asyncio
async def test_tool_call_budget() -> None:
    cfg = _cfg(max_tool_calls_per_investigation=1)
    with patch("app.integrations.splunk.tool.load_splunk_config", return_value=cfg):
        ctx = AgentContext(incident_id="inc-1", tenant_id="t-1", objective="", metadata={"splunk_tool_calls": 1})
        result = await run_splunk_search("index=*", context=ctx)
    assert result.status == "SPLUNK_QUERY_REJECTED"


@pytest.mark.asyncio
async def test_registry_splunk_tool_evidence() -> None:
    registry = build_tool_registry()
    ctx = AgentContext(incident_id="inc-1", tenant_id="t-1", objective="")
    with patch("app.integrations.splunk.tool.load_splunk_config", return_value=_cfg()):
        with patch.object(
            SplunkClient,
            "search",
            new=AsyncMock(return_value=("job-3", [{"host": "db1"}], 20)),
        ):
            result, evidence = await execute_registry_tool(
                registry,
                ctx,
                agent_name="investigation",
                agent_version="2.0",
                tool_name="splunk_search",
                arguments={"query": "index=main", "earliest": "-5m"},
                tool_call_count=1,
            )
    assert result["status"] == "SUCCESS_WITH_RESULTS"
    assert isinstance(evidence, list)
    assert evidence[0].id == "splunk:job-3:0"
    assert evidence[0].source == "splunk"


def test_fabricated_evidence_id_rejected() -> None:
    from app.runtime.llm_agents.models import Claim, InvestigationOutput
    from app.runtime.llm_agents.validation import validate_investigation_output

    output = InvestigationOutput(
        claims=[Claim(claim="Fake splunk reference", confidence=0.9, evidence_ids=["splunk:fake-sid:999"])],
    )
    validated = validate_investigation_output(output, available_evidence_ids={"splunk:real:0"})
    assert validated.claims[0].status == "unsupported"


@pytest.mark.asyncio
async def test_auth_failure_via_search() -> None:
    with patch("app.integrations.splunk.tool.load_splunk_config", return_value=_cfg()):
        with patch.object(
            SplunkClient,
            "search",
            new=AsyncMock(side_effect=SplunkAuthenticationError("auth failed")),
        ):
            result = await run_splunk_search("index=main", earliest="-5m")
    assert result.status == "SPLUNK_AUTH_FAILURE"


@pytest.mark.asyncio
async def test_authorization_failure() -> None:
    with patch("app.integrations.splunk.tool.load_splunk_config", return_value=_cfg()):
        with patch.object(
            SplunkClient,
            "search",
            new=AsyncMock(side_effect=SplunkAuthorizationError("forbidden")),
        ):
            result = await run_splunk_search("index=main", earliest="-5m")
    assert result.status == "SPLUNK_AUTHORIZATION_FAILURE"


@pytest.mark.asyncio
async def test_timeout_failure() -> None:
    with patch("app.integrations.splunk.tool.load_splunk_config", return_value=_cfg()):
        with patch.object(
            SplunkClient,
            "search",
            new=AsyncMock(side_effect=SplunkTimeoutError("poll timed out")),
        ):
            result = await run_splunk_search("index=main", earliest="-5m")
    assert result.status == "SPLUNK_TIMEOUT"


@pytest.mark.asyncio
async def test_network_failure() -> None:
    with patch("app.integrations.splunk.tool.load_splunk_config", return_value=_cfg()):
        with patch.object(
            SplunkClient,
            "search",
            new=AsyncMock(side_effect=SplunkUnavailableError("connection refused")),
        ):
            result = await run_splunk_search("index=main", earliest="-5m")
    assert result.status == "SPLUNK_UNAVAILABLE"


@pytest.mark.asyncio
async def test_query_rejected_skips_network() -> None:
    with patch("app.integrations.splunk.tool.load_splunk_config", return_value=_cfg()):
        with patch.object(SplunkClient, "search", new=AsyncMock()) as mock_search:
            result = await run_splunk_search("index=* | delete", earliest="-5m")
    mock_search.assert_not_called()
    assert result.status == "SPLUNK_QUERY_REJECTED"
