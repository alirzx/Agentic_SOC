"""Phase 8.6.2 structured investigation parsing, repair, and grounding tests."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.core.cost_telemetry import CostTracker
from app.llm.provider_errors import AuthenticationError
from app.runtime.llm_agents.execution_errors import (
    InvestigationExecutionMeta,
    InvestigationStructuredOutputError,
    LLM_EMPTY_RESPONSE,
    STRUCTURED_OUTPUT_REPAIR_FAILED,
)
from app.runtime.llm_agents.models import Claim, InvestigationOutput, LlmStepResponse
from app.runtime.llm_agents.structured_step import _parse_step_text, invoke_investigation_step
from app.runtime.llm_agents.validation import ground_claims, is_valid_mitre_technique_id, validate_investigation_output
from app.runtime.llm_agents.tool_runner import parse_json_response


VALID_STEP = {
    "action": "conclude",
    "output": {
        "status": "completed",
        "claims": [{"claim": "brute force", "confidence": 0.8, "evidence_ids": ["ev-1"]}],
        "attack_chain": ["credential_access"],
        "open_questions": [],
        "uncertainties": [],
        "risk_signals": {},
    },
}


def test_valid_json_parse_and_schema() -> None:
    step, record = _parse_step_text(__import__("json").dumps(VALID_STEP))
    assert step is not None
    assert step.action == "conclude"
    assert record.parse_status == "VALID"
    assert record.schema_status == "VALID"


def test_markdown_json_parse() -> None:
    wrapped = "```json\n" + __import__("json").dumps(VALID_STEP) + "\n```"
    step, record = _parse_step_text(wrapped)
    assert step is not None
    assert record.parse_status == "VALID"


def test_invalid_schema_triggers_validation_error() -> None:
    bad = {"action": "not_a_valid_action"}
    step, record = _parse_step_text(__import__("json").dumps(bad))
    assert step is None
    assert record.schema_status == "INVALID"


def test_empty_response_classified() -> None:
    step, record = _parse_step_text("")
    assert step is None
    assert record.error_code == LLM_EMPTY_RESPONSE


@pytest.mark.asyncio
async def test_repair_succeeds(monkeypatch) -> None:
    exec_meta = InvestigationExecutionMeta()
    llm = MagicMock()
    bad = MagicMock(content="not json")
    good = MagicMock(content=__import__("json").dumps(VALID_STEP))
    monkeypatch.setattr(
        "app.runtime.llm_agents.structured_step.safe_ainvoke",
        AsyncMock(side_effect=[bad, good]),
    )
    step = await invoke_investigation_step(
        llm,
        nonce="nonce",
        user_content="test",
        attempt_index=1,
        exec_meta=exec_meta,
    )
    assert step.action == "conclude"
    assert exec_meta.repair_attempted is True
    assert exec_meta.llm_calls == 2
    assert exec_meta.parse_status == "VALID"


@pytest.mark.asyncio
async def test_repair_fails_raises_structured_error(monkeypatch) -> None:
    exec_meta = InvestigationExecutionMeta()
    llm = MagicMock()
    bad = MagicMock(content="not json")
    monkeypatch.setattr(
        "app.runtime.llm_agents.structured_step.safe_ainvoke",
        AsyncMock(side_effect=[bad, bad]),
    )
    with pytest.raises(InvestigationStructuredOutputError) as exc_info:
        await invoke_investigation_step(
            llm,
            nonce="nonce",
            user_content="test",
            attempt_index=1,
            exec_meta=exec_meta,
        )
    assert exc_info.value.reason == STRUCTURED_OUTPUT_REPAIR_FAILED
    assert exec_meta.llm_calls == 2


@pytest.mark.asyncio
async def test_auth_error_no_repair(monkeypatch) -> None:
    exec_meta = InvestigationExecutionMeta()
    llm = MagicMock()
    async def _auth_fail(*_a, **_k):
        raise AuthenticationError("401", category="INVALID_API_KEY", http_status=401)

    monkeypatch.setattr("app.runtime.llm_agents.structured_step.safe_ainvoke", _auth_fail)
    with pytest.raises(AuthenticationError):
        await invoke_investigation_step(
            llm,
            nonce="nonce",
            user_content="test",
            attempt_index=1,
            exec_meta=exec_meta,
        )
    assert exec_meta.llm_calls == 0
    assert exec_meta.repair_attempted is False


@pytest.mark.asyncio
async def test_cost_tracker_counts_initial_and_repair(monkeypatch) -> None:
    llm = MagicMock()
    bad = MagicMock(content="bad")
    good = MagicMock(content=__import__("json").dumps(VALID_STEP))
    good.usage_metadata = {"input_tokens": 5, "output_tokens": 2}
    bad.usage_metadata = {"input_tokens": 3, "output_tokens": 1}

    async def _fake_ainvoke(_llm, _messages, **_kwargs):
        from app.core.cost_telemetry import record_llm_call

        call = _fake_ainvoke.calls
        _fake_ainvoke.calls += 1
        resp = bad if call == 1 else good
        record_llm_call(resp, model="DeepSeek-V4-Flash", latency_ms=1.0)
        return resp

    _fake_ainvoke.calls = 0
    monkeypatch.setattr("app.runtime.llm_agents.structured_step.safe_ainvoke", _fake_ainvoke)
    exec_meta = InvestigationExecutionMeta()
    async with CostTracker(run_id="r1", tenant_id="t1") as tracker:
        await invoke_investigation_step(
            llm,
            nonce="nonce",
            user_content="test",
            attempt_index=1,
            exec_meta=exec_meta,
        )
        assert exec_meta.llm_calls == 2
        assert len(tracker._records) >= 1
        assert tracker.total_tokens > 0


def test_evidence_grounding_rejects_unknown_ids() -> None:
    claims = ground_claims(
        [Claim(claim="x", confidence=0.9, evidence_ids=["missing-id"])],
        {"known-id"},
    )
    assert claims[0].status == "unsupported"


def test_mitre_format_validation() -> None:
    assert is_valid_mitre_technique_id("T1059")
    assert is_valid_mitre_technique_id("T1059.003")
    assert not is_valid_mitre_technique_id("T99999")
    output = validate_investigation_output(
        InvestigationOutput(
            status="completed",
            attack_chain=["T99999", "credential_access", "TA0006"],
            claims=[],
        ),
        available_evidence_ids=set(),
    )
    assert "credential_access" in output.attack_chain
    assert "TA0006" in output.attack_chain


def test_parse_json_response_markdown() -> None:
    payload = parse_json_response("```json\n{\"a\": 1}\n```")
    assert payload["a"] == 1
