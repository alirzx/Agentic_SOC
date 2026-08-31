"""Bounded structured parsing + repair for Investigation LLM steps (Phase 8.6.2)."""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from app.llm import safe_ainvoke
from app.llm.provider_errors import classify_llm_exception, is_auth_failure, sanitize_error_message
from app.llm.structured_output import parse_structured
from app.prompting.envelope import system_rule

from .execution_errors import (
    InvestigationExecutionMeta,
    InvestigationStructuredOutputError,
    LLM_EMPTY_RESPONSE,
    SCHEMA_VALIDATION_ERROR,
    STRUCTURED_OUTPUT_PARSE_ERROR,
    STRUCTURED_OUTPUT_REPAIR_FAILED,
    StepExecutionRecord,
)
from .models import LlmStepResponse
from .prompts import INVESTIGATION_REPAIR_PROMPT, INVESTIGATION_SYSTEM_PROMPT

logger = structlog.get_logger()

_MAX_REPAIR_SNIPPET = 1200


def _validate_step(payload: dict[str, Any]) -> LlmStepResponse:
    return LlmStepResponse.model_validate(payload)


def _parse_step_text(text: str) -> tuple[LlmStepResponse | None, StepExecutionRecord]:
    record = StepExecutionRecord(attempt=0)
    if not str(text).strip():
        record.parse_status = "EMPTY"
        record.schema_status = "INVALID"
        record.error_code = LLM_EMPTY_RESPONSE
        record.error_detail = "empty response"
        return None, record
    result = parse_structured(text, validator=_validate_step)
    if result.ok:
        record.parse_status = "VALID"
        record.schema_status = "VALID"
        return result.value, record
    record.parse_status = "INVALID"
    record.schema_status = "INVALID"
    if "schema validation" in (result.error or ""):
        record.error_code = SCHEMA_VALIDATION_ERROR
    else:
        record.error_code = STRUCTURED_OUTPUT_PARSE_ERROR
    record.error_detail = sanitize_error_message(result.error or "parse failed")
    return None, record


async def invoke_investigation_step(
    llm: Any,
    *,
    nonce: str,
    user_content: str,
    attempt_index: int,
    exec_meta: InvestigationExecutionMeta,
) -> LlmStepResponse:
    """Call LLM once, parse step JSON, optionally one repair call. Fail fast on auth."""
    messages = [
        SystemMessage(content=INVESTIGATION_SYSTEM_PROMPT + "\n\n" + system_rule(nonce)),
        HumanMessage(content=user_content),
    ]
    try:
        response = await safe_ainvoke(llm, messages)
    except Exception as exc:  # noqa: BLE001
        classified = classify_llm_exception(exc)
        if is_auth_failure(classified):
            raise
        raise InvestigationStructuredOutputError(
            classified.category,
            detail=sanitize_error_message(str(exc)),
            meta=exec_meta,
        ) from exc
    exec_meta.llm_calls += 1
    content = str(getattr(response, "content", "") or "")
    step, record = _parse_step_text(content)
    record.attempt = attempt_index
    exec_meta.steps.append(record)
    if step is not None:
        exec_meta.parse_status = "VALID"
        exec_meta.schema_status = "VALID"
        return step

    # Bounded repair — exactly one additional LLM call
    exec_meta.repair_attempted = True
    snippet = sanitize_error_message(content[:_MAX_REPAIR_SNIPPET])
    repair_user = (
        f"{INVESTIGATION_REPAIR_PROMPT}\n\n"
        f"Validation error: {record.error_detail}\n\n"
        f"Previous invalid response (truncated):\n{snippet}"
    )
    repair_messages = [
        SystemMessage(content=INVESTIGATION_SYSTEM_PROMPT + "\n\n" + system_rule(nonce)),
        HumanMessage(content=repair_user),
    ]
    try:
        repair_response = await safe_ainvoke(llm, repair_messages)
    except Exception as exc:  # noqa: BLE001
        classified = classify_llm_exception(exc)
        if is_auth_failure(classified):
            raise
        raise InvestigationStructuredOutputError(
            classified.category,
            detail=sanitize_error_message(str(exc)),
            meta=exec_meta,
        ) from exc
    exec_meta.llm_calls += 1
    repair_content = str(getattr(repair_response, "content", "") or "")
    repaired_step, repair_record = _parse_step_text(repair_content)
    repair_record.attempt = attempt_index
    repair_record.repair_attempted = True
    exec_meta.steps.append(repair_record)
    if repaired_step is not None:
        exec_meta.parse_status = "VALID"
        exec_meta.schema_status = "VALID"
        return repaired_step

    exec_meta.parse_status = repair_record.parse_status
    exec_meta.schema_status = repair_record.schema_status
    exec_meta.fallback = True
    exec_meta.fallback_reason = STRUCTURED_OUTPUT_REPAIR_FAILED
    raise InvestigationStructuredOutputError(
        STRUCTURED_OUTPUT_REPAIR_FAILED,
        detail=repair_record.error_detail or record.error_detail,
        meta=exec_meta,
    )
