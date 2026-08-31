"""Investigation / structured-output failure classification (Phase 8.6.2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

ParseStatus = Literal["VALID", "INVALID", "EMPTY"]
SchemaStatus = Literal["VALID", "INVALID", "NOT_ATTEMPTED"]

# Provider / infrastructure (do not trigger structured repair)
LLM_AUTH_FAILURE = "LLM_AUTH_FAILURE"
LLM_RATE_LIMIT = "LLM_RATE_LIMIT"
LLM_TIMEOUT = "LLM_TIMEOUT"
LLM_PROVIDER_ERROR = "LLM_PROVIDER_ERROR"
LLM_EMPTY_RESPONSE = "LLM_EMPTY_RESPONSE"

# Structured output pipeline
STRUCTURED_OUTPUT_PARSE_ERROR = "STRUCTURED_OUTPUT_PARSE_ERROR"
SCHEMA_VALIDATION_ERROR = "SCHEMA_VALIDATION_ERROR"
STRUCTURED_OUTPUT_REPAIR_FAILED = "STRUCTURED_OUTPUT_REPAIR_FAILED"

# Evidence / tools
NO_EVIDENCE = "NO_EVIDENCE"
TOOL_FAILURE = "TOOL_FAILURE"
TI_UNAVAILABLE = "TI_UNAVAILABLE"
SIEM_UNAVAILABLE = "SIEM_UNAVAILABLE"
EVIDENCE_GROUNDING_FAILURE = "EVIDENCE_GROUNDING_FAILURE"
MITRE_VALIDATION_FAILURE = "MITRE_VALIDATION_FAILURE"


@dataclass
class StepExecutionRecord:
    """Per-LLM-call observability for Investigation steps."""

    attempt: int
    parse_status: ParseStatus = "INVALID"
    schema_status: SchemaStatus = "NOT_ATTEMPTED"
    repair_attempted: bool = False
    error_code: str | None = None
    error_detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "parse_status": self.parse_status,
            "schema_status": self.schema_status,
            "repair_attempted": self.repair_attempted,
            "error_code": self.error_code,
            "error_detail": self.error_detail,
        }


@dataclass
class InvestigationExecutionMeta:
    """Aggregated Investigation LLM execution metadata."""

    agent: str = "investigation"
    execution_mode: str = "LLM"
    llm_calls: int = 0
    parse_status: ParseStatus = "INVALID"
    schema_status: SchemaStatus = "NOT_ATTEMPTED"
    repair_attempted: bool = False
    fallback: bool = False
    fallback_reason: str | None = None
    steps: list[StepExecutionRecord] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "execution_mode": self.execution_mode,
            "llm_calls": self.llm_calls,
            "parse_status": self.parse_status,
            "schema_status": self.schema_status,
            "repair_attempted": self.repair_attempted,
            "fallback": self.fallback,
            "fallback_reason": self.fallback_reason,
            "steps": [s.as_dict() for s in self.steps],
        }


class InvestigationStructuredOutputError(Exception):
    """Structured parse/validation failed after bounded repair — triggers controlled fallback."""

    def __init__(
        self,
        reason: str,
        *,
        detail: str | None = None,
        meta: InvestigationExecutionMeta | None = None,
    ) -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail
        self.meta = meta
