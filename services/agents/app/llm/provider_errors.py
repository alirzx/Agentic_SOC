"""Structured LLM provider errors and HTTP status classification (Phase 8.6.1)."""

from __future__ import annotations

import re
from typing import Any

_AUTH_FAILURE_CATEGORIES = frozenset(
    {
        "CONFIGURATION_ERROR",
        "INVALID_API_KEY",
        "EXPIRED_API_KEY",
        "WRONG_BASE_URL",
        "WRONG_AUTH_HEADER",
        "WRONG_MODEL_ENDPOINT",
        "PROVIDER_REJECTION",
    }
)

_RETRYABLE_CATEGORIES = frozenset(
    {
        "RATE_LIMIT",
        "PROVIDER_UNAVAILABLE",
        "TIMEOUT",
        "NETWORK",
    }
)

_STATUS_CODE_RE = re.compile(r"(?:error code|status code|status)\s*[:=]?\s*(\d{3})", re.IGNORECASE)


class LlmProviderError(Exception):
    """Base error for classified LLM gateway / provider failures."""

    def __init__(
        self,
        message: str,
        *,
        category: str = "PROVIDER_REJECTION",
        http_status: int | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.http_status = http_status
        self.cause = cause


class AuthenticationError(LlmProviderError):
    """401 or equivalent authentication failure."""


class PermissionError(LlmProviderError):
    """403 or equivalent authorization failure."""


class RateLimitError(LlmProviderError):
    """429 rate limit."""


class TimeoutError(LlmProviderError):
    """Request timed out."""


class ProviderUnavailableError(LlmProviderError):
    """5xx or upstream unavailable."""


class InvalidRequestError(LlmProviderError):
    """400-class invalid request (not auth)."""


class ModelNotFoundError(LlmProviderError):
    """404 model or endpoint not found."""


class InvalidResponseError(LlmProviderError):
    """Provider returned an unusable response body."""


def _status_from_message(message: str) -> int | None:
    match = _STATUS_CODE_RE.search(message)
    if match:
        return int(match.group(1))
    return None


def _status_from_exception(exc: Exception) -> int | None:
    for attr in ("status_code", "http_status", "status"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    if response is not None:
        code = getattr(response, "status_code", None)
        if isinstance(code, int):
            return code
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        status = body.get("status")
        if isinstance(status, int):
            return status
    return _status_from_message(str(exc))


def _auth_category(http_status: int, message: str) -> str:
    lowered = message.lower()
    if http_status == 404:
        return "WRONG_MODEL_ENDPOINT"
    if "expired" in lowered:
        return "EXPIRED_API_KEY"
    if "invalid" in lowered and "key" in lowered:
        return "INVALID_API_KEY"
    if "unauthorized" in lowered or http_status == 401:
        return "INVALID_API_KEY"
    if "forbidden" in lowered or http_status == 403:
        return "PROVIDER_REJECTION"
    return "INVALID_API_KEY"


def classify_llm_exception(exc: Exception) -> LlmProviderError:
    """Map a raw provider/client exception to a structured :class:`LlmProviderError`."""
    if isinstance(exc, LlmProviderError):
        return exc
    status = _status_from_exception(exc)
    message = str(exc).strip() or exc.__class__.__name__
    if status == 401:
        category = _auth_category(status, message)
        return AuthenticationError(
            message,
            category=category,
            http_status=status,
            cause=exc,
        )
    if status == 403:
        return PermissionError(
            message,
            category="PROVIDER_REJECTION",
            http_status=status,
            cause=exc,
        )
    if status == 404:
        return ModelNotFoundError(
            message,
            category="WRONG_MODEL_ENDPOINT",
            http_status=status,
            cause=exc,
        )
    if status == 429:
        return RateLimitError(message, category="RATE_LIMIT", http_status=status, cause=exc)
    if status is not None and 500 <= status <= 599:
        return ProviderUnavailableError(
            message,
            category="PROVIDER_UNAVAILABLE",
            http_status=status,
            cause=exc,
        )
    if status is not None and 400 <= status < 500:
        return InvalidRequestError(message, category="PROVIDER_REJECTION", http_status=status, cause=exc)
    lowered = message.lower()
    if "timeout" in lowered or exc.__class__.__name__.lower().endswith("timeouterror"):
        return TimeoutError(message, category="TIMEOUT", http_status=status, cause=exc)
    if any(token in lowered for token in ("connection", "network", "resolve", "getaddrinfo")):
        return ProviderUnavailableError(message, category="NETWORK", http_status=status, cause=exc)
    return LlmProviderError(message, category="PROVIDER_REJECTION", http_status=status, cause=exc)


def is_auth_failure(exc: Exception) -> bool:
    """True when credentials or endpoint auth contract is wrong — do not retry."""
    classified = classify_llm_exception(exc)
    if isinstance(classified, (AuthenticationError, PermissionError)):
        return True
    return classified.category in _AUTH_FAILURE_CATEGORIES


def is_retryable(exc: Exception) -> bool:
    """True for transient failures that merit a bounded retry."""
    classified = classify_llm_exception(exc)
    if is_auth_failure(classified):
        return False
    if isinstance(classified, (RateLimitError, ProviderUnavailableError, TimeoutError)):
        return True
    return classified.category in _RETRYABLE_CATEGORIES


def sanitize_error_message(message: str, *, api_key: str | None = None) -> str:
    """Strip secrets from provider error text for logs and diagnostics."""
    text = str(message)
    if api_key and len(api_key) > 4:
        text = text.replace(api_key, "***")
    text = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer ***", text, flags=re.IGNORECASE)
    text = re.sub(r"(api[_-]?key\s*[:=]\s*)['\"]?[A-Za-z0-9_\-]{8,}['\"]?", r"\1***", text, flags=re.IGNORECASE)
    return text[:500]


def failure_causes(category: str) -> list[str]:
    """Human-readable hints for operators."""
    mapping: dict[str, list[str]] = {
        "INVALID_API_KEY": [
            "invalid token",
            "incorrect OPENAI_API_KEY",
            "gateway token mismatch",
        ],
        "EXPIRED_API_KEY": ["expired token"],
        "WRONG_BASE_URL": ["incorrect gateway URL", "missing or duplicate /v1 path"],
        "WRONG_AUTH_HEADER": ["incorrect Authorization format", "Bearer token required"],
        "WRONG_MODEL_ENDPOINT": ["wrong API endpoint", "model not found on provider"],
        "PROVIDER_REJECTION": ["provider rejected the request"],
        "CONFIGURATION_ERROR": ["missing OPENAI_BASE_URL or OPENAI_API_KEY"],
    }
    return mapping.get(category, mapping["PROVIDER_REJECTION"])
