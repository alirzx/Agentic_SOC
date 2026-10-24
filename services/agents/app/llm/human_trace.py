"""Explicit, operator-enabled payload tracing around the LLM privacy boundary.

HUMAN TRACE intentionally records tenant-sensitive application input when
enabled. It is strictly a controlled-debugging feature and is OFF by default.
Trace serialization is bounded, credential-scrubbed, and fail-open so logging
can never alter an LLM request or response.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from typing import Any

import structlog

logger = structlog.get_logger()

HUMAN_TRACE_ENABLED_ENV = "AISOC_LLM_HUMAN_TRACE_ENABLED"
HUMAN_TRACE_MAX_CHARS_ENV = "AISOC_LLM_HUMAN_TRACE_MAX_CHARS"
DEFAULT_HUMAN_TRACE_MAX_CHARS = 50_000

INTERNAL_INPUT = "INTERNAL_INPUT"
PROVIDER_INPUT = "PROVIDER_INPUT"
PROVIDER_RESPONSE = "PROVIDER_RESPONSE"
LOCAL_RESPONSE = "LOCAL_RESPONSE"

TRACE_EVENT_NAMES = {
    INTERNAL_INPUT: "llm.human_trace.internal_input",
    PROVIDER_INPUT: "llm.human_trace.provider_input",
    PROVIDER_RESPONSE: "llm.human_trace.provider_response",
    LOCAL_RESPONSE: "llm.human_trace.local_response",
}

_SENSITIVE_ENV_NAMES = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "LLM_API_KEY",
    "LITELLM_MASTER_KEY",
    "AISOC_PRIVACY_TOKEN_KEY",
    "AISOC_AGENTS_TENANT_SIGNING_KEY",
    "AISOC_CREDENTIAL_KEY",
)
_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "proxy_authorization",
        "api_key",
        "apikey",
        "access_key",
        "secret_access_key",
        "access_token",
        "refresh_token",
        "auth_token",
        "bearer_token",
        "token",
        "password",
        "passwd",
        "passphrase",
        "secret",
        "client_secret",
        "private_key",
        "privacy_token_key",
        "tenant_signing_key",
        "cache_key",
        "cache_namespace",
    }
)
_AUTHORIZATION_RE = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(?:bearer|basic)?\s*[^\s,;\"']+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_URL_RE = re.compile(r"(?i)https?://[^\s\"'<>]+")
_URL_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:api[_-]?key|access[_-]?token|token|key|secret|password|sig|signature)=)[^&#\s]+"
)
_LONG_URL_PATH_SEGMENT_RE = re.compile(r"(?<=/)[A-Za-z0-9_-]{24,}(?=/|[?#]|$)")


def human_trace_enabled() -> bool:
    """Return whether sensitive payload tracing is explicitly enabled."""
    return os.getenv(HUMAN_TRACE_ENABLED_ENV, "0").strip().lower() in {"1", "true", "yes", "on"}


def _max_chars() -> int:
    try:
        return max(1, int(os.getenv(HUMAN_TRACE_MAX_CHARS_ENV, str(DEFAULT_HUMAN_TRACE_MAX_CHARS))))
    except (TypeError, ValueError):
        return DEFAULT_HUMAN_TRACE_MAX_CHARS


def _normalise_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def _sensitive_key(value: Any) -> bool:
    key = _normalise_key(value)
    return key in _SENSITIVE_KEYS or key.endswith(
        ("_api_key", "_access_token", "_refresh_token", "_auth_token", "_secret", "_password")
    )


def _scrub_url(match: re.Match[str]) -> str:
    url = match.group(0)
    scheme, remainder = url.split("://", 1)
    boundary = re.search(r"[/?#]", remainder)
    authority = remainder[: boundary.start()] if boundary else remainder
    suffix = remainder[boundary.start() :] if boundary else ""
    if "@" in authority:
        authority = "[REDACTED_CREDENTIAL]@" + authority.rsplit("@", 1)[-1]
    suffix = _URL_QUERY_SECRET_RE.sub(r"\1[REDACTED_CREDENTIAL]", suffix)
    suffix = _LONG_URL_PATH_SEGMENT_RE.sub("[REDACTED_URL_CREDENTIAL]", suffix)
    return f"{scheme}://{authority}{suffix}"


def _scrub_text(value: str) -> str:
    scrubbed = value
    for name in _SENSITIVE_ENV_NAMES:
        configured = os.getenv(name, "")
        if len(configured) >= 4:
            scrubbed = scrubbed.replace(configured, "[REDACTED_CREDENTIAL]")
    scrubbed = _AUTHORIZATION_RE.sub(r"\1[REDACTED_CREDENTIAL]", scrubbed)
    scrubbed = _BEARER_RE.sub("Bearer [REDACTED_CREDENTIAL]", scrubbed)
    return _URL_RE.sub(_scrub_url, scrubbed)


def _snapshot(value: Any, *, _seen: set[int] | None = None) -> Any:
    """Create a detached, credential-scrubbed representation without mutation."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _scrub_text(value)
    if isinstance(value, bytes):
        return _scrub_text(value.decode("utf-8", errors="replace"))

    seen = _seen if _seen is not None else set()
    identity = id(value)
    if identity in seen:
        return "<recursive-reference>"
    seen.add(identity)
    try:
        if isinstance(value, Mapping):
            snapshot: dict[str, Any] = {}
            redacted_fields = 0
            for key, item in value.items():
                if _sensitive_key(key):
                    redacted_fields += 1
                    continue
                snapshot[str(key)] = _snapshot(item, _seen=seen)
            if redacted_fields:
                snapshot["redacted_credential_fields"] = redacted_fields
            return snapshot
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [_snapshot(item, _seen=seen) for item in value]

        model_dump = getattr(value, "model_dump", None)
        if callable(model_dump):
            dumped = model_dump(mode="python")
            snapshot = _snapshot(dumped, _seen=seen)
            if isinstance(snapshot, dict):
                return {"message_type": value.__class__.__name__, **snapshot}
            return snapshot

        attributes: dict[str, Any] = {}
        for name in (
            "type",
            "role",
            "content",
            "name",
            "id",
            "additional_kwargs",
            "response_metadata",
            "tool_calls",
            "invalid_tool_calls",
            "usage_metadata",
        ):
            if hasattr(value, name):
                attributes[name] = _snapshot(getattr(value, name), _seen=seen)
        if attributes:
            return {"message_type": value.__class__.__name__, **attributes}
        return _scrub_text(str(value))
    finally:
        seen.discard(identity)


def _render_payload(payload: Any) -> tuple[str, bool, int]:
    rendered = json.dumps(_snapshot(payload), ensure_ascii=False, indent=2, default=str)
    original_chars = len(rendered)
    limit = _max_chars()
    if original_chars <= limit:
        return rendered, False, original_chars
    marker = "\n... [HUMAN TRACE payload truncated]"
    if limit <= len(marker):
        return marker[:limit], True, original_chars
    return rendered[: limit - len(marker)] + marker, True, original_chars


def emit_human_trace(
    stage: str,
    payload: Any,
    *,
    model: str,
    privacy_enabled: bool,
    tenant_id: str | None,
    path: str,
    projection_applied: bool,
    provider_called: bool | None = None,
    cache_hit: bool = False,
    chunk_index: int | None = None,
) -> None:
    """Emit one bounded trace event; suppress every tracing failure."""
    if not human_trace_enabled():
        return
    try:
        rendered, truncated, original_chars = _render_payload(payload)
        fields: dict[str, Any] = {
            "human_trace": True,
            "stage": stage,
            "path": path,
            "model": _scrub_text(model),
            "privacy_enabled": privacy_enabled,
            "projection_applied": projection_applied,
            "tenant_id": _scrub_text(tenant_id) if tenant_id else None,
            "cache_hit": cache_hit,
            "payload": rendered,
            "payload_truncated": truncated,
            "payload_original_chars": original_chars,
        }
        if provider_called is not None:
            fields["provider_called"] = provider_called
        if chunk_index is not None:
            fields["chunk_index"] = chunk_index
        logger.info(TRACE_EVENT_NAMES[stage], **fields)
    except Exception:  # noqa: BLE001 — diagnostics must never affect LLM behavior
        return
