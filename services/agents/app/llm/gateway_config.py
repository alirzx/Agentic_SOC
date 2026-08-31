"""Gateway URL + credential diagnostics for OpenAI-compatible providers (Phase 8.6.1)."""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlparse

_TOKEN_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_\-]{24,}$")
_CHAT_COMPLETIONS_SUFFIX = "/chat/completions"


def load_api_key() -> str | None:
    """Load API key from env without logging it."""
    raw = os.getenv("OPENAI_API_KEY", "").strip() or os.getenv("LLM_API_KEY", "").strip()
    return raw or None


def describe_api_key(api_key: str | None = None) -> dict[str, Any]:
    """Safe API key diagnostics — never returns the secret."""
    key = api_key or load_api_key()
    if not key:
        return {"present": False, "length": 0, "prefix": ""}
    return {
        "present": True,
        "length": len(key),
        "prefix": key[:4],
    }


def normalize_openai_base_url(base_url: str) -> str:
    """Normalize OpenAI-compatible base URL for :class:`langchain_openai.ChatOpenAI`.

    Canonical form ends with ``/v1`` (no trailing slash). Strips accidental
    ``/chat/completions`` suffix. Does **not** append ``/v1`` blindly.
    """
    url = base_url.strip().rstrip("/")
    if not url:
        return url
    if url.endswith(_CHAT_COMPLETIONS_SUFFIX):
        url = url[: -len(_CHAT_COMPLETIONS_SUFFIX)]
    return url


def sanitize_base_url_for_log(base_url: str | None) -> str:
    """Redact long path segments (gateway tokens) for safe logging."""
    if not base_url:
        return "NOT_CONFIGURED"
    parsed = urlparse(base_url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    redacted: list[str] = []
    for segment in segments:
        if _TOKEN_SEGMENT_RE.match(segment):
            redacted.append(f"{segment[:4]}…{segment[-4:]}")
        else:
            redacted.append(segment)
    path = "/" + "/".join(redacted) if redacted else ""
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def base_url_issues(base_url: str | None) -> list[str]:
    """Return configuration warnings without mutating the URL."""
    if not base_url:
        return ["OPENAI_BASE_URL is not set"]
    issues: list[str] = []
    normalized = normalize_openai_base_url(base_url)
    if "/v1/v1" in normalized:
        issues.append("duplicate /v1 segment detected (/v1/v1)")
    if not normalized.endswith("/v1"):
        issues.append("base URL does not end with /v1 — OpenAI-compatible clients append /chat/completions")
    if base_url.endswith(_CHAT_COMPLETIONS_SUFFIX):
        issues.append("base URL includes /chat/completions — use base ending in /v1 only")
    return issues


def extract_embedded_gateway_token(base_url: str | None) -> str | None:
    """Return a long path segment that likely embeds a gateway token."""
    if not base_url:
        return None
    segments = [segment for segment in urlparse(base_url).path.split("/") if segment]
    for segment in segments:
        if _TOKEN_SEGMENT_RE.match(segment):
            return segment
    return None


def validate_gateway_config() -> dict[str, Any]:
    """Collect safe gateway configuration diagnostics."""
    from app.llm.factory import resolve_base_url, resolve_model_alias

    raw_base = os.getenv("OPENAI_BASE_URL", "").strip() or os.getenv("LLM_BASE_URL", "").strip() or None
    resolved_base = resolve_base_url()
    api_key_info = describe_api_key()
    model = resolve_model_alias("triage")
    embedded_token = extract_embedded_gateway_token(raw_base or resolved_base or "")
    api_key = load_api_key()
    token_matches_key = bool(
        embedded_token and api_key and embedded_token == api_key
    )
    issues: list[str] = []
    if not api_key_info["present"]:
        issues.append("OPENAI_API_KEY is missing")
    if not resolved_base:
        issues.append("OPENAI_BASE_URL is missing")
    else:
        issues.extend(base_url_issues(raw_base or resolved_base))
    if embedded_token and api_key and not token_matches_key:
        issues.append(
            "embedded gateway path token differs from OPENAI_API_KEY — verify both Arvan credentials are current"
        )
    category = "OK"
    if not api_key_info["present"] or not resolved_base:
        category = "CONFIGURATION_ERROR"
    return {
        "api_key": api_key_info,
        "base_url_raw_sanitized": sanitize_base_url_for_log(raw_base),
        "base_url_normalized_sanitized": sanitize_base_url_for_log(resolved_base),
        "base_url_issues": issues,
        "model_triage": model,
        "model_investigation": resolve_model_alias("investigation"),
        "model_report": resolve_model_alias("report"),
        "embedded_path_token_detected": bool(embedded_token),
        "api_key_matches_embedded_path_token": token_matches_key,
        "configuration_category": category,
        "llm_configured": bool(api_key_info["present"] and resolved_base),
    }
