"""LLMInputContract — fail-closed validator for every LLM call (T2.3).

The contract enforces a minimum-leak policy on every prompt that leaves
``services/agents`` for a third-party LLM. Allowed inputs:

* ``ContextBundle.summary_for_llm`` outputs (summary fields, scores,
  small lists),
* analyst-authored alert summaries / titles / descriptions,
* RAG snippets retrieved via the doc store,
* numerical scores (severity, risk, confidence),
* MITRE technique IDs and short categorical strings.

Forbidden inputs (the call MUST be aborted with
:class:`LLMContractViolation` if any are detected):

* raw OCSF JSON (objects with ``activity_id`` / ``class_uid`` /
  ``time_dt`` keys, ``metadata.product`` blocks, etc.),
* raw vendor log lines (Splunk events, Sentinel JSON arrays, EDR
  process events, Sysmon XML, m365 audit blobs, …),
* serialised PII payloads (passwords, tokens, full credit-card numbers).

The validator is intentionally heuristic — false positives are far less
costly than false negatives. Operators who need to disable the gate for
a debugging session can flip ``AISOC_AGENTS_LLM_CONTRACT_ENFORCED=0``;
in production this stays on by default.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Iterable
from typing import Any

import structlog
from langchain_core.messages import AIMessage

from app.core.cost_telemetry import record_llm_call
from app.llm.human_trace import (
    INTERNAL_INPUT,
    LOCAL_RESPONSE,
    PROVIDER_INPUT,
    PROVIDER_RESPONSE,
    emit_human_trace,
)
from app.llm.response_cache import ResponseCache
from app.privacy.context import PrivacyConfigurationError, current_privacy_gateway

logger = structlog.get_logger()

_ALLOWED_MESSAGE_ROLES = frozenset({"system", "user", "assistant", "tool", "developer", "function"})
_LANGCHAIN_RUNTIME_KWARGS = frozenset({"config"})
_MODEL_VISIBLE_KWARGS = frozenset(
    {
        "frequency_penalty",
        "functions",
        "logit_bias",
        "logprobs",
        "max_completion_tokens",
        "max_tokens",
        "n",
        "parallel_tool_calls",
        "presence_penalty",
        "reasoning_effort",
        "response_format",
        "seed",
        "service_tier",
        "stop",
        "temperature",
        "tool_choice",
        "tools",
        "top_logprobs",
        "top_p",
    }
)
_STRUCTURAL_OPTION_KEYS = frozenset(
    {
        "$ref",
        "additionalProperties",
        "const",
        "enum",
        "format",
        "name",
        "pattern",
        "required",
        "strict",
        "type",
    }
)

# Wave 1 — content-addressed response cache in the LLM hot path. Identical
# (model + prompt + input) calls are served from cache instead of paid for
# again. Byte-identical to what the model returned, so it's determinism-safe.
# Disable with AISOC_LLM_RESPONSE_CACHE=0.
_RESPONSE_CACHE = ResponseCache()
_RESPONSE_CACHE_ENABLED = os.getenv("AISOC_LLM_RESPONSE_CACHE", "1").lower() not in ("0", "false", "no")


def _model_name(llm: Any) -> str:
    return str(getattr(llm, "model", None) or getattr(llm, "model_name", None) or "")


def _trace(
    stage: str,
    payload: Any,
    *,
    gateway: Any,
    model: str,
    path: str,
    provider_called: bool | None = None,
    cache_hit: bool = False,
    chunk_index: int | None = None,
) -> None:
    emit_human_trace(
        stage,
        payload,
        model=model,
        privacy_enabled=gateway is not None,
        tenant_id=getattr(gateway, "tenant_id", None),
        path=path,
        projection_applied=gateway is not None and stage in {PROVIDER_INPUT, PROVIDER_RESPONSE},
        provider_called=provider_called,
        cache_hit=cache_hit,
        chunk_index=chunk_index,
    )


def _cache_parts(messages: list[Any]) -> tuple[str, str]:
    """Split messages into (system prompt, user input) for the cache key."""
    prompt_parts: list[str] = []
    input_parts: list[str] = []
    for m in messages:
        content = getattr(m, "content", m)
        if not isinstance(content, str):
            content = str(content)
        mtype = (getattr(m, "type", "") or m.__class__.__name__).lower()
        (prompt_parts if "system" in mtype else input_parts).append(content)
    return "\n".join(prompt_parts), "\n".join(input_parts)


def _cache_safe(messages: list[Any]) -> bool:
    """Tool turns need their full structured shape and are never content-cached."""
    for message in messages:
        if getattr(message, "tool_calls", None):
            return False
        role = str(getattr(message, "type", "") or (message.get("role") if isinstance(message, dict) else ""))
        if role.lower() == "tool":
            return False
    return True


AGENTS_LLM_CONTRACT_ENFORCED_ENV = "AISOC_AGENTS_LLM_CONTRACT_ENFORCED"

_OCSF_KEYS = frozenset(
    {
        "class_uid",
        "category_uid",
        "activity_id",
        "type_uid",
        "metadata",
        "time_dt",
        "observables",
        "raw_data",
    }
)
_LOG_KEYS = frozenset(
    {
        "Event",
        "EventData",
        "Sysmon",
        "RecordID",
        "EventRecordID",
        "Channel",
        "Provider",
        "_raw",
        "_time",
        "punct",
    }
)

# Union of dict keys that must never appear in LLM-bound JSON strings
# (prompt serialization uses this to redact / shallow-summarize nested data).
CONTRACT_DICT_KEY_BLOCKLIST: frozenset[str] = frozenset(_OCSF_KEYS | _LOG_KEYS)

# Compact regex for the most common raw-log signatures we want to catch
# even when the payload is rendered as a string instead of a dict.
_LOG_SHAPE_PATTERNS = (
    re.compile(r'"class_uid"\s*:\s*\d+'),
    re.compile(r'"activity_id"\s*:\s*\d+'),
    re.compile(r'"EventID"\s*:\s*\d+'),
    re.compile(r'"EventRecordID"\s*:\s*\d+'),
    re.compile(r'<Event xmlns="http://schemas\.microsoft\.com/win/'),
    # Splunk / Sentinel "search head" envelope
    re.compile(r'"_raw"\s*:\s*"'),
    re.compile(r'"sourcetype"\s*:\s*"'),
)

# Loose secret patterns — caught only as a last-resort guard. The vault
# layer (T*.4) is the primary defence; this is belt-and-braces.
_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

_MAX_MESSAGE_CHARS = int(os.getenv("AISOC_AGENTS_LLM_CONTRACT_MAX_CHARS", "60000"))
_MAX_JSON_LINE_KEYS = 6  # tuple-of-keys threshold for "looks like a log line"


class LLMContractViolation(RuntimeError):
    """Raised when a prompt about to be sent to an LLM violates the contract."""

    def __init__(self, reason: str, *, role: str | None = None, evidence: str | None = None) -> None:
        msg = f"[LLMInputContract] {reason}"
        if role:
            msg += f" (role={role})"
        if evidence:
            msg += f" — evidence: {evidence[:200]!r}"
        super().__init__(msg)
        self.reason = reason
        self.role = role
        self.evidence = evidence


# ---------------------------------------------------------------------------
# Enforcement toggle
# ---------------------------------------------------------------------------

# Module-level cache so callers can flip enforcement at runtime via
# :func:`set_contract_enforcement`. The env var is the source of truth on
# fresh process start.


def _env_default_enforced() -> bool:
    raw = os.getenv(AGENTS_LLM_CONTRACT_ENFORCED_ENV, "1").strip()
    return raw not in {"0", "false", "False", "no", "off"}


_ENFORCED: bool = _env_default_enforced()


def is_contract_enforced() -> bool:
    return _ENFORCED


def set_contract_enforcement(value: bool) -> bool:
    """Override enforcement at runtime. Returns the previous value."""
    global _ENFORCED  # noqa: PLW0603
    prev, _ENFORCED = _ENFORCED, bool(value)
    return prev


# ---------------------------------------------------------------------------
# Heuristic classifier — does this message look like raw log / OCSF?
# ---------------------------------------------------------------------------


def _looks_like_ocsf(payload: dict[str, Any]) -> str | None:
    matched = _OCSF_KEYS & set(payload.keys())
    if matched:
        return f"OCSF keys present: {sorted(matched)}"
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and {"product", "version"} <= set(metadata.keys()):
        return "OCSF-style metadata.product/version block"
    return None


def _looks_like_raw_log(payload: dict[str, Any]) -> str | None:
    matched = _LOG_KEYS & set(payload.keys())
    if matched:
        return f"raw-log keys present: {sorted(matched)}"
    if isinstance(payload.get("EventID"), int) and "Channel" in payload:
        return "Windows event-log shape (EventID + Channel)"
    return None


def _looks_like_log_string(text: str) -> str | None:
    head = text[:4000]
    for pattern in _LOG_SHAPE_PATTERNS:
        m = pattern.search(head)
        if m:
            return f"raw-log signature matched: {m.group(0)[:80]}"
    return None


def _looks_like_secret(text: str) -> str | None:
    head = text[:4000]
    for pattern in _SECRET_PATTERNS:
        m = pattern.search(head)
        if m:
            return f"secret-shaped value detected: {m.group(0)[:60]}"
    return None


def _try_load_json(text: str) -> Any | None:
    """Parse ``text`` as JSON if it looks like one; return ``None`` otherwise."""
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None


def classify_message(content: str, *, role: str = "user") -> str | None:
    """Return a violation reason if ``content`` breaches the contract, else None."""
    if not isinstance(content, str):
        # Multi-modal (list-of-parts) messages aren't supported by the
        # contract yet — reject them so we never leak them by accident.
        return f"non-string message content (type={type(content).__name__})"

    if len(content) > _MAX_MESSAGE_CHARS:
        return f"message exceeds size cap ({len(content)} > {_MAX_MESSAGE_CHARS} chars)"

    # 1) Substring scan — fastest path, catches log shapes embedded in prose.
    log_hit = _looks_like_log_string(content)
    if log_hit:
        return log_hit

    secret_hit = _looks_like_secret(content)
    if secret_hit:
        return secret_hit

    # 2) JSON inspection — only when the message *looks* like JSON we try
    # to parse it. Avoids paying parse cost on every prose message.
    parsed = _try_load_json(content)
    if isinstance(parsed, dict):
        ocsf = _looks_like_ocsf(parsed)
        if ocsf:
            return ocsf
        log = _looks_like_raw_log(parsed)
        if log:
            return log
    elif isinstance(parsed, list) and parsed:
        head = parsed[0]
        if isinstance(head, dict):
            if len(head) > _MAX_JSON_LINE_KEYS and (_looks_like_ocsf(head) or _looks_like_raw_log(head)):
                return "raw event array detected (looks like log batch)"

    return None


# ---------------------------------------------------------------------------
# Contract model
# ---------------------------------------------------------------------------


class LLMInputContract:
    """Validator for the message list handed to ``llm.ainvoke``.

    Implemented as a class with a ``validate`` classmethod (rather than a
    Pydantic ``BaseModel``) because LangChain's ``BaseMessage`` subclasses
    don't round-trip cleanly through Pydantic v2 validation. The contract
    invariants are enforced via :func:`classify_message` per element.
    """

    @classmethod
    def validate(cls, messages: Iterable[Any]) -> list[dict[str, Any]]:
        """Return the normalised view of ``messages`` if all pass the contract.

        Each returned dict has shape ``{"role": str, "content": str}``.
        Raises :class:`LLMContractViolation` on the first breach.
        """
        normalised: list[dict[str, Any]] = []
        for idx, msg in enumerate(messages):
            role, content = _coerce_message(msg)
            if is_contract_enforced():
                reason = classify_message(content, role=role)
                if reason:
                    raise LLMContractViolation(
                        f"message[{idx}] failed contract: {reason}",
                        role=role,
                        evidence=content[:200],
                    )
            normalised.append({"role": role, "content": content})
        return normalised


def _coerce_message(msg: Any) -> tuple[str, str]:
    """Extract string content from a supported chat-message-shaped object.

    Supports plain dicts, LangChain ``BaseMessage`` subclasses, and tuples
    of ``(role, content)``. Multipart or otherwise structured content is
    rejected because stringifying it for validation while sending the original
    object would let provider-visible content bypass this contract.
    """
    def require_string(content: Any, *, role: str) -> str:
        if not isinstance(content, str):
            raise LLMContractViolation("non-string message content is unsupported", role=role)
        return content

    if isinstance(msg, dict):
        role = str(msg.get("role") or "user")
        if role not in _ALLOWED_MESSAGE_ROLES:
            raise LLMContractViolation("invalid message role", role=role)
        return role, require_string(msg.get("content"), role=role)
    if hasattr(msg, "type") and hasattr(msg, "content"):
        # LangChain BaseMessage: ``.type`` is "system" / "human" / "ai" / "tool"
        type_to_role = {"human": "user", "ai": "assistant", "system": "system", "tool": "tool"}
        role = type_to_role.get(getattr(msg, "type", "user"), "user")
        return role, require_string(getattr(msg, "content", ""), role=role)
    if isinstance(msg, tuple) and len(msg) == 2:
        role, content = msg
        normalized_role = {"human": "user", "ai": "assistant"}.get(str(role), str(role))
        if normalized_role not in _ALLOWED_MESSAGE_ROLES:
            raise LLMContractViolation("invalid message role", role=normalized_role)
        return normalized_role, require_string(content, role=normalized_role)
    return "user", str(msg)


def validate_messages(messages: Iterable[Any]) -> list[dict[str, Any]]:
    """Module-level convenience for one-off validation."""
    return LLMInputContract.validate(messages)


def _split_invocation_kwargs(kwargs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    unsupported = sorted(set(kwargs) - _LANGCHAIN_RUNTIME_KWARGS - _MODEL_VISIBLE_KWARGS)
    if unsupported:
        raise LLMContractViolation(f"unsupported LangChain invocation fields: {unsupported}")
    runtime = {key: value for key, value in kwargs.items() if key in _LANGCHAIN_RUNTIME_KWARGS}
    provider = {key: value for key, value in kwargs.items() if key in _MODEL_VISIBLE_KWARGS}
    return runtime, provider


def _assert_model_option_structure(original: Any, protected: Any, *, key: str = "") -> None:
    """Reject a Gateway transformation that changes tool/schema semantics."""
    if isinstance(original, dict):
        if not isinstance(protected, dict) or set(original) != set(protected):
            raise PrivacyConfigurationError("privacy projection changed model-option structure")
        for child_key, value in original.items():
            if child_key in _STRUCTURAL_OPTION_KEYS and protected[child_key] != value:
                raise PrivacyConfigurationError("privacy projection changed provider schema semantics")
            _assert_model_option_structure(value, protected[child_key], key=child_key)
        return
    if isinstance(original, list):
        if not isinstance(protected, list) or len(original) != len(protected):
            raise PrivacyConfigurationError("privacy projection changed model-option structure")
        for before, after in zip(original, protected, strict=True):
            _assert_model_option_structure(before, after, key=key)
        return
    if not isinstance(original, str) and protected != original:
        raise PrivacyConfigurationError("privacy projection changed model-option value")


async def _provider_invocation(
    gateway: Any,
    messages: list[Any],
    kwargs: dict[str, Any],
) -> tuple[list[Any], dict[str, Any]]:
    runtime, model_options = _split_invocation_kwargs(kwargs)
    provider_messages = await gateway.encode_messages(messages) if gateway else messages
    protected_options = model_options
    if gateway and model_options:
        protected_options = await gateway.encode_model_options(model_options)
        _assert_model_option_structure(model_options, protected_options)
    return provider_messages, {**runtime, **protected_options}


async def protect_model_options(options: dict[str, Any]) -> dict[str, Any]:
    """Protect trusted model-visible binding options before ``llm.bind*``.

    Bound LangChain runnables keep their provider kwargs outside the later
    ``ainvoke`` call, so callers must use this helper before binding them.
    """
    _runtime, model_options = _split_invocation_kwargs(dict(options))
    gateway = current_privacy_gateway()
    if gateway is None or not model_options:
        return model_options
    protected = await gateway.encode_model_options(model_options)
    _assert_model_option_structure(model_options, protected)
    return protected


# ---------------------------------------------------------------------------
# Safe LLM invocation wrapper
# ---------------------------------------------------------------------------


async def safe_ainvoke(llm: Any, messages: Iterable[Any], **kwargs: Any) -> Any:
    """Validate ``messages`` against the contract, then call ``llm.ainvoke``.

    All callsites in ``services/agents`` MUST route through this function
    (or :func:`safe_astream` for streaming) so the contract is uniformly
    enforced. Raises :class:`LLMContractViolation` on contract breach.
    """
    materialised = list(messages)
    gateway = current_privacy_gateway()
    model = _model_name(llm)
    _trace(INTERNAL_INPUT, materialised, gateway=gateway, model=model, path="ainvoke")
    provider_messages, provider_kwargs = await _provider_invocation(gateway, materialised, kwargs)
    provider_trace = (
        {"messages": provider_messages, "model_options": {k: v for k, v in provider_kwargs.items() if k != "config"}}
        if provider_kwargs
        else provider_messages
    )
    _trace(PROVIDER_INPUT, provider_trace, gateway=gateway, model=model, path="ainvoke")
    LLMInputContract.validate(provider_messages)

    prompt, user_input = _cache_parts(provider_messages)
    cache_namespace = gateway.cache_namespace if gateway else ""
    # Only cache plain calls (no per-call kwargs like temperature overrides).
    use_cache = (
        _RESPONSE_CACHE_ENABLED
        and not bool(getattr(gateway, "is_remote", False))
        and bool(model)
        and bool(user_input)
        and not provider_kwargs
        and _cache_safe(provider_messages)
    )
    if use_cache:
        cached = _RESPONSE_CACHE.lookup(model=model, prompt=prompt, user_input=user_input, namespace=cache_namespace)
        if cached is not None:
            cached_message = AIMessage(content=cached)
            _trace(
                PROVIDER_RESPONSE,
                cached_message,
                gateway=gateway,
                model=model,
                path="cache",
                provider_called=False,
                cache_hit=True,
            )
            local_result = await gateway.decode_response(cached_message) if gateway else cached_message
            _trace(
                LOCAL_RESPONSE,
                local_result,
                gateway=gateway,
                model=model,
                path="cache",
                provider_called=False,
                cache_hit=True,
            )
            return local_result

    t0 = time.monotonic()
    result = await llm.ainvoke(provider_messages, **provider_kwargs)
    latency_ms = (time.monotonic() - t0) * 1000.0
    _trace(PROVIDER_RESPONSE, result, gateway=gateway, model=model, path="ainvoke", provider_called=True)
    # Record token/cost against the active CostTracker (no-op if none bound), so
    # the high-volume auto-triage path is finally visible in the cost dashboard.
    try:
        record_llm_call(result, model=model, latency_ms=latency_ms)
    except Exception:  # noqa: BLE001 — telemetry must never break an LLM call
        pass

    if use_cache:
        content = getattr(result, "content", None)
        if isinstance(content, str) and content:
            _RESPONSE_CACHE.store(
                model=model,
                prompt=prompt,
                user_input=user_input,
                response=content,
                namespace=cache_namespace,
            )
    local_result = await gateway.decode_response(result) if gateway else result
    _trace(LOCAL_RESPONSE, local_result, gateway=gateway, model=model, path="ainvoke", provider_called=True)
    return local_result


async def safe_astream(llm: Any, messages: Iterable[Any], **kwargs: Any):
    """Streaming variant with bounded whole-response restoration.

    Protected streams are buffered and emitted as one combined chunk so an
    alias split across provider chunks can never be partially restored.
    """
    materialised = list(messages)
    gateway = current_privacy_gateway()
    model = _model_name(llm)
    _trace(INTERNAL_INPUT, materialised, gateway=gateway, model=model, path="astream")
    provider_messages, provider_kwargs = await _provider_invocation(gateway, materialised, kwargs)
    provider_trace = (
        {"messages": provider_messages, "model_options": {k: v for k, v in provider_kwargs.items() if k != "config"}}
        if provider_kwargs
        else provider_messages
    )
    _trace(PROVIDER_INPUT, provider_trace, gateway=gateway, model=model, path="astream")
    LLMInputContract.validate(provider_messages)
    if gateway is None:
        chunk_index = 0
        t0 = time.monotonic()
        combined: Any | None = None
        async for chunk in llm.astream(provider_messages, **provider_kwargs):
            _trace(
                PROVIDER_RESPONSE,
                chunk,
                gateway=gateway,
                model=model,
                path="astream",
                provider_called=True,
                chunk_index=chunk_index,
            )
            _trace(
                LOCAL_RESPONSE,
                chunk,
                gateway=gateway,
                model=model,
                path="astream",
                provider_called=True,
                chunk_index=chunk_index,
            )
            yield chunk
            try:
                combined = chunk if combined is None else combined + chunk
            except (TypeError, ValueError):
                combined = None
            chunk_index += 1
        if combined is not None:
            try:
                record_llm_call(combined, model=model, latency_ms=(time.monotonic() - t0) * 1000.0)
            except Exception:  # noqa: BLE001 - telemetry never breaks streaming
                pass
        return

    combined: Any | None = None
    size = 0
    max_chars = int(os.getenv("AISOC_LLM_PRIVACY_STREAM_MAX_CHARS", "1000000"))
    t0 = time.monotonic()
    async for chunk in llm.astream(provider_messages, **provider_kwargs):
        content = getattr(chunk, "content", chunk)
        size += len(content) if isinstance(content, str) else len(str(content))
        if size > max_chars:
            raise PrivacyConfigurationError("protected LLM stream exceeded the bounded buffer limit")
        if combined is None:
            combined = chunk
        else:
            try:
                combined = combined + chunk
            except (TypeError, ValueError) as exc:
                raise PrivacyConfigurationError("protected LLM stream returned unsupported chunk types") from exc
    if combined is not None:
        _trace(PROVIDER_RESPONSE, combined, gateway=gateway, model=model, path="astream", provider_called=True)
        try:
            record_llm_call(combined, model=model, latency_ms=(time.monotonic() - t0) * 1000.0)
        except Exception:  # noqa: BLE001 - telemetry never breaks streaming
            pass
        local_result = await gateway.decode_response(combined)
        _trace(LOCAL_RESPONSE, local_result, gateway=gateway, model=model, path="astream", provider_called=True)
        yield local_result


def make_safe_chat_model(llm: Any) -> Any:
    """Wrap a chat model so its ``ainvoke``/``astream`` enforce the contract.

    Useful when an existing function holds an ``llm`` reference and we
    want to upgrade it without rewriting every call site. The wrapper
    delegates everything else to the underlying model unchanged.
    """

    class _ContractGuardedChatModel:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

        async def ainvoke(self, messages: Iterable[Any], **kwargs: Any) -> Any:
            return await safe_ainvoke(self._inner, messages, **kwargs)

        def astream(self, messages: Iterable[Any], **kwargs: Any):
            return safe_astream(self._inner, messages, **kwargs)

    return _ContractGuardedChatModel(llm)


# ---------------------------------------------------------------------------
# Raw OpenAI-compatible chat-completions HTTP wrapper
# ---------------------------------------------------------------------------

DEFAULT_OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"

_SAFE_HTTP_BODY_FIELDS = frozenset(
    {
        "frequency_penalty",
        "logit_bias",
        "logprobs",
        "max_completion_tokens",
        "max_tokens",
        "n",
        "parallel_tool_calls",
        "presence_penalty",
        "reasoning_effort",
        "response_format",
        "seed",
        "service_tier",
        "stop",
        "temperature",
        "tool_choice",
        "tools",
        "top_logprobs",
        "top_p",
    }
)


def _validate_http_options(extra_body: dict[str, Any], extra_headers: dict[str, str] | None) -> None:
    unsupported = sorted(set(extra_body) - _SAFE_HTTP_BODY_FIELDS)
    if unsupported:
        raise LLMContractViolation(f"unsupported raw chat-completions fields: {unsupported}")
    if extra_headers and any(str(key).strip().lower() in {"authorization", "proxy-authorization"} for key in extra_headers):
        raise LLMContractViolation("provider authorization headers cannot be overridden")


async def safe_chat_completions_request(
    *,
    api_key: str,
    model: str,
    messages: Iterable[Any],
    url: str = DEFAULT_OPENAI_CHAT_COMPLETIONS_URL,
    timeout: float = 30.0,
    extra_headers: dict[str, str] | None = None,
    **extra_body: Any,
) -> dict[str, Any]:
    """Validate ``messages`` against the contract, then issue a chat-completions POST.

    Use this for call sites in ``services/agents`` that talk to an
    OpenAI-compatible chat-completions endpoint over raw HTTP (e.g.
    ``api/copilot.py``, ``nl_query/translator.py``) instead of LangChain.
    The contract is enforced **before** the network request, so a
    violation never leaks log data on the wire.

    Returns the parsed JSON response. Raises:

    * :class:`LLMContractViolation` if any message fails the contract.
    * ``ValueError`` if ``api_key`` is empty.
    * ``httpx.HTTPError`` for transport / non-2xx responses (callers
      decide whether to fall back).
    """
    if not api_key:
        raise ValueError("api_key is required for safe_chat_completions_request")

    materialised = list(messages)
    gateway = current_privacy_gateway()
    _trace(INTERNAL_INPUT, materialised, gateway=gateway, model=model, path="http")
    _validate_http_options(extra_body, extra_headers)
    internal_body: dict[str, Any] = {"model": model, "messages": materialised, **extra_body}
    body = await gateway.encode_http_body(internal_body) if gateway else internal_body
    provider_messages = body["messages"]
    _trace(PROVIDER_INPUT, body, gateway=gateway, model=model, path="http")
    LLMInputContract.validate(provider_messages)

    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - httpx is a hard dep
        raise RuntimeError("httpx is required for safe_chat_completions_request") from exc

    headers: dict[str, str] = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    async with httpx.AsyncClient(timeout=timeout) as client:
        t0 = time.monotonic()
        resp = await client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        payload = resp.json()
        _trace(PROVIDER_RESPONSE, payload, gateway=gateway, model=model, path="http", provider_called=True)
        try:
            record_llm_call(payload, model=model, latency_ms=(time.monotonic() - t0) * 1000.0)
        except Exception:  # noqa: BLE001 - telemetry never breaks an LLM call
            pass
        local_result = await gateway.decode_response(payload) if gateway else payload
        _trace(LOCAL_RESPONSE, local_result, gateway=gateway, model=model, path="http", provider_called=True)
        return local_result
