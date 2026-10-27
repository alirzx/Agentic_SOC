"""Async adapter for the independent Soorin Data Privacy Gateway.

This module deliberately contains no detection, tokenization, or encryption
logic.  Those security-boundary responsibilities stay in the standalone
Gateway.  The adapter only owns workflow context lifecycle and lossless
conversion between LangChain objects and the Gateway's JSON contract.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import os
import re
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

import httpx
import structlog

from app.privacy.gateway import PRIVACY_SYSTEM_GUIDANCE

logger = structlog.get_logger()

_PROFILE_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_ROLE_BY_TYPE = {"human": "user", "ai": "assistant", "system": "system", "tool": "tool"}
_RETRYABLE_STATUS = frozenset({409, 502, 503, 504})
_ALIAS_PREFIX = (
    r"(?:CRED_[A-Z_]+|IP_(?:V4|V6)_[A-Z_]+|IP_OPAQUE|HOST|USER|EMAIL|ASSET|MAC|SUBNET|"
    r"DOMAIN|URL_INTERNAL|PATH|TICKET|CASE|REFERENCE|PHONE|EMPLOYEE_ID|USER_SID|ORG_ID|"
    r"AD_GROUP|CLOUD_RESOURCE|DEVICE_SERIAL|SPLUNK_INDEX)_"
)
_ALIAS_LIKE_RE = re.compile(rf"(?<![A-Za-z0-9_]){_ALIAS_PREFIX}[A-Z0-9_]{{8,48}}(?![A-Za-z0-9_])")
_REGISTRATION_FIELDS: dict[str, str] = {
    "src_ip": "IP",
    "source_ip": "IP",
    "dst_ip": "IP",
    "destination_ip": "IP",
    "ip_address": "IP",
    "host": "HOST",
    "hostname": "HOST",
    "host_name": "HOST",
    "device_name": "HOST",
    "computer_name": "HOST",
    "username": "USER",
    "user_name": "USER",
    "src_user": "USER",
    "dest_user": "USER",
    "principal": "USER",
    "domain": "DOMAIN",
    "domain_name": "DOMAIN",
    "asset": "ASSET",
    "asset_id": "ASSET",
    "device_id": "ASSET",
}


class RemotePrivacyError(RuntimeError):
    """Credential-safe failure raised by the remote privacy boundary."""

    def __init__(self, category: str, *, status_code: int | None = None) -> None:
        super().__init__(f"remote privacy gateway failure: {category}")
        self.category = category
        self.status_code = status_code


def _error_category(exc: BaseException) -> tuple[str, int | None]:
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return {
            400: "invalid_context_or_policy",
            401: "invalid_service_credential",
            403: "unauthorized_tenant_or_context",
            413: "payload_too_large",
            422: "invalid_request_schema",
            503: "storage_unavailable",
        }.get(status, "gateway_server_error" if status >= 500 else "gateway_request_rejected"), status
    if isinstance(exc, httpx.TimeoutException | TimeoutError):
        return "gateway_timeout", None
    if isinstance(exc, httpx.HTTPError | OSError):
        return "gateway_unavailable", None
    return "gateway_client_error", None


def _json_value(value: Any, *, _depth: int = 0) -> Any:
    """Create a detached JSON-compatible snapshot without mutating ``value``."""
    if _depth > 32:
        raise RemotePrivacyError("unsupported_message_nesting")
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, Mapping):
        return {str(key): _json_value(item, _depth=_depth + 1) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_json_value(item, _depth=_depth + 1) for item in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _json_value(model_dump(mode="python"), _depth=_depth + 1)

    attributes: dict[str, Any] = {}
    for name in (
        "type",
        "role",
        "content",
        "name",
        "id",
        "tool_call_id",
        "additional_kwargs",
        "response_metadata",
        "tool_calls",
        "invalid_tool_calls",
        "usage_metadata",
    ):
        if hasattr(value, name):
            attributes[name] = _json_value(getattr(value, name), _depth=_depth + 1)
    if attributes:
        return attributes
    raise RemotePrivacyError("unsupported_message_type")


def _message_to_wire(message: Any) -> dict[str, Any]:
    if isinstance(message, tuple) and len(message) == 2:
        return {"role": str(message[0]), "content": _json_value(message[1])}
    data = _json_value(message)
    if not isinstance(data, dict):
        raise RemotePrivacyError("unsupported_message_type")
    role = data.get("role")
    if not isinstance(role, str) or not role:
        message_type = str(data.get("type") or getattr(message, "type", "human"))
        role = _ROLE_BY_TYPE.get(message_type, message_type if message_type in _ROLE_BY_TYPE.values() else "user")
    if "content" not in data:
        raise RemotePrivacyError("message_content_missing")
    return {"role": role, **data}


def _rebuild(template: Any, transformed: Any) -> Any:
    """Reconstruct the caller/provider object shape from a transformed snapshot."""
    if isinstance(template, dict):
        return transformed
    if isinstance(template, list):
        if not isinstance(transformed, list) or len(template) != len(transformed):
            raise RemotePrivacyError("gateway_response_shape_mismatch")
        return [_rebuild(original, item) for original, item in zip(template, transformed, strict=True)]
    if isinstance(template, tuple):
        if len(template) == 2 and isinstance(transformed, dict):
            return (transformed.get("role", template[0]), transformed.get("content"))
        if not isinstance(transformed, list | tuple) or len(template) != len(transformed):
            raise RemotePrivacyError("gateway_response_shape_mismatch")
        return tuple(_rebuild(original, item) for original, item in zip(template, transformed, strict=True))
    if isinstance(template, str | bytes | int | float | bool) or template is None:
        return transformed
    if not isinstance(transformed, dict):
        raise RemotePrivacyError("gateway_response_shape_mismatch")

    updates = {
        name: transformed[name]
        for name in (
            "content",
            "additional_kwargs",
            "response_metadata",
            "tool_calls",
            "invalid_tool_calls",
            "usage_metadata",
            "name",
            "id",
            "tool_call_id",
        )
        if name in transformed and hasattr(template, name)
    }
    model_copy = getattr(template, "model_copy", None)
    if callable(model_copy):
        return model_copy(update=updates, deep=True)
    cloned = copy.copy(template)
    for name, value in updates.items():
        try:
            setattr(cloned, name, value)
        except (AttributeError, TypeError) as exc:
            raise RemotePrivacyError("message_reconstruction_failed") from exc
    return cloned


def _registration_values(payload: Any) -> list[dict[str, str]]:
    """Extract only schema-typed identities; never infer kinds from prose."""
    registrations: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def walk(value: Any, path: tuple[str, ...] = (), depth: int = 0) -> None:
        if depth > 16 or len(registrations) >= 250:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, (*path, str(key)), depth + 1)
            return
        if isinstance(value, list):
            for child in value:
                walk(child, path, depth + 1)
            return
        if not path or not isinstance(value, str):
            return
        kind = _REGISTRATION_FIELDS.get(path[-1].strip().lower())
        cleaned = value.strip()
        if not kind or not cleaned or len(cleaned) > 4096 or cleaned.casefold() in {"unknown", "none", "null", "n/a"}:
            return
        key = (kind, cleaned)
        if key in seen:
            return
        seen.add(key)
        registrations.append(
            {"kind": kind, "value": cleaned, "source": "soc.structured_message", "role": path[-1][:128]}
        )

    walk(payload)
    return registrations


def _guidance_like(messages: list[Any]) -> Any:
    if messages and isinstance(messages[0], dict):
        return {"role": "system", "content": PRIVACY_SYSTEM_GUIDANCE}
    if messages and isinstance(messages[0], tuple):
        return ("system", PRIVACY_SYSTEM_GUIDANCE)
    from langchain_core.messages import SystemMessage

    return SystemMessage(content=PRIVACY_SYSTEM_GUIDANCE)


def _string_values(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _string_values(child)


class RemotePrivacyBackend:
    """One remote Gateway context shared by one logical SOC workflow."""

    backend_name = "remote"
    is_remote = True
    cache_namespace = ""  # Remote response caching is intentionally disabled.

    def __init__(
        self,
        *,
        tenant_id: str,
        base_url: str,
        api_key: str,
        profile: str = "agentic-soc-v1",
        timeout: float = 30.0,
        ttl_seconds: int = 3600,
        client: Any | None = None,
        client_factory: Callable[..., Any] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        max_attempts: int = 2,
    ) -> None:
        self.tenant_id = tenant_id
        self.base_url = base_url.rstrip("/")
        self.profile = profile
        self.timeout = timeout
        self.ttl_seconds = ttl_seconds
        self._api_key = api_key
        self._client = client
        self._client_factory = client_factory
        self._transport = transport
        self._owns_client = client is None
        self._max_attempts = max(1, max_attempts)
        self._context_id: str | None = None
        self._expires_at: datetime | None = None
        self.policy_version = "unknown"
        self.last_encode_stats: dict[str, int] = {}
        self.last_decode_stats: dict[str, int] = {}
        self._start_lock = asyncio.Lock()
        self._validate()

    @classmethod
    def from_environment(
        cls,
        tenant_id: str,
        *,
        client: Any | None = None,
        client_factory: Callable[..., Any] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> RemotePrivacyBackend:
        try:
            timeout = float(os.getenv("AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS", "30"))
            ttl = int(os.getenv("AISOC_PRIVACY_CONTEXT_TTL_SECONDS", "3600"))
        except ValueError as exc:
            raise RemotePrivacyError("invalid_remote_configuration") from exc
        return cls(
            tenant_id=tenant_id,
            base_url=os.getenv("AISOC_PRIVACY_REMOTE_URL", ""),
            api_key=os.getenv("AISOC_PRIVACY_REMOTE_API_KEY", ""),
            profile=os.getenv("AISOC_PRIVACY_REMOTE_PROFILE", "agentic-soc-v1"),
            timeout=timeout,
            ttl_seconds=ttl,
            client=client,
            client_factory=client_factory,
            transport=transport,
        )

    def _validate(self) -> None:
        try:
            if str(uuid.UUID(self.tenant_id)) != self.tenant_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise RemotePrivacyError("canonical_tenant_uuid_required") from exc
        if not self.base_url.startswith(("http://", "https://")):
            raise RemotePrivacyError("remote_url_required")
        if "@" in self.base_url.split("://", 1)[-1].split("/", 1)[0]:
            raise RemotePrivacyError("remote_url_must_not_embed_credentials")
        if os.getenv("AISOC_ENV", "").strip().lower() == "production" and not self.base_url.startswith("https://"):
            raise RemotePrivacyError("remote_https_required_in_production")
        if not self._api_key:
            raise RemotePrivacyError("remote_service_credential_required")
        if not _PROFILE_RE.fullmatch(self.profile):
            raise RemotePrivacyError("invalid_remote_profile")
        if not 0 < self.timeout <= 600:
            raise RemotePrivacyError("invalid_remote_timeout")
        if not 60 <= self.ttl_seconds <= 86400:
            raise RemotePrivacyError("invalid_context_ttl")

    @property
    def context_trace_id(self) -> str | None:
        if not self._context_id:
            return None
        return hashlib.sha256(self._context_id.encode()).hexdigest()[:16]

    async def start(self) -> RemotePrivacyBackend:
        async with self._start_lock:
            if self._context_id is not None:
                return self
            if self._client is None:
                factory = self._client_factory
                if factory is None:
                    try:
                        from soorin_privacy import AsyncPrivacyClient
                    except ImportError as exc:
                        raise RemotePrivacyError("privacy_sdk_not_installed") from exc
                    factory = AsyncPrivacyClient
                self._client = factory(
                    base_url=self.base_url,
                    api_key=self._api_key,
                    timeout=self.timeout,
                    transport=self._transport,
                )
            started = time.monotonic()
            response = await self._gateway_call(
                "create_context",
                lambda: self._client.create_context(
                    tenant_id=self.tenant_id,
                    profile=self.profile,
                    ttl_seconds=self.ttl_seconds,
                ),
                retry=False,
            )
            if not isinstance(response, dict) or not isinstance(response.get("context_id"), str):
                raise RemotePrivacyError("invalid_gateway_response")
            self._context_id = response["context_id"]
            if response.get("tenant_id") != self.tenant_id or response.get("profile") != self.profile:
                raise RemotePrivacyError("gateway_context_binding_mismatch")
            self.policy_version = str(response.get("policy_version") or "unknown")
            try:
                self._expires_at = datetime.fromisoformat(str(response["expires_at"]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError) as exc:
                raise RemotePrivacyError("invalid_gateway_expiration") from exc
            self._audit("create_context", (time.monotonic() - started) * 1000, {})
            return self

    def _assert_active(self) -> str:
        if self._context_id is None or self._expires_at is None:
            raise RemotePrivacyError("remote_context_not_started")
        now = datetime.now(self._expires_at.tzinfo)
        if now >= self._expires_at:
            raise RemotePrivacyError("remote_context_expired")
        return self._context_id

    async def encode_messages(self, messages: list[Any]) -> list[Any]:
        context_id = self._assert_active()
        wire = [_message_to_wire(message) for message in messages]
        started = time.monotonic()
        result = await self._gateway_call(
            "encode",
            lambda: self._client.encode(
                wire,
                format="messages",
                context_id=context_id,
                profile=self.profile,
                tenant_id=self.tenant_id,
                registrations=_registration_values(wire),
            ),
        )
        payload = result.get("payload") if isinstance(result, dict) else None
        if not isinstance(payload, list) or len(payload) != len(messages):
            raise RemotePrivacyError("gateway_response_shape_mismatch")
        self.last_encode_stats = self._stats(result)
        self.policy_version = str(result.get("policy_version") or self.policy_version)
        self._audit("encode", (time.monotonic() - started) * 1000, self.last_encode_stats)
        rebuilt = [_rebuild(original, transformed) for original, transformed in zip(messages, payload, strict=True)]
        return [_guidance_like(messages), *rebuilt]

    async def encode_http_body(self, body: dict[str, Any]) -> dict[str, Any]:
        """Encode every model-visible raw-HTTP field in one Gateway request."""
        context_id = self._assert_active()
        snapshot = _json_value(body)
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("messages"), list):
            raise RemotePrivacyError("invalid_provider_body")
        started = time.monotonic()
        result = await self._gateway_call(
            "encode",
            lambda: self._client.encode(
                snapshot,
                format="json",
                context_id=context_id,
                profile=self.profile,
                tenant_id=self.tenant_id,
                registrations=_registration_values(snapshot),
            ),
        )
        payload = result.get("payload") if isinstance(result, dict) else None
        if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
            raise RemotePrivacyError("gateway_response_shape_mismatch")
        self.last_encode_stats = self._stats(result)
        self.policy_version = str(result.get("policy_version") or self.policy_version)
        self._audit("encode", (time.monotonic() - started) * 1000, self.last_encode_stats)
        payload["messages"] = [
            {"role": "system", "content": PRIVACY_SYSTEM_GUIDANCE},
            *payload["messages"],
        ]
        return payload

    async def decode_response(self, response: Any) -> Any:
        context_id = self._assert_active()
        snapshot = _json_value(response)
        started = time.monotonic()
        result = await self._gateway_call(
            "decode",
            lambda: self._client.decode(snapshot, context_id=context_id, format="json"),
        )
        if not isinstance(result, dict) or "payload" not in result:
            raise RemotePrivacyError("invalid_gateway_response")
        self.last_decode_stats = self._stats(result)
        self._audit("decode", (time.monotonic() - started) * 1000, self.last_decode_stats)
        if self.last_decode_stats.get("unknown_aliases", 0):
            raise RemotePrivacyError("unknown_provider_alias")
        decoded_payload = result["payload"]
        if self._has_residual_alias(decoded_payload):
            raise RemotePrivacyError("unresolved_provider_alias")
        return _rebuild(response, decoded_payload)

    def _has_residual_alias(self, payload: Any) -> bool:
        for value in _string_values(payload):
            # Any alias-like token left after Decode is unresolved. This also
            # catches provider-corrupted aliases that no longer match the
            # Gateway's exact token grammar.
            if _ALIAS_LIKE_RE.search(value):
                return True
        return False

    @staticmethod
    def _stats(result: dict[str, Any]) -> dict[str, int]:
        stats = result.get("stats")
        if not isinstance(stats, dict):
            return {}
        return {str(key): int(value) for key, value in stats.items() if isinstance(value, int)}

    async def _gateway_call(
        self,
        operation: str,
        call: Callable[[], Awaitable[Any]],
        *,
        retry: bool = True,
    ) -> Any:
        last: BaseException | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                return await call()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - converted to credential-safe typed error
                last = exc
                category, status = _error_category(exc)
                retryable = status in _RETRYABLE_STATUS or category in {"gateway_timeout", "gateway_unavailable"}
                if not retry or not retryable or attempt >= self._max_attempts:
                    logger.warning(
                        "privacy.remote.failed",
                        operation=operation,
                        tenant_id=self.tenant_id,
                        context_trace_id=self.context_trace_id,
                        error_category=category,
                        status_code=status,
                        attempts=attempt,
                    )
                    raise RemotePrivacyError(category, status_code=status) from exc
                await asyncio.sleep(0.05 * attempt)
        raise RemotePrivacyError("gateway_client_error") from last

    def _audit(self, operation: str, latency_ms: float, stats: dict[str, int]) -> None:
        logger.info(
            "privacy.remote.operation",
            operation=operation,
            tenant_id=self.tenant_id,
            context_trace_id=self.context_trace_id,
            profile=self.profile,
            policy_version=self.policy_version,
            latency_ms=round(latency_ms, 2),
            **stats,
        )

    async def aclose(self) -> None:
        client, context_id = self._client, self._context_id
        self._context_id = None
        try:
            if client is not None and context_id is not None:
                try:
                    await self._gateway_call("delete_context", lambda: client.delete_context(context_id))
                except RemotePrivacyError:
                    # Cleanup failure is audited by _gateway_call. It must not
                    # replace the workflow's primary result or exception.
                    pass
        finally:
            if client is not None and self._owns_client:
                try:
                    await client.aclose()
                except Exception:  # noqa: BLE001 - shutdown is best effort
                    logger.warning(
                        "privacy.remote.client_close_failed",
                        tenant_id=self.tenant_id,
                        context_trace_id=self.context_trace_id,
                    )


__all__ = ["RemotePrivacyBackend", "RemotePrivacyError"]
