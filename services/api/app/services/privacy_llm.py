"""Tenant-scoped external LLM egress through independent Privacy Gateway.

This module handles API-service requests, which cannot import the Agents
service's in-process ContextVar. Never log sensitive request/response bodies.
"""
from __future__ import annotations

import copy
import json
import os
import re
import uuid
from typing import Any

import httpx

from app.core.airgap import enforce_airgap_for_url


class PrivacyEgressError(RuntimeError):
    """Credential-safe error; never include upstream response text."""


_ALIAS_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:IP_(?:V4|V6)_[A-Z_]+|IP_OPAQUE|HOST|USER|EMAIL|"
    r"ASSET|MAC|SUBNET|DOMAIN|URL_INTERNAL|PATH|TICKET|CASE|REFERENCE|"
    r"PHONE|EMPLOYEE_ID|USER_SID|ORG_ID|AD_GROUP|CLOUD_RESOURCE|"
    r"DEVICE_SERIAL|SPLUNK_INDEX|CRED_[A-Z_]+)_[A-Za-z0-9]{16,48}"
    r"(?![A-Za-z0-9_])",
    re.IGNORECASE,
)

# This is intentionally system-level model guidance, not privacy policy logic.
# Keep its meaning aligned with the Agents privacy guidance: provider-visible
# aliases are valid opaque entity references and must not be reversed or treated
# as suspicious merely because of their syntax.
_PRIVACY_PROVIDER_GUIDANCE = (
    "Some internal SOC identities in this request have been replaced with privacy-preserving "
    "pseudonyms such as USER_*, EMAIL_*, HOST_*, ASSET_*, IP_V4_*, IP_V6_*, IP_OPAQUE_*, and PATH_*.\n\n"
    "Treat each pseudonym as an opaque but stable identity within this analysis. Preserve every "
    "pseudonym exactly when referring to it. Do not decode, guess, reconstruct, abbreviate, truncate, "
    "or infer the original identity. Do not treat pseudonym syntax itself as evidence of maliciousness.\n\n"
    "[REDACTED_SECRET] means a secret was intentionally withheld. Do not guess or reconstruct it."
)


def _required() -> bool:
    return _production() or os.getenv("AISOC_LLM_PRIVACY_REQUIRED", "0").strip().lower() in {
        "1", "true", "yes", "on"
    }


def _production() -> bool:
    return any(os.getenv(key, "").strip().lower() in {"prod", "production"}
               for key in ("AISOC_ENV", "APP_ENV", "ENV", "ENVIRONMENT"))


def _enabled() -> bool:
    return os.getenv("AISOC_LLM_PRIVACY_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}


def _required_config() -> tuple[str, str, str, float, int]:
    if os.getenv("AISOC_PRIVACY_BACKEND", "local").strip().lower() != "remote":
        raise PrivacyEgressError("api_requires_remote_privacy_backend")
    url = os.getenv("AISOC_PRIVACY_REMOTE_URL", "").rstrip("/")
    key = os.getenv("AISOC_PRIVACY_REMOTE_API_KEY", "")
    profile = os.getenv("AISOC_PRIVACY_REMOTE_PROFILE", "agentic-soc-v1")
    try:
        timeout = float(os.getenv("AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS", "30"))
        ttl = int(os.getenv("AISOC_PRIVACY_CONTEXT_TTL_SECONDS", "3600"))
    except ValueError as exc:
        raise PrivacyEgressError("invalid_privacy_config") from exc
    if not url or not key or not profile or not (0 < timeout <= 600) or not (60 <= ttl <= 86400):
        raise PrivacyEgressError("incomplete_privacy_config")
    if "@" in url.split("://")[-1].split("/")[0]:
        raise PrivacyEgressError("gateway_url_contains_credentials")
    if _required() and not url.startswith("https://"):
        error = "production_gateway_requires_https" if _production() else "required_gateway_requires_https"
        raise PrivacyEgressError(error)
    if not (url.startswith("https://") or url.startswith("http://")):
        raise PrivacyEgressError("invalid_gateway_url")
    return url, key, profile, timeout, ttl


def _tenant_uuid(value: str | uuid.UUID | None) -> str:
    if value is None:
        raise PrivacyEgressError("missing_authorized_tenant")
    try:
        parsed = uuid.UUID(str(value))
        return str(parsed)
    except (ValueError, TypeError, AttributeError) as exc:
        raise PrivacyEgressError("invalid_authorized_tenant") from exc


def _valid_stats(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str) and type(count) is int for key, count in value.items()
    )


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


async def safe_chat_post(
    provider: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str],
    body: dict[str, Any],
    tenant_id: str | uuid.UUID | None,
) -> httpx.Response:
    """Encode full provider JSON body, send once, decode complete response.

    A trusted request/DB tenant must be supplied by the caller. Gateway errors
    never trigger a raw provider retry. Caller may use deterministic fallback.
    """
    enforce_airgap_for_url(url)
    if not _enabled():
        if _required():
            raise PrivacyEgressError("production_provider_privacy_disabled")
        return await provider.post(url, headers=headers, json=body)

    tenant = _tenant_uuid(tenant_id)
    base, key, profile, timeout, ttl = _required_config()
    provider_body = copy.deepcopy(body)
    messages = provider_body.get("messages")
    if not isinstance(messages, list):
        raise PrivacyEgressError("invalid_provider_messages")
    provider_body["messages"] = [
        {"role": "system", "content": _PRIVACY_PROVIDER_GUIDANCE},
        *messages,
    ]
    context_id: str | None = None
    async with httpx.AsyncClient(
        base_url=base,
        timeout=httpx.Timeout(timeout),
        headers={"Authorization": f"Bearer {key}"},
        follow_redirects=False,
    ) as gateway:
        async def gateway_post(
            path: str,
            request_body: dict[str, Any],
            *,
            expected_status: int,
        ) -> dict[str, Any]:
            try:
                response = await gateway.post(path, json=request_body)
                if response.status_code != expected_status:
                    raise PrivacyEgressError("gateway_request_failed")
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("invalid response shape")
                return data
            except (httpx.HTTPError, ValueError) as exc:
                raise PrivacyEgressError("gateway_request_failed") from exc

        try:
            context = await gateway_post(
                "/v1/contexts",
                {"tenant_id": tenant, "profile": profile, "ttl_seconds": ttl},
                expected_status=201,
            )
            context_id = context.get("context_id")
            if not _nonempty_string(context_id) or not context_id.startswith("ctx_"):
                raise PrivacyEgressError("invalid_gateway_context")
            if context.get("tenant_id") != tenant or context.get("profile") != profile:
                raise PrivacyEgressError("gateway_context_binding_mismatch")
            if not _nonempty_string(context.get("policy_version")) or not _nonempty_string(
                context.get("expires_at")
            ):
                raise PrivacyEgressError("invalid_gateway_context")
            encoded = await gateway_post(
                "/v1/encode",
                {
                    "context_id": context_id,
                    "tenant_id": tenant,
                    "profile": profile,
                    "purpose": "llm-egress",
                    "format": "json",
                    "payload": provider_body,
                    "registrations": [],
                },
                expected_status=200,
            )
            if encoded.get("context_id") != context_id or encoded.get("format") != "json":
                raise PrivacyEgressError("gateway_encode_binding_mismatch")
            if (
                not _nonempty_string(encoded.get("policy_version"))
                or not _nonempty_string(encoded.get("expires_at"))
                or not _valid_stats(encoded.get("stats"))
            ):
                raise PrivacyEgressError("invalid_gateway_encode_response")
            protected = encoded.get("payload")
            if not isinstance(protected, dict) or not isinstance(protected.get("messages"), list):
                raise PrivacyEgressError("invalid_gateway_payload")
            if protected.get("model") != provider_body.get("model"):
                raise PrivacyEgressError("gateway_changed_model")
            for structural_key in ("response_format", "tool_choice", "temperature",
                                   "max_tokens", "max_completion_tokens"):
                if (
                    structural_key in provider_body
                    and protected.get(structural_key) != provider_body[structural_key]
                ):
                    raise PrivacyEgressError("gateway_changed_provider_semantics")
            # No fields may be introduced outside the protected request.
            if set(protected) != set(provider_body):
                raise PrivacyEgressError("gateway_changed_body_keys")
            protected_messages = protected["messages"]
            if len(protected_messages) != len(provider_body["messages"]):
                raise PrivacyEgressError("gateway_changed_provider_semantics")
            for original, projected in zip(provider_body["messages"], protected_messages, strict=True):
                if not isinstance(original, dict) or not isinstance(projected, dict):
                    raise PrivacyEgressError("gateway_changed_provider_semantics")
                for structural_key in ("role", "name", "tool_call_id"):
                    if original.get(structural_key) != projected.get(structural_key):
                        raise PrivacyEgressError("gateway_changed_provider_semantics")
            response = await provider.post(url, headers=headers, json=protected)
            response.raise_for_status()
            provider_json = response.json()
            decoded = await gateway_post(
                "/v1/decode",
                {
                    "context_id": context_id,
                    "format": "json",
                    "payload": provider_json,
                    "purpose": "llm-response",
                    "reveal_credentials": False,
                },
                expected_status=200,
            )
            if decoded.get("context_id") != context_id or decoded.get("format") != "json":
                raise PrivacyEgressError("gateway_decode_binding_mismatch")
            if not _valid_stats(decoded.get("stats")):
                raise PrivacyEgressError("invalid_gateway_decode_response")
            restored = decoded.get("payload")
            if not isinstance(restored, dict):
                raise PrivacyEgressError("invalid_decoded_payload")
            stats = decoded["stats"]
            if stats.get("unknown_aliases", 0):
                raise PrivacyEgressError("unknown_provider_alias")
            if _ALIAS_RE.search(json.dumps(restored, ensure_ascii=False)):
                raise PrivacyEgressError("unresolved_provider_alias")
            return httpx.Response(
                status_code=response.status_code,
                json=restored,
                request=response.request,
                headers={"content-type": "application/json"},
            )
        except PrivacyEgressError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise PrivacyEgressError("provider_or_decode_failed") from exc
        finally:
            if context_id is not None:
                try:
                    await gateway.delete(f"/v1/contexts/{context_id}")
                except httpx.HTTPError:
                    pass  # bounded TTL remains as secondary cleanup
