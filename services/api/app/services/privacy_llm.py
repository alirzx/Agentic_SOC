"""Tenant-scoped external LLM egress through independent Privacy Gateway.

This module handles API-service requests, which cannot import the Agents
service's in-process ContextVar. Never log sensitive request/response bodies.
"""
from __future__ import annotations

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
        raise PrivacyEgressError("production_gateway_requires_https" if _production() else "required_gateway_requires_https")
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
    context_id: str | None = None
    async with httpx.AsyncClient(
        base_url=base,
        timeout=httpx.Timeout(timeout),
        headers={"Authorization": f"Bearer {key}"},
        follow_redirects=False,
    ) as gateway:
        async def gateway_post(path: str, request_body: dict[str, Any]) -> dict[str, Any]:
            try:
                response = await gateway.post(path, json=request_body)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("invalid response shape")
                return data
            except (httpx.HTTPError, ValueError) as exc:
                raise PrivacyEgressError("gateway_request_failed") from exc

        try:
            context = await gateway_post(
                "/v1/contexts", {"tenant_id": tenant, "profile": profile, "ttl_seconds": ttl}
            )
            context_id = context.get("context_id")
            if not isinstance(context_id, str) or not context_id.startswith("ctx_"):
                raise PrivacyEgressError("invalid_gateway_context")
            if context.get("tenant_id") != tenant or context.get("profile") != profile:
                raise PrivacyEgressError("gateway_context_binding_mismatch")
            encoded = await gateway_post(
                "/v1/encode",
                {
                    "context_id": context_id,
                    "tenant_id": tenant,
                    "profile": profile,
                    "purpose": "llm-egress",
                    "format": "json",
                    "payload": body,
                    "registrations": [],
                },
            )
            protected = encoded.get("payload")
            if not isinstance(protected, dict) or not isinstance(protected.get("messages"), list):
                raise PrivacyEgressError("invalid_gateway_payload")
            if protected.get("model") != body.get("model"):
                raise PrivacyEgressError("gateway_changed_model")
            for structural_key in ("response_format", "tool_choice", "temperature",
                                   "max_tokens", "max_completion_tokens"):
                if structural_key in body and protected.get(structural_key) != body[structural_key]:
                    raise PrivacyEgressError("gateway_changed_provider_semantics")
            # No fields may be introduced outside the protected request.
            if set(protected) != set(body):
                raise PrivacyEgressError("gateway_changed_body_keys")
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
            )
            restored = decoded.get("payload")
            if not isinstance(restored, dict):
                raise PrivacyEgressError("invalid_decoded_payload")
            stats = decoded.get("stats", {})
            if isinstance(stats, dict) and stats.get("unknown_aliases", 0):
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
