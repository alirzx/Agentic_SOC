"""Trusted request-tenant resolution for direct agents-service APIs."""

from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import Request

from app.privacy.context import PrivacyConfigurationError

TENANT_HEADER = "X-Tenant-Id"
TENANT_SIGNATURE_HEADER = "X-AiSOC-Tenant-Signature"
TENANT_SIGNING_KEY_ENV = "AISOC_AGENTS_TENANT_SIGNING_KEY"
ALLOW_UNSIGNED_TENANT_ENV = "AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER"
_SIGNATURE_VERSION = b"aisoc-agents-tenant-v1"


def tenant_signature(tenant_id: str, key: str | bytes) -> str:
    """Return the HMAC signature an authenticated upstream must inject."""
    tenant = str(tenant_id).strip()
    secret = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    if not tenant:
        raise ValueError("tenant_id is required")
    if len(secret) < 32:
        raise ValueError("tenant signing key must contain at least 32 bytes")
    payload = _SIGNATURE_VERSION + b"\x00" + tenant.encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _allow_unsigned_header() -> bool:
    enabled = os.getenv(ALLOW_UNSIGNED_TENANT_ENV, "0").strip().lower() in {"1", "true", "yes", "on"}
    environment = (os.getenv("AISOC_ENV") or os.getenv("ENV") or "development").strip().lower()
    if enabled and environment in {"prod", "production"}:
        raise PrivacyConfigurationError(f"{ALLOW_UNSIGNED_TENANT_ENV} cannot be enabled in production")
    return enabled


def resolve_request_tenant(request: Request) -> str | None:
    """Resolve only authenticated state or an HMAC-authenticated tenant header.

    ``X-Tenant-Id`` alone is browser-controlled and is therefore never trusted
    by default. An authenticating middleware may set
    ``request.state.authenticated_tenant_id``; otherwise the upstream proxy
    must inject ``X-AiSOC-Tenant-Signature`` using the shared signing key.
    """
    state_tenant = str(getattr(request.state, "authenticated_tenant_id", "") or "").strip()
    if state_tenant:
        return state_tenant

    tenant = str(request.headers.get(TENANT_HEADER, "") or "").strip()
    if not tenant:
        return None

    raw_key = os.getenv(TENANT_SIGNING_KEY_ENV, "")
    supplied = str(request.headers.get(TENANT_SIGNATURE_HEADER, "") or "").strip()
    if raw_key and supplied:
        try:
            expected = tenant_signature(tenant, raw_key)
        except ValueError as exc:
            raise PrivacyConfigurationError(str(exc)) from exc
        if hmac.compare_digest(supplied.casefold(), expected):
            return tenant
        return None

    if _allow_unsigned_header():
        return tenant
    return None

