"""Credential-safe tenant authentication for API-to-Agents requests."""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid

TENANT_SIGNING_KEY_ENV = "AISOC_AGENTS_TENANT_SIGNING_KEY"
TENANT_HEADER = "X-Tenant-Id"
TENANT_SIGNATURE_HEADER = "X-AiSOC-Tenant-Signature"
_SIGNATURE_VERSION = b"aisoc-agents-tenant-v1"


class AgentsTenantAuthError(RuntimeError):
    """Safe configuration error that never includes signing-key material."""


def signed_tenant_headers(tenant_id: str | uuid.UUID) -> dict[str, str]:
    """Return the headers Agents validates for one authenticated API tenant."""
    try:
        tenant = str(uuid.UUID(str(tenant_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AgentsTenantAuthError("invalid_agents_tenant") from exc

    secret = os.getenv(TENANT_SIGNING_KEY_ENV, "").encode("utf-8")
    if len(secret) < 32:
        raise AgentsTenantAuthError("agents_tenant_signing_key_not_configured")
    payload = _SIGNATURE_VERSION + b"\x00" + tenant.encode("utf-8")
    signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return {
        TENANT_HEADER: tenant,
        TENANT_SIGNATURE_HEADER: signature,
    }


def tkg_grant(tenant_id: uuid.UUID, resource_id: uuid.UUID, *, case: bool = False) -> str:
    key = os.getenv(TENANT_SIGNING_KEY_ENV, "").encode()
    if len(key) < 32:
        raise AgentsTenantAuthError("agents_tenant_signing_key_not_configured")
    purpose = "tkg-case-v1" if case else "tkg-read-v1"
    return hmac.digest(key, f"{purpose}/{tenant_id}/{resource_id}".encode(), "sha256").hex()


__all__ = ["AgentsTenantAuthError", "signed_tenant_headers"]
