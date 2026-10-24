"""Trusted request-tenant resolution for direct agents-service APIs."""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from typing import Any

from fastapi import Request

from app.privacy.context import PrivacyConfigurationError, privacy_enabled

TENANT_HEADER = "X-Tenant-Id"
TENANT_SIGNATURE_HEADER = "X-AiSOC-Tenant-Signature"
TENANT_SIGNING_KEY_ENV = "AISOC_AGENTS_TENANT_SIGNING_KEY"
ALLOW_UNSIGNED_TENANT_ENV = "AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER"
_SIGNATURE_VERSION = b"aisoc-agents-tenant-v1"

# Stable seed tenant created by the platform's initial migration. A caller may
# use the logical ``default`` placeholder, but the Privacy Gateway must only
# ever receive this (or another database-authoritative) UUID representation.
CANONICAL_SEED_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_PLACEHOLDER_TENANT_REFS = frozenset({"", "default"})


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
    environments = {os.getenv(name, "").strip().lower() for name in ("AISOC_ENV", "ENV", "ENVIRONMENT")}
    if enabled and environments.intersection({"prod", "production"}):
        raise PrivacyConfigurationError(f"{ALLOW_UNSIGNED_TENANT_ENV} cannot be enabled in production")
    return enabled


def normalize_tenant_uuid(tenant_ref: Any) -> str | None:
    """Return the canonical string form of an explicit UUID, if supplied."""
    try:
        return str(uuid.UUID(str(tenant_ref).strip()))
    except (AttributeError, ValueError, TypeError):
        return None


def _row_tenant_uuid(row: Any) -> str | None:
    if not row:
        return None
    try:
        value = row["id"]
    except (KeyError, TypeError):
        return None
    return normalize_tenant_uuid(value)


async def _resolve_with_connection(connection: Any, tenant_ref: str) -> str | None:
    explicit = normalize_tenant_uuid(tenant_ref)
    if explicit is not None:
        return explicit

    ref = str(tenant_ref or "").strip()
    if ref.casefold() in _PLACEHOLDER_TENANT_REFS:
        canonical = await connection.fetchrow(
            "SELECT id FROM tenants WHERE id = $1",
            CANONICAL_SEED_TENANT_ID,
        )
        canonical_id = _row_tenant_uuid(canonical)
        if canonical_id is not None:
            return canonical_id
        tenants = await connection.fetch("SELECT id FROM tenants LIMIT 2")
        if len(tenants) == 1:
            return _row_tenant_uuid(tenants[0])
        return None

    # Slugs are unique in the platform schema, so they are authoritative.
    slug = await connection.fetchrow("SELECT id FROM tenants WHERE slug = $1", ref)
    slug_id = _row_tenant_uuid(slug)
    if slug_id is not None:
        return slug_id

    # Names are supported for compatibility, but unlike slugs are not unique.
    # Refuse an ambiguous name rather than choosing an arbitrary tenant.
    names = await connection.fetch("SELECT id FROM tenants WHERE name = $1 LIMIT 2", ref)
    if len(names) == 1:
        return _row_tenant_uuid(names[0])
    return None


async def resolve_canonical_tenant(
    tenant_ref: str | uuid.UUID | None,
    *,
    connection: Any | None = None,
    pool: Any | None = None,
) -> str | None:
    """Resolve UUID/slug/name/default to one database-authoritative UUID string.

    Explicit UUIDs need no database round trip. Other references require the
    tenants table; absence or ambiguity returns ``None`` and never invents a
    privacy namespace.
    """
    explicit = normalize_tenant_uuid(tenant_ref)
    if explicit is not None:
        return explicit

    ref = str(tenant_ref or "").strip()
    if connection is not None:
        return await _resolve_with_connection(connection, ref)

    try:
        if pool is None:
            # Lazy import avoids making the lightweight request-trust helper
            # eagerly import the investigator/LangGraph package.
            from app.investigator import ledger as ledger_module  # noqa: PLC0415

            pool = await ledger_module.get_pool()
        if pool is None:
            return None
        async with pool.acquire() as acquired:
            return await _resolve_with_connection(acquired, ref)
    except Exception:  # noqa: BLE001 - callers decide fail-closed vs fallback
        return None


async def resolve_tenant_for_llm(
    tenant_ref: str | uuid.UUID | None,
    *,
    allow_default: bool = False,
    pool: Any | None = None,
) -> str:
    """Canonicalize an outer-workflow tenant before protected LLM execution.

    Privacy-enabled egress fails closed when the trusted reference cannot be
    resolved. Privacy-off workflows retain their prior string/default behavior
    when the tenant database is unavailable.
    """
    raw = str(tenant_ref or "").strip()
    privacy_on = privacy_enabled()
    if not raw and not allow_default:
        if privacy_on:
            raise PrivacyConfigurationError("trusted tenant_id is required for protected LLM egress")
        return raw

    reference = raw or "default"
    if not privacy_on:
        return normalize_tenant_uuid(reference) or reference

    canonical = await resolve_canonical_tenant(reference, pool=pool)
    if canonical is not None:
        return canonical

    raise PrivacyConfigurationError(
        "tenant reference could not be resolved to a canonical UUID for protected LLM egress"
    )


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
