"""API-to-Agents tenant assertions use the Agents-compatible HMAC contract."""

from __future__ import annotations

import hashlib
import hmac
import uuid

import pytest

from app.services.agents_tenant_auth import AgentsTenantAuthError, signed_tenant_headers


def test_signed_tenant_headers_are_canonical_and_agents_compatible(monkeypatch) -> None:
    tenant = uuid.UUID("11111111-1111-1111-1111-111111111111")
    key = "synthetic-signing-key-0123456789abcdef"
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", key)

    headers = signed_tenant_headers(tenant)
    expected = hmac.new(
        key.encode(),
        b"aisoc-agents-tenant-v1\x00" + str(tenant).encode(),
        hashlib.sha256,
    ).hexdigest()

    assert headers == {
        "X-Tenant-Id": str(tenant),
        "X-AiSOC-Tenant-Signature": expected,
    }


@pytest.mark.parametrize("key", ["", "too-short"])
def test_missing_or_short_signing_key_fails_without_exposing_key(monkeypatch, key) -> None:
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", key)
    with pytest.raises(AgentsTenantAuthError, match="signing_key_not_configured") as raised:
        signed_tenant_headers("11111111-1111-1111-1111-111111111111")
    assert key not in str(raised.value) or not key
