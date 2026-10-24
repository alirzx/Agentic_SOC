"""Regression coverage for canonical tenant identity at protected LLM egress."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from app.api import copilot
from app.api import triage as triage_api
from app.privacy.context import PrivacyConfigurationError, privacy_context
from app.privacy.gateway import PrivacyGateway
from app.privacy.tenant import (
    CANONICAL_SEED_TENANT_ID,
    resolve_canonical_tenant,
    resolve_request_tenant,
    resolve_tenant_for_llm,
    tenant_signature,
)
from app.workers import fused_alert_consumer as worker_module
from app.workers.fused_alert_consumer import FusedAlertTriageWorker, build_state
from fastapi import BackgroundTasks
from starlette.requests import Request

KEY = "canonical-tenant-privacy-key-0123456789"
SIGNING_KEY = "canonical-tenant-signing-key-0123456"
TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")
HOST = "endpoint01.corp.synthetic.test"


class _TenantConnection:
    def __init__(
        self,
        *,
        slugs: dict[str, uuid.UUID] | None = None,
        names: dict[str, list[uuid.UUID]] | None = None,
        canonical_exists: bool = False,
        tenants: list[uuid.UUID] | None = None,
    ) -> None:
        self.slugs = slugs or {}
        self.names = names or {}
        self.canonical_exists = canonical_exists
        self.tenants = tenants or []

    async def fetchrow(self, sql: str, *args):
        if "WHERE id = $1" in sql:
            return {"id": CANONICAL_SEED_TENANT_ID} if self.canonical_exists else None
        if "slug = $1" in sql:
            tenant_id = self.slugs.get(str(args[0]))
            return {"id": tenant_id} if tenant_id is not None else None
        return None

    async def fetch(self, sql: str, *args):
        if "name = $1" in sql:
            return [{"id": tenant_id} for tenant_id in self.names.get(str(args[0]), [])[:2]]
        if "FROM tenants LIMIT 2" in sql:
            return [{"id": tenant_id} for tenant_id in self.tenants[:2]]
        return []


def _alias(tenant_id: str) -> dict[str, str]:
    gateway = PrivacyGateway(tenant_id=tenant_id, token_key=KEY)
    return gateway.project_value({"hostname": HOST, "user": "alice"})


def _signed_request(tenant_ref: str) -> Request:
    signature = tenant_signature(tenant_ref, SIGNING_KEY)
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (b"x-tenant-id", tenant_ref.encode()),
                (b"x-aisoc-tenant-signature", signature.encode()),
            ],
        }
    )


def _fused(tenant_ref: str) -> dict:
    return {
        "id": "33333333-3333-3333-3333-333333333333",
        "tenant_id": tenant_ref,
        "incident_id": "44444444-4444-4444-4444-444444444444",
        "alert": {
            "id": "33333333-3333-3333-3333-333333333333",
            "tenant_id": tenant_ref,
            "title": "Synthetic canonical tenant alert",
            "hostname": HOST,
            "username": "alice",
        },
    }


@pytest.mark.asyncio
async def test_slug_name_and_uuid_share_one_privacy_namespace() -> None:
    connection = _TenantConnection(
        slugs={"tenant-a": TENANT_A},
        names={"Tenant A": [TENANT_A]},
    )

    from_slug = await resolve_canonical_tenant("tenant-a", connection=connection)
    from_name = await resolve_canonical_tenant("Tenant A", connection=connection)
    from_uuid = await resolve_canonical_tenant(str(TENANT_A), connection=connection)

    assert from_slug == from_name == from_uuid == str(TENANT_A)
    assert _alias(from_slug) == _alias(from_name) == _alias(from_uuid)


@pytest.mark.asyncio
async def test_default_seed_sole_tenant_and_ambiguity_semantics() -> None:
    assert await resolve_canonical_tenant(
        "default",
        connection=_TenantConnection(canonical_exists=True, tenants=[TENANT_A, TENANT_B]),
    ) == str(CANONICAL_SEED_TENANT_ID)
    assert await resolve_canonical_tenant(
        "default",
        connection=_TenantConnection(tenants=[TENANT_A]),
    ) == str(TENANT_A)
    assert (
        await resolve_canonical_tenant(
            "default",
            connection=_TenantConnection(tenants=[TENANT_A, TENANT_B]),
        )
        is None
    )


@pytest.mark.asyncio
async def test_ambiguous_tenant_name_is_not_selected() -> None:
    connection = _TenantConnection(names={"Shared Name": [TENANT_A, TENANT_B]})
    assert await resolve_canonical_tenant("Shared Name", connection=connection) is None


@pytest.mark.asyncio
async def test_signed_api_and_fused_worker_reach_same_tenant_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", SIGNING_KEY)
    connection = _TenantConnection(slugs={"tenant-a": TENANT_A})

    trusted_api_ref = resolve_request_tenant(_signed_request("tenant-a"))
    api_tenant = await resolve_canonical_tenant(trusted_api_ref, connection=connection)
    worker_tenant = await resolve_canonical_tenant(_fused("tenant-a")["tenant_id"], connection=connection)
    worker_state = build_state(_fused("tenant-a"), canonical_tenant_id=worker_tenant)

    assert api_tenant == worker_tenant == str(TENANT_A)
    assert worker_state is not None
    assert worker_state.tenant_id == TENANT_A
    assert _alias(api_tenant) == _alias(str(worker_state.tenant_id))


@pytest.mark.asyncio
async def test_unknown_signed_api_tenant_has_zero_provider_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", KEY)
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", SIGNING_KEY)
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-provider-key")

    async def _unresolved(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.privacy.tenant.resolve_canonical_tenant", _unresolved)
    copilot._CONVERSATIONS.clear()
    with patch("httpx.AsyncClient", side_effect=AssertionError("provider must not be constructed")) as client:
        response = await copilot.chat(
            copilot.CopilotChatRequest(message=f"Investigate hostname={HOST}"),
            _signed_request("unknown-tenant"),
        )

    client.assert_not_called()
    assert response.reply.content in copilot._SYNTHETIC_REPLIES


@pytest.mark.asyncio
async def test_triage_api_queues_canonical_tenant_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", KEY)

    async def _canonical(*_args, **_kwargs):
        return str(TENANT_A)

    monkeypatch.setattr("app.privacy.tenant.resolve_canonical_tenant", _canonical)
    background = BackgroundTasks()
    response = await triage_api.launch_triage(
        "CASE-CANONICAL-TENANT",
        triage_api.TriageRequest(tenant_id="tenant-a"),
        background,
    )

    queued_state = background.tasks[0].args[2]
    assert queued_state.tenant_id == TENANT_A
    triage_api._triage_runs.pop(response.run_id, None)


@pytest.mark.asyncio
async def test_unknown_worker_tenant_falls_back_before_llm_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", KEY)

    async def _unresolved(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.privacy.tenant.resolve_canonical_tenant", _unresolved)
    monkeypatch.setattr(worker_module, "resolve_llm_config", AsyncMock(side_effect=AssertionError("provider setup reached")))
    monkeypatch.setattr(worker_module, "run_auto_triage", AsyncMock(side_effect=AssertionError("provider call reached")))
    worker = FusedAlertTriageWorker(bootstrap_servers="unused")

    result = await worker.triage(_fused("unknown-tenant"))

    worker_module.resolve_llm_config.assert_not_awaited()
    worker_module.run_auto_triage.assert_not_awaited()
    assert result is not None
    assert result["tier"] == "deterministic"


@pytest.mark.asyncio
async def test_repeated_resolution_is_stable_and_tenants_remain_separate() -> None:
    connection = _TenantConnection(slugs={"tenant-a": TENANT_A, "tenant-b": TENANT_B})
    first = await resolve_canonical_tenant("tenant-a", connection=connection)
    second = await resolve_canonical_tenant("tenant-a", connection=connection)
    other = await resolve_canonical_tenant("tenant-b", connection=connection)

    assert first == second == str(TENANT_A)
    assert other == str(TENANT_B)
    assert _alias(first)["user"] != _alias(other)["user"]


def test_nested_canonical_context_reuses_session_and_reverse_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", KEY)

    with privacy_context(str(TENANT_A)) as outer:
        assert outer is not None
        projected = outer.gateway.project_value({"hostname": HOST})
        with privacy_context(str(TENANT_A)) as inner:
            assert inner is outer
            assert inner.gateway.process_response(projected) == {"hostname": HOST}


def test_privacy_context_rejects_uncanonicalized_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "1")
    monkeypatch.setenv("AISOC_PRIVACY_TOKEN_KEY", KEY)

    with pytest.raises(PrivacyConfigurationError, match="canonical tenant UUID"):
        with privacy_context("tenant-a"):
            pass


@pytest.mark.asyncio
async def test_privacy_off_preserves_unresolved_tenant_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_LLM_PRIVACY_ENABLED", "0")

    assert await resolve_tenant_for_llm("tenant-a") == "tenant-a"
    with privacy_context("tenant-a") as session:
        assert session is None
