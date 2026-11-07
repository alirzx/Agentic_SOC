"""Tests for the internal analyst-feedback endpoint (Runbook control plane).

The endpoint is the only way analyst feedback reaches outcome memory, so the
tests cover both halves of the contract: it refuses unauthenticated callers, and
it reports honestly whether a prior was actually updated.
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from app.api.outcomes import OutcomeFeedbackIn, post_outcome_feedback
from app.privacy.tenant import tenant_signature
from fastapi import HTTPException
from starlette.requests import Request

SIGNING_KEY = "runbook-feedback-signing-key-0123456789"
TENANT = str(uuid.UUID("11111111-1111-1111-1111-111111111111"))


def _request(*, tenant: str = TENANT, signature: str | None = None) -> Request:
    headers = [(b"x-tenant-id", tenant.encode())]
    if signature is not None:
        headers.append((b"x-aisoc-tenant-signature", signature.encode()))
    return Request({"type": "http", "method": "POST", "path": "/", "headers": headers})


@pytest.fixture(autouse=True)
def _signing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AGENTS_TENANT_SIGNING_KEY", SIGNING_KEY)
    # Never let an unsigned header through, even on a dev machine running these tests.
    monkeypatch.delenv("AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER", raising=False)
    monkeypatch.setenv("AISOC_ENV", "production")
    assert os.environ["AISOC_AGENTS_TENANT_SIGNING_KEY"] == SIGNING_KEY


@pytest.mark.asyncio
async def test_rejects_unsigned_tenant_header() -> None:
    with patch("app.api.outcomes.record_analyst_feedback", new_callable=AsyncMock) as recorder:
        with pytest.raises(HTTPException) as exc:
            await post_outcome_feedback(
                OutcomeFeedbackIn(signature="sig-1", feedback="good"),
                _request(),
            )
    assert exc.value.status_code == 401
    recorder.assert_not_awaited()


@pytest.mark.asyncio
async def test_rejects_bad_signature() -> None:
    with patch("app.api.outcomes.record_analyst_feedback", new_callable=AsyncMock) as recorder:
        with pytest.raises(HTTPException) as exc:
            await post_outcome_feedback(
                OutcomeFeedbackIn(signature="sig-1", feedback="good"),
                _request(signature="deadbeef"),
            )
    assert exc.value.status_code == 401
    recorder.assert_not_awaited()


@pytest.mark.asyncio
async def test_forwards_signed_feedback_and_reports_update() -> None:
    with patch(
        "app.api.outcomes.record_analyst_feedback",
        new_callable=AsyncMock,
        return_value={"signature": "sig-1", "confidence": 0.60},
    ) as recorder:
        response = await post_outcome_feedback(
            OutcomeFeedbackIn(signature="sig-1", feedback="poor", alert_id=None),
            _request(signature=tenant_signature(TENANT, SIGNING_KEY)),
        )

    assert response == {"updated": True}
    recorder.assert_awaited_once()
    args, kwargs = recorder.await_args
    assert args[0] == TENANT
    assert args[1] == "sig-1"
    assert kwargs["feedback"] == "poor"


@pytest.mark.asyncio
async def test_reports_no_update_when_prior_missing() -> None:
    """No prior => honest ``updated: false``, never a fake success."""
    with patch(
        "app.api.outcomes.record_analyst_feedback",
        new_callable=AsyncMock,
        return_value={},
    ):
        response = await post_outcome_feedback(
            OutcomeFeedbackIn(signature="unknown-signature", feedback="good"),
            _request(signature=tenant_signature(TENANT, SIGNING_KEY)),
        )

    assert response == {"updated": False}
