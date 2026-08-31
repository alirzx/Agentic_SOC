"""Tenant isolation for evaluation API."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.agentic_evaluation import get_evaluation, list_evaluations


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="analyst",
        email="analyst@example.com",
    )


@pytest.mark.asyncio
async def test_list_evaluations_filters_tenant() -> None:
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    db.execute = AsyncMock(return_value=result)
    user = _user()
    rows = await list_evaluations(db=db, current_user=user, limit=50)
    assert rows == []
    stmt = db.execute.await_args.args[0]
    assert "tenant_id" in str(stmt.compile()).lower()


@pytest.mark.asyncio
async def test_get_evaluation_404_other_tenant() -> None:
    from fastapi import HTTPException

    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=result)
    with pytest.raises(HTTPException) as exc:
        await get_evaluation(run_id=uuid.uuid4(), db=db, current_user=_user())
    assert exc.value.status_code == 404
