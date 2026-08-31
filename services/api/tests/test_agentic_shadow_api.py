"""Tenant isolation for GET /api/v1/soc/agentic/shadow-runs."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.agentic_shadow import get_shadow_run, list_shadow_runs
from fastapi import HTTPException


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="analyst",
        email="analyst@example.com",
    )


@pytest.mark.asyncio
async def test_list_shadow_runs_filters_by_caller_tenant() -> None:
    db = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    db.execute = AsyncMock(return_value=result)
    user = _user()
    rows = await list_shadow_runs(db=db, current_user=user, status_filter=None, limit=50)
    assert rows == []
    stmt = db.execute.await_args.args[0]
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": False}))
    assert "tenant_id" in compiled.lower()


@pytest.mark.asyncio
async def test_get_shadow_run_404_for_other_tenant() -> None:
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=result)
    with pytest.raises(HTTPException) as exc:
        await get_shadow_run(run_id=uuid.uuid4(), db=db, current_user=_user())
    assert exc.value.status_code == 404
