from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import tkg_knowledge
from app.api.v1.endpoints import cases


def response(value):
    return Mock(scalar_one_or_none=Mock(return_value=value))


def user(*, explicit=True):
    return SimpleNamespace(tenant_id=uuid4(), explicit_workspace=explicit, require_permission=Mock())


@pytest.mark.asyncio
async def test_coverage_requires_workspace_before_touching_database():
    db = AsyncMock()
    with pytest.raises(HTTPException) as error:
        await tkg_knowledge.case_coverage(uuid4(), db, user(explicit=False))
    assert error.value.status_code == 403
    db.execute.assert_not_called()


@pytest.mark.asyncio
async def test_coverage_checks_workspace_ownership_and_keeps_delivery_states_distinct():
    owner, resource = user(), uuid4()
    mapping = dict(alerts=2, eligible_alerts=2, configured_bindings=1, enabled_bindings=1,
                   covered_bindings=1, accepted_receipts=2, recoverable_receipts=0,
                   delivery_counts={"pending_materialization": 1, "bound": 1}, last_updated=None)
    rows = Mock(mappings=Mock(return_value=Mock(one=Mock(return_value=mapping))))
    db = SimpleNamespace(execute=AsyncMock(side_effect=[response(1), rows]))
    result = await tkg_knowledge.case_coverage(resource, db, owner)
    assert result.delivery_counts == {"pending_materialization": 1, "bound": 1}
    assert result.accepted_receipts == 2
    owner.require_permission.assert_called_once_with("cases:read")
    for call in db.execute.await_args_list:
        assert call.args[1] == {"id": resource, "tenant": owner.tenant_id}
        assert "tenant_id" in str(call.args[0])


@pytest.mark.asyncio
async def test_run_history_checks_actual_scope_and_omits_private_properties(monkeypatch):
    owner, case, run_id, kb, fact = user(), uuid4(), uuid4(), uuid4(), uuid4()
    started_at = datetime.now(UTC)
    fetch = AsyncMock(return_value=SimpleNamespace(id=run_id, case_id=case, started_at=started_at, status="completed"))
    monkeypatch.setattr(tkg_knowledge, "_fetch_run", fetch)
    entry = {"resource_kind": "case", "resource_id": str(case), "history": {
        "profile": "standard", "historical_status": "partial", "raw_tool_payload": "must not return",
        "facts": [{"id": str(fact), "kb_id": str(kb), "raw_text": "must not return"}],
    }}
    db = SimpleNamespace(execute=AsyncMock(side_effect=[response(1), response(entry)]))
    result = await tkg_knowledge.run_history(run_id, case, "case", db, owner)
    fetch.assert_awaited_once_with(db, run_id, owner.tenant_id)
    assert result.history.facts[0].id == fact
    assert "must not return" not in result.model_dump_json()
    entry["resource_id"] = str(uuid4())
    db.execute.side_effect = [response(1), response(entry)]
    with pytest.raises(HTTPException) as denied:
        await tkg_knowledge.run_history(run_id, case, "case", db, owner)
    assert denied.value.status_code == 404
    db.execute.side_effect = [response(1), response(None)]
    old_run = await tkg_knowledge.run_history(run_id, case, "case", db, owner)
    assert old_run.history is None and old_run.run_id == run_id


@pytest.mark.asyncio
async def test_legacy_case_proxy_refuses_a_run_from_another_case(monkeypatch):
    owner, case_id, run_id = user(), uuid4(), uuid4()
    db = SimpleNamespace(execute=AsyncMock(return_value=response(1)))
    proxy = AsyncMock(return_value=Mock(status_code=200, json=Mock(return_value={"case_id": str(uuid4())})))
    monkeypatch.setattr(cases, "_agents_proxy", proxy)
    with pytest.raises(HTTPException) as denied:
        await cases.case_investigation_run(str(case_id), str(run_id), owner, db)
    assert denied.value.status_code == 404
    proxy.assert_awaited_once_with("GET", f"/api/v1/investigations/{run_id}", tenant_id=owner.tenant_id)
