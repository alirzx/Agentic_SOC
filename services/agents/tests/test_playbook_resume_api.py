"""HTTP contract for ``POST /api/v1/playbooks/runs/{run_id}/resume``.

The control-plane API is the only caller. What matters here is that the endpoint
cannot be driven by a browser (no tenant signature ⇒ 401), cannot be used to
probe another tenant's runs (unknown and foreign are both 404), refuses a run
that is not parked (409), and refuses to pretend the surface works when the flag
is off (503 rather than 404).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.api.playbooks import router as playbooks_router  # noqa: E402
from app.playbook import Playbook, PlaybookStep, run_store  # noqa: E402
from app.playbook.store import PlaybookStore  # noqa: E402
from app.privacy.tenant import TENANT_SIGNING_KEY_ENV, tenant_signature  # noqa: E402

TENANT = "00000000-0000-0000-0000-000000000001"
RUN_ID = "11111111-1111-4111-8111-111111111111"
KEY = "test-tenant-signing-key-that-is-long-enough"


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv(TENANT_SIGNING_KEY_ENV, KEY)
    monkeypatch.setenv("AISOC_PLAYBOOK_RESUME", "1")
    app = FastAPI()
    app.include_router(playbooks_router)
    return TestClient(app)


def _headers() -> dict[str, str]:
    return {
        "X-Tenant-Id": TENANT,
        "X-AiSOC-Tenant-Signature": tenant_signature(TENANT, KEY),
    }


def _row(**overrides: Any) -> dict[str, Any]:
    base = {
        "id": RUN_ID,
        "status": "pending_approval",
        "playbook_snapshot": {"name": "containment", "steps": [{"id": "s1", "name": "noop", "type": "http"}]},
        "trigger_context": {},
        "context": {},
        "step_results": [],
        "next_step_index": 1,
        "gate_step_id": "gate",
        "gate_step_name": "Isolate host",
        "started_at": "2026-10-29T10:00:00+00:00",
        "error": None,
    }
    base.update(overrides)
    return base


def test_resume_requires_a_tenant_signature(client: TestClient) -> None:
    response = client.post(f"/api/v1/playbooks/runs/{RUN_ID}/resume", json={"decision": "approve"})
    assert response.status_code == 401


def test_resume_is_disabled_unless_the_flag_is_on(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AISOC_PLAYBOOK_RESUME", "0")
    response = client.post(
        f"/api/v1/playbooks/runs/{RUN_ID}/resume",
        json={"decision": "approve"},
        headers=_headers(),
    )
    # 503, not 404: the surface is off, the run may well exist.
    assert response.status_code == 503


def test_unknown_run_is_not_found(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_store, "load_run", AsyncMock(return_value=None))
    response = client.post(
        f"/api/v1/playbooks/runs/{RUN_ID}/resume",
        json={"decision": "approve"},
        headers=_headers(),
    )
    assert response.status_code == 404


def test_a_run_that_is_not_parked_conflicts(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_store, "load_run", AsyncMock(return_value=_row(status="completed")))
    response = client.post(
        f"/api/v1/playbooks/runs/{RUN_ID}/resume",
        json={"decision": "approve"},
        headers=_headers(),
    )
    assert response.status_code == 409
    assert "completed" in response.json()["detail"]


def test_reject_reports_a_cancelled_run(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(run_store, "load_run", AsyncMock(return_value=_row()))
    monkeypatch.setattr(run_store, "mark_decided", AsyncMock(return_value=True))
    monkeypatch.setattr(run_store, "persist_run", AsyncMock(return_value=True))

    response = client.post(
        f"/api/v1/playbooks/runs/{RUN_ID}/resume",
        json={"decision": "reject", "actor": "lead@example.com"},
        headers=_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "cancelled"
    assert body["resumed"] is False


def test_invalid_decision_is_rejected_by_schema(client: TestClient) -> None:
    response = client.post(
        f"/api/v1/playbooks/runs/{RUN_ID}/resume",
        json={"decision": "maybe"},
        headers=_headers(),
    )
    assert response.status_code == 422


def test_cross_tenant_run_is_indistinguishable_from_missing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``load_run`` is tenant-scoped; the endpoint must not answer differently."""
    scoped: list[tuple[str, str]] = []

    async def _load(run_id: str, tenant_ref: str) -> dict[str, Any] | None:
        scoped.append((run_id, tenant_ref))
        return None

    monkeypatch.setattr(run_store, "load_run", _load)

    response = client.post(
        f"/api/v1/playbooks/runs/{RUN_ID}/resume",
        json={"decision": "approve"},
        headers=_headers(),
    )

    assert response.status_code == 404
    assert scoped == [(RUN_ID, TENANT)]


def test_store_update_revalidates_step_dicts(tmp_path: Path) -> None:
    """Updating a playbook with raw step dicts must keep Pydantic model types intact."""
    store = PlaybookStore(store_dir=tmp_path)
    pb = Playbook(
        id="playbook-1",
        name="demo",
        steps=[PlaybookStep(id="s1", name="notify", type="notify")],
    )
    store._playbooks[pb.id] = pb

    updated = store.update(
        pb.id,
        {"steps": [{"id": "s2", "name": "block", "type": "block_ip"}]},
    )

    assert updated is not None
    assert isinstance(updated.steps[0], PlaybookStep)
    assert updated.steps[0].type.value == "block_ip"
