"""Small deterministic tests with no database, network, or model dependencies."""

from contextlib import asynccontextmanager
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

from app.services.tkg import reconcile, worker


def test_lease_settings_keep_fencing_after_http_deadlines():
    assert worker.WorkerSettings().lease_seconds == 60
    with pytest.raises(ValidationError, match="both HTTP requests"):
        worker.WorkerSettings(request_timeout_seconds=30)
    with pytest.raises(ValidationError, match="both database operations"):
        reconcile.Settings(lease_seconds=29)


@pytest.mark.asyncio
async def test_overlong_success_is_distinct_from_permanent_conflict():
    for status, content, code in [(200, b" " * 1048577, "response_too_large"), (409, b" " * 4097, "http_409")]:
        def response(request):
            return httpx.Response(status, content=content)

        async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
            with pytest.raises(worker.DeliveryError, match=code):
                await worker.request_json(client, "POST", "https://fixture.invalid", "fixture")
    assert worker.receipt_state("failed", "failed_recoverable") == "pending_materialization"
    assert worker.receipt_state("quarantined", "failed_recoverable") == "quarantined"


class Pool:
    @asynccontextmanager
    async def acquire(self):
        yield self


@pytest.mark.asyncio
async def test_malformed_binding_only_defers_its_receipt():
    row = {"tenant_id": UUID(int=1), "binding_id": UUID(int=2), "id": UUID(int=3),
           "receipt_id": UUID(int=4), "reconcile_fence": 7, "reconcile_failures": 1}

    class BindingPool(Pool):
        async def fetchrow(self, query, *args):
            return {"id": row["binding_id"], "enabled": True}

        async def execute(self, query, *args):
            assert args[:6] == (row["id"], "pending_materialization", None, None, "receipt_binding_unavailable", 2)
            assert args[-1] == row["reconcile_fence"]
            return "UPDATE 1"

    await reconcile.fetch_status(BindingPool(), None, row, reconcile.Settings())


@pytest.mark.asyncio
async def test_a_slow_poll_wave_cannot_reclaim_an_already_seen_row(monkeypatch):
    due = [{"id": UUID(int=1)}, {"id": UUID(int=2)}]

    class DuePool(Pool):
        async def fetch(self, query, size, lease, excluded):
            assert "d.id <> ALL($3::uuid[])" in query
            return [row for row in due if row["id"] not in excluded][:size]

        async def fetchrow(self, query):
            return {"pending": 2, "oldest": 10}

    seen = []

    async def poll(pool, http, row, settings):
        seen.append(row["id"])

    monkeypatch.setattr(reconcile, "fetch_status", poll)
    await reconcile.reconcile_batch(DuePool(), None, reconcile.Settings())
    assert seen == [row["id"] for row in due]
