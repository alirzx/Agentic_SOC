"""IngestClient chunks oversized connector polls under the ingest MaxBatchSize."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.ingest_client import IngestClient


@respx.mock
@pytest.mark.asyncio
async def test_push_events_chunks_above_chunk_size():
    client = IngestClient("http://ingest.test:8080", chunk_size=2)
    route = respx.post("http://ingest.test:8080/v1/ingest/batch").mock(
        return_value=httpx.Response(200, json={"accepted": 2, "rejected": 0})
    )
    events = [{"id": str(i)} for i in range(5)]
    out = await client.push_events(
        tenant_id="00000000-0000-0000-0000-000000000001",
        connector_id="00000000-0000-0000-0000-0000000000c1",
        connector_type="splunk",
        events=events,
    )
    assert out["accepted"] == 6  # 3 chunks * mocked accepted=2
    assert route.call_count == 3
    import json

    sizes = [len(json.loads(call.request.content)["events"]) for call in route.calls]
    assert sizes == [2, 2, 1]


@respx.mock
@pytest.mark.asyncio
async def test_push_events_empty_short_circuits():
    route = respx.post("http://ingest.test:8080/v1/ingest/batch").mock(
        return_value=httpx.Response(200, json={"accepted": 0, "rejected": 0})
    )
    client = IngestClient("http://ingest.test:8080", chunk_size=500)
    out = await client.push_events(
        tenant_id="t",
        connector_id="c",
        connector_type="splunk",
        events=[],
    )
    assert out == {"accepted": 0, "rejected": 0}
    assert route.call_count == 0
