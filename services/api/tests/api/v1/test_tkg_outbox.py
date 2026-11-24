"""Synthetic rows in a disposable Postgres schema. TKG transport is mocked."""
import hashlib
import json
import os
from argparse import Namespace
from pathlib import Path
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
import pytest_asyncio

from app.services.tkg.binding import Binding, BindingError
from app.services.tkg.projection import freeze
from app.services.tkg.worker import backfill, deliver, receipt_state, refresh_receipts
from app.services.tkg_evaluation.sender import RecordError

MIGRATION = Path(__file__).resolve().parents[3] / "migrations/094_workspace_tkg.sql"
DEMO = UUID("00000000-0000-0000-0000-000000000001")
CAO = UUID("00000000-0000-4000-8000-000000000002")  # synthetic second workspace


@pytest_asyncio.fixture
async def store(tmp_path, monkeypatch):
    url = os.getenv("TKG_TEST_POSTGRES_DSN")
    if not url:
        pytest.skip("requires disposable TKG_TEST_POSTGRES_DSN")
    conn = await asyncpg.connect(url)
    schema = "tkg_test_" + uuid4().hex
    await conn.execute(f"CREATE SCHEMA {schema}")
    try:
        await conn.execute(f"SET search_path TO {schema},public")
        await conn.execute("""CREATE TABLE tenants(id uuid PRIMARY KEY);
            CREATE TABLE connectors(id uuid PRIMARY KEY,tenant_id uuid REFERENCES tenants);
            CREATE TABLE alerts(id uuid PRIMARY KEY,tenant_id uuid REFERENCES tenants,
              connector_id uuid,connector_type text,llm_payload jsonb,source_event_ids jsonb,
              raw_event jsonb,rule_id text,rule_name text,ocsf_class_uid int,status text);""")
        await conn.execute(MIGRATION.read_text())
        monkeypatch.setenv("AISOC_TKG_SECRET_DIR",str(tmp_path))
        monkeypatch.setenv("AISOC_TKG_ORIGIN_FIXTURE","https://fixture.test")
        owners = []
        for tenant in (DEMO,CAO):
            connector,kb,source = uuid4(),uuid4(),uuid4()
            await conn.execute("INSERT INTO tenants VALUES ($1)",tenant)
            await conn.execute("INSERT INTO connectors VALUES ($1,$2)",connector,tenant)
            row = await conn.fetchrow("""INSERT INTO workspace_tkg_bindings
                (tenant_id,instance,kb_id,source_id,tkg_tenant,source_system,source_instance,connector_id,enabled,auto_ingest)
                VALUES ($1,'fixture',$2,$3,$4,'splunk',$4,$5,true,true) RETURNING *""",tenant,kb,source,str(tenant),connector)
            b = Binding.from_row(row,tenant)
            owners.append(b)
            for role in ("ingest","reader","diagnostics"):
                path = tmp_path/role/str(tenant)/str(b.id)
                path.parent.mkdir(parents=True)
                path.write_text(role+"-"+str(b.id))
        yield conn,owners
    finally:
        await conn.execute(f"DROP SCHEMA {schema} CASCADE")
        await conn.close()


def payload(binding):
    return {"id":str(uuid4()),"connector_id":str(binding.connector_id),"connector_type":"splunk",
            "llm_payload":{"alert_id":"notable-fixture","event_time":"2026-11-01T10:00:00Z","rule_name":"synthetic rule"},
            "raw_event":{"finding":{"uid":"finding-fixture"},"raw_data":{"raw_event":{"source_event_id":"original-event"}}},
            "source_event_ids":["finding-fixture"]}


async def insert(conn,b,disposition):
    row = payload(b)
    await conn.execute("""INSERT INTO alerts(id,tenant_id,connector_id,connector_type,llm_payload,raw_event,status)
        VALUES ($1,$2,$3,'splunk',$4,$5,$6)""", UUID(row["id"]),b.tenant_id,b.connector_id,
        json.dumps(row["llm_payload"]),json.dumps(row["raw_event"]),disposition)
    return UUID(row["id"])


@pytest.mark.asyncio
async def test_durability_scope_replay_and_backfill(store):
    conn,(demo,cao) = store
    ids = [await insert(conn,demo,status) for status in
           ("new","auto_closed","benign_true_positive","false_positive","business_context_suppressed","memory_reused")]
    await insert(conn,cao,"closed")
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await conn.execute("INSERT INTO alerts(id,tenant_id,connector_id) VALUES($1,$2,$3)",uuid4(),uuid4(),cao.connector_id)
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await conn.execute("INSERT INTO workspace_tkg_bindings(tenant_id,instance,kb_id,source_id,tkg_tenant,source_system,source_instance,connector_id) VALUES ($1,'test',$2,$3,'x','splunk','x',$4)",
                           demo.tenant_id,uuid4(),uuid4(),cao.connector_id)
    await conn.execute("UPDATE workspace_tkg_bindings SET auto_ingest=false WHERE id=$1",demo.id)
    old = await insert(conn,demo,"closed")
    args = Namespace(workspace=demo.tenant_id,connector=demo.connector_id,after=None,batch=100,rate=100000,apply=False)
    await backfill(conn,args)
    assert await conn.fetchval("SELECT count(*) FROM tkg_alert_deliveries")==7
    args.apply=True
    await backfill(conn,args)
    await backfill(conn,args)
    actual = await conn.fetch("SELECT * FROM tkg_alert_deliveries WHERE tenant_id=$1",demo.tenant_id)
    assert {r["alert_row_id"] for r in actual}=={*ids,old}
    assert all(r["kb_id"]==demo.kb_id and r["binding_id"]==demo.id for r in actual)
    row = await conn.fetchrow("SELECT * FROM workspace_tkg_bindings WHERE id=$1",cao.id)
    with pytest.raises(BindingError):
        Binding.from_row(row,demo.tenant_id)


@pytest.mark.asyncio
async def test_worker_receipt_recovery_and_disable(store):
    conn,(demo,cao) = store
    alert = await insert(conn,cao,"false_positive")
    receipt = uuid4()
    submitted = []
    def handler(request):
        assert request.headers["Authorization"]=="Bearer ingest-"+str(cao.id)
        assert str(cao.source_id) in request.url.path
        record = json.loads(request.content)["record"]
        assert record["tenant_id"]==cao.tkg_tenant and record["alert_row_id"]==str(alert)
        assert record["source_event_ids"]==["original-event"] and record["finding"]["uid"]=="finding-fixture"
        if request.url.path.endswith("preview"):
            return httpx.Response(200,json={"schema_version":"soorin.ingestion-preview.v1","knowledge_base_id":str(cao.kb_id),
                "source_id":str(cao.source_id),"canonical_event":{**record,"source_record_id":str(alert)}})
        submitted.append(request.content)
        if len(submitted)==1:
            raise httpx.ReadTimeout("synthetic lost acknowledgement")
        return httpx.Response(200,json={"receipt_id":str(receipt),"status":"submitted","schema_version":"soorin.ingestion-receipt.v1"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await deliver(conn,client)
        row = await conn.fetchrow("SELECT * FROM tkg_alert_deliveries")
        assert row["state"]=="retry_scheduled" and row["receipt_id"] is None
        # Simulate a crashed submitter's expired lease.
        await conn.execute("UPDATE tkg_alert_deliveries SET state='submitting',next_attempt=now()")
        await conn.execute("UPDATE workspace_tkg_bindings SET enabled=false WHERE id=$1",cao.id)
        assert not await deliver(conn,client)
        await conn.execute("UPDATE workspace_tkg_bindings SET enabled=true WHERE id=$1",cao.id)
        await deliver(conn,client)
        row = await conn.fetchrow("SELECT * FROM tkg_alert_deliveries")
        assert row["state"]=="pending_materialization" and row["receipt_id"]==receipt
        assert submitted[0]==submitted[1]==row["payload"]
        assert row["payload_hash"]==hashlib.sha256(submitted[0]).hexdigest()
    def status(request):
        assert str(cao.kb_id) in request.url.path and str(receipt) in request.url.path
        assert request.headers["Authorization"]=="Bearer diagnostics-"+str(cao.id)
        return httpx.Response(200,json={"receipt_id":str(receipt),"status":"bound"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(status)) as http:
        await refresh_receipts(conn,http,Namespace(workspace=cao.tenant_id,batch=1,rate=100000))
    assert await conn.fetchval("SELECT state FROM tkg_alert_deliveries")=="bound"


def test_quarantine_reasons():
    b = Binding(uuid4(),DEMO,"fixture",uuid4(),uuid4(),"blue","splunk","splunk-blue",uuid4())
    for change,error in [({"connector_type":"edr"},"unsupported_profile"),({"llm_payload":"{"},"malformed_json"),
                         ({"llm_payload":{}, "raw_event":{}, "source_event_ids":[]},"missing_source_identity"),
                         ({"llm_payload":{"alert_id":"original"}},"missing_or_invalid_source_time"),
                         ({"llm_payload":{"event_time":"2026-01-01T00:00:00Z"}},"no_event_information")]:
        row = {**payload(b),**change}
        with pytest.raises(RecordError,match=error):
            freeze(row,b)
    assert receipt_state("submitted","terminal_failure")=="quarantined"
