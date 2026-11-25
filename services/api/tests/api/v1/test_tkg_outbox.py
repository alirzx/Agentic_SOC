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
              raw_event jsonb,rule_id text,rule_name text,ocsf_class_uid int,status text,title text);""")
        await conn.execute(MIGRATION.read_text())
        monkeypatch.setenv("AISOC_TKG_SECRET_DIR", str(tmp_path))
        monkeypatch.setenv("AISOC_TKG_ORIGIN_FIXTURE", "https://fixture.test")
        owners = []
        for tenant in (DEMO, CAO):
            connector, kb, source = uuid4(), uuid4(), uuid4()
            await conn.execute("INSERT INTO tenants VALUES ($1)", tenant)
            await conn.execute("INSERT INTO connectors VALUES ($1,$2)", connector, tenant)
            row = await conn.fetchrow(
                """INSERT INTO workspace_tkg_bindings
                (tenant_id,instance,kb_id,source_id,tkg_tenant,source_system,source_instance,connector_id,enabled,auto_ingest)
                VALUES ($1,'fixture',$2,$3,$4,'splunk',$4,$5,true,true) RETURNING *""",
                tenant,
                kb,
                source,
                str(tenant),
                connector,
            )
            b = Binding.from_row(row, tenant)
            owners.append(b)
            for role in ("ingest", "reader", "diagnostics"):
                path = tmp_path / role / str(tenant) / str(b.id)
                path.parent.mkdir(parents=True)
                path.write_text(role + "-" + str(b.id))
        yield conn, owners
    finally:
        await conn.execute(f"DROP SCHEMA {schema} CASCADE")
        await conn.close()


def payload(binding):
    return {
        "id": str(uuid4()),
        "connector_id": str(binding.connector_id),
        "connector_type": "splunk",
        "llm_payload": {"alert_id": "notable-fixture", "event_time": "2026-11-01T10:00:00Z", "rule_name": "synthetic rule"},
        "raw_event": {"finding": {"uid": "finding-fixture"}, "raw_data": {"raw_event": {"source_event_id": "original-event"}}},
        "source_event_ids": ["finding-fixture"],
    }


async def insert(conn, b, disposition):
    row = payload(b)
    await conn.execute(
        """INSERT INTO alerts(id,tenant_id,connector_id,connector_type,llm_payload,raw_event,status)
        VALUES ($1,$2,$3,'splunk',$4,$5,$6)""",
        UUID(row["id"]),
        b.tenant_id,
        b.connector_id,
        json.dumps(row["llm_payload"]),
        json.dumps(row["raw_event"]),
        disposition,
    )
    return UUID(row["id"])


@pytest.mark.asyncio
async def test_durability_scope_replay_and_backfill(store):
    conn, (demo, cao) = store
    ids = [
        await insert(conn, demo, status)
        for status in ("new", "auto_closed", "benign_true_positive", "false_positive", "business_context_suppressed", "memory_reused")
    ]
    await insert(conn, cao, "closed")
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await conn.execute("INSERT INTO alerts(id,tenant_id,connector_id) VALUES($1,$2,$3)", uuid4(), uuid4(), cao.connector_id)
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await conn.execute(
            "INSERT INTO workspace_tkg_bindings(tenant_id,instance,kb_id,source_id,tkg_tenant,source_system,source_instance,connector_id) VALUES ($1,'test',$2,$3,'x','splunk','x',$4)",
            demo.tenant_id,
            uuid4(),
            uuid4(),
            cao.connector_id,
        )
    await conn.execute("UPDATE workspace_tkg_bindings SET auto_ingest=false WHERE id=$1", demo.id)
    old = await insert(conn, demo, "closed")
    args = Namespace(workspace=demo.tenant_id, connector=demo.connector_id, after=None, batch=100, rate=100000, apply=False)
    await backfill(conn, args)
    assert await conn.fetchval("SELECT count(*) FROM tkg_alert_deliveries") == 7
    args.apply = True
    await backfill(conn, args)
    await backfill(conn, args)
    actual = await conn.fetch("SELECT * FROM tkg_alert_deliveries WHERE tenant_id=$1", demo.tenant_id)
    assert {r["alert_row_id"] for r in actual} == {*ids, old}
    assert all(r["kb_id"] == demo.kb_id and r["binding_id"] == demo.id for r in actual)
    row = await conn.fetchrow("SELECT * FROM workspace_tkg_bindings WHERE id=$1", cao.id)
    with pytest.raises(BindingError):
        Binding.from_row(row, demo.tenant_id)


@pytest.mark.asyncio
async def test_worker_receipt_recovery_and_disable(store):
    conn, (demo, cao) = store
    alert = await insert(conn, cao, "false_positive")
    receipt = uuid4()
    submitted = []

    def handler(request):
        assert request.headers["Authorization"] == "Bearer ingest-" + str(cao.id)
        assert str(cao.source_id) in request.url.path
        record = json.loads(request.content)["record"]
        assert record["tenant_id"] == cao.tkg_tenant and record["alert_row_id"] == str(alert)
        assert record["source_event_ids"] == ["original-event"] and record["finding"]["uid"] == "finding-fixture"
        if request.url.path.endswith("preview"):
            return httpx.Response(
                200,
                json={
                    "schema_version": "soorin.ingestion-preview.v1",
                    "persistent_writes": False,
                    "canonical_event": {**record, "source_record_id": str(alert), "event_type": "security_alert"},
                },
            )
        submitted.append(request.content)
        if len(submitted) == 1:
            raise httpx.ReadTimeout("synthetic lost acknowledgement")
        return httpx.Response(
            200, json={"receipt_id": str(receipt), "status": "submitted", "schema_version": "soorin.ingestion-receipt.v1"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await deliver(conn, client)
        row = await conn.fetchrow("SELECT * FROM tkg_alert_deliveries")
        assert row["state"] == "retry_scheduled" and row["receipt_id"] is None
        # Simulate a crashed submitter's expired lease.
        await conn.execute("UPDATE tkg_alert_deliveries SET state='submitting',next_attempt=now()")
        await conn.execute("UPDATE workspace_tkg_bindings SET enabled=false WHERE id=$1", cao.id)
        assert not await deliver(conn, client)
        await conn.execute("UPDATE workspace_tkg_bindings SET enabled=true WHERE id=$1", cao.id)
        await deliver(conn, client)
        row = await conn.fetchrow("SELECT * FROM tkg_alert_deliveries")
        assert row["state"] == "pending_materialization" and row["receipt_id"] == receipt
        assert submitted[0] == submitted[1] == row["payload"]
        assert row["payload_hash"] == hashlib.sha256(submitted[0]).hexdigest()

    def status(request):
        assert str(cao.kb_id) in request.url.path and str(receipt) in request.url.path
        assert request.headers["Authorization"] == "Bearer diagnostics-" + str(cao.id)
        return httpx.Response(200, json={"receipt_id": str(receipt), "status": "bound"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(status)) as http:
        await refresh_receipts(conn, http, Namespace(workspace=cao.tenant_id, batch=1, rate=100000))
    assert await conn.fetchval("SELECT state FROM tkg_alert_deliveries") == "bound"


def test_quarantine_reasons():
    b = Binding(uuid4(), DEMO, "fixture", uuid4(), uuid4(), "blue", "splunk", "splunk-blue", uuid4())
    for change, error in [
        ({"connector_type": "edr"}, "unsupported_profile"),
        ({"llm_payload": "{"}, "malformed_json"),
        ({"llm_payload": {}, "raw_event": {}, "source_event_ids": []}, "missing_source_identity"),
        ({"llm_payload": {"alert_id": "original"}}, "missing_or_invalid_source_time"),
        ({"llm_payload": {"event_time": "2026-01-01T00:00:00Z"}}, "no_event_information"),
    ]:
        row = {**payload(b), **change}
        with pytest.raises(RecordError, match=error):
            freeze(row, b)
    assert receipt_state("submitted", "terminal_failure") == "quarantined"


@pytest.mark.asyncio
async def test_production_migration_chain_and_application_role():
    url = os.getenv("TKG_TEST_CHAIN_DSN")
    if not url:
        pytest.skip("requires a disposable database with the SOC migration chain applied")
    conn = await asyncpg.connect(url)
    tenant, other, connector, binding, alert = [uuid4() for _ in range(5)]
    try:
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO tenants(id,name,slug) VALUES ($1,'Demo fixture',$3),($2,'CAO fixture',$4)",
                tenant,
                other,
                str(tenant),
                str(other),
            )
            await conn.execute(
                "INSERT INTO connectors(id,tenant_id,name,connector_type) VALUES ($1,$2,'Splunk fixture','splunk')", connector, tenant
            )
            await conn.execute(
                """INSERT INTO workspace_tkg_bindings
                (id,tenant_id,instance,kb_id,source_id,tkg_tenant,source_system,source_instance,connector_id,enabled,auto_ingest)
                VALUES ($1,$2,'fixture',$3,$4,'blue','splunk',$5,$6,true,true)""",
                binding,
                tenant,
                uuid4(),
                uuid4(),
                str(connector),
                connector,
            )
            with pytest.raises(asyncpg.RaiseError, match="immutable TKG binding"):
                async with conn.transaction():
                    await conn.execute("UPDATE workspace_tkg_bindings SET kb_id=$1 WHERE id=$2", uuid4(), binding)
            await conn.execute("SET LOCAL ROLE aisoc_app")
            insert_sql = """INSERT INTO alerts(id,tenant_id,connector_id,connector_type,title,status,llm_payload)
                VALUES ($1,$2,$3,'splunk','Fixture','closed',$4) ON CONFLICT (id) DO NOTHING"""
            body = json.dumps({"alert_id": "N-fixture", "event_time": "2026-11-01T10:00:00Z", "rule_name": "Fixture"})
            with pytest.raises(RuntimeError, match="rollback"):
                async with conn.transaction():
                    await conn.execute(insert_sql, alert, tenant, connector, body)
                    await conn.execute("SELECT set_config('app.current_tenant_id',$1,true)", str(tenant))
                    assert await conn.fetchval("SELECT count(*) FROM tkg_alert_deliveries WHERE alert_row_id=$1", alert) == 1
                    raise RuntimeError("rollback")
            await conn.execute("SELECT set_config('app.current_tenant_id',$1,true)", str(tenant))
            assert await conn.fetchval("SELECT count(*) FROM tkg_alert_deliveries WHERE alert_row_id=$1", alert) == 0
            assert await conn.fetchval("SELECT count(*) FROM alerts WHERE id=$1", alert) == 0
            await conn.execute(insert_sql, alert, tenant, connector, body)
            await conn.execute(insert_sql, alert, tenant, connector, body)
            assert await conn.fetchval("SELECT count(*) FROM tkg_alert_deliveries WHERE alert_row_id=$1", alert) == 1
            await conn.execute("SELECT set_config('app.current_tenant_id',$1,true)", str(other))
            assert await conn.fetchval("SELECT count(*) FROM workspace_tkg_bindings WHERE id=$1", binding) == 0
            assert await conn.fetchval("SELECT count(*) FROM tkg_alert_deliveries WHERE alert_row_id=$1", alert) == 0
            raise RuntimeError("rollback fixture")
    except RuntimeError as exc:
        if str(exc) != "rollback fixture":
            raise
    finally:
        await conn.close()


def test_frozen_record_against_real_tkg_adapter(monkeypatch):
    import runpy
    from app.services.tkg.worker import DeliveryError, validate_preview

    checkout = os.getenv("TKG_TEST_CHECKOUT")
    if not checkout:
        pytest.skip("requires adjacent TKG checkout")
    monkeypatch.syspath_prepend(checkout)
    adapter = runpy.run_path(str(Path(checkout) / "soorin/ops/http_adapter.py"))["normalize"]
    b = Binding(uuid4(), DEMO, "fixture", uuid4(), uuid4(), "tenant-blue", "splunk", "splunk-e2e", uuid4())
    row = payload(b)
    row["title"] = "Password Spray Detection Source Alert"
    row["llm_payload"]["alert_fields"] = {"hostname": "http.synthetic.example"}
    frozen = freeze(row, b)
    fixture_path = os.getenv("TKG_TEST_FROZEN_ALERT_OUT")
    if fixture_path:
        Path(fixture_path).write_bytes(frozen)
    params = {**json.loads(frozen), "tenant_id": b.tkg_tenant, "source_system": b.source_system, "source_instance": b.source_instance}
    preview = adapter(params)
    validate_preview(preview, b, row["id"])
    assert preview["canonical_event"]["content_checksum"] == adapter(params)["canonical_event"]["content_checksum"]
    with pytest.raises(DeliveryError, match="preview_scope_or_identity_mismatch"):
        validate_preview(preview, b, uuid4())


@pytest.mark.asyncio
@pytest.mark.parametrize(("failure", "state"), [("token", "quarantined"), ("scope", "quarantined"), ("busy", "retry_scheduled")])
async def test_preview_failures_never_submit(store, failure, state):
    conn, (_, binding) = store
    alert = await insert(conn, binding, "closed")

    def serve(request):
        assert request.url.path.endswith("/preview")
        if failure == "token":
            return httpx.Response(401)
        if failure == "busy":
            return httpx.Response(429)
        record = json.loads(request.content)["record"]
        return httpx.Response(
            200,
            json={
                "schema_version": "soorin.ingestion-preview.v1",
                "persistent_writes": False,
                "canonical_event": {**record, "source_record_id": str(alert), "event_type": "security_alert", "source_instance": "foreign"},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
        assert await deliver(conn, client)
    assert await conn.fetchval("SELECT state FROM tkg_alert_deliveries") == state


@pytest.mark.asyncio
async def test_workspace_manual_sync_reports_existing_deliveries(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from app.services.tkg_evaluation import sync

    binding = Binding(uuid4(), DEMO, "fixture", uuid4(), uuid4(), "blue", "splunk", "splunk-blue", uuid4())
    known, pending, new = [payload(binding) for _ in range(3)]
    rows = [
        {"alert_row_id": UUID(r["id"]), "state": status, "receipt_id": uuid4()}
        for r, status in [(known, "bound"), (pending, "pending_materialization")]
    ]
    result = SimpleNamespace(mappings=lambda: SimpleNamespace(all=lambda: rows))
    db = SimpleNamespace(execute=AsyncMock(return_value=result), commit=AsyncMock())
    monkeypatch.setattr(
        sync,
        "workspace_config",
        AsyncMock(return_value=SimpleNamespace(configured=True, binding=binding, allow_send=True, evaluation_identity="security_alert")),
    )
    monkeypatch.setattr(sync, "load_case", AsyncMock(return_value={"alert_ids": []}))
    monkeypatch.setattr(sync, "load_case_scope", AsyncMock(return_value=([], [])))
    monkeypatch.setattr(sync, "load_alerts", AsyncMock(return_value=[known, pending, new]))
    out = await sync.sync_missing_alerts(db, tenant_id=DEMO, case_id=uuid4())
    assert out["would_send"] == [{"alert_id": new["id"]}]
    assert out["already_in_graph"][0]["alert_id"] == known["id"]
    assert out["existing_deliveries"][0]["status"] == "pending_materialization"
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_case_eval_checks_response_scope_and_rotates_reader(tmp_path, monkeypatch):
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock
    from types import SimpleNamespace

    from app.db import database
    from app.services.tkg_evaluation.client import TkgClient, TkgConfig, TkgError

    binding = Binding(uuid4(), DEMO, "fixture", uuid4(), uuid4(), "blue", "splunk", "splunk-blue", uuid4())
    reader = tmp_path / "reader" / str(DEMO) / str(binding.id)
    reader.parent.mkdir(parents=True)
    reader.write_text("fixture-reader-one")
    monkeypatch.setenv("AISOC_TKG_SECRET_DIR", str(tmp_path))

    @asynccontextmanager
    async def session():
        yield SimpleNamespace(execute=AsyncMock(), scalar=AsyncMock(return_value=True))

    monkeypatch.setattr(database, "AsyncSessionLocal", session)
    seen = []

    def serve(request):
        seen.append(request.headers["Authorization"])
        body = json.loads(request.content)
        assert body["authority_name"] == "soc_alert_row_id"
        return httpx.Response(
            200,
            json={
                "schema_version": "soorin.identity-resolution.v1",
                "knowledge_base_id": str(binding.kb_id if len(seen) == 1 else uuid4()),
                "tenant_id": binding.tkg_tenant,
                "status": "not_found",
            },
        )

    cfg = TkgConfig(
        base_url="https://fixture.invalid",
        email="",
        password="",
        kb_id=str(binding.kb_id),
        tenant_id=binding.tkg_tenant,
        binding=binding,
        evaluation_identity="security_alert",
    )
    async with TkgClient(cfg, transport=httpx.MockTransport(serve)) as client:
        assert (await client.resolve(str(uuid4())))["status"] == "not_found"
        reader.write_text("fixture-reader-two")
        with pytest.raises(TkgError, match="response scope or schema mismatch"):
            await client.resolve(str(uuid4()))
    assert seen == ["Bearer fixture-reader-one", "Bearer fixture-reader-two"]


@pytest.mark.asyncio
async def test_competing_workers_and_stale_ack(store):
    import asyncio

    conn, (_, binding) = store
    await insert(conn, binding, "false_positive")
    schema = await conn.fetchval("SELECT current_schema()")
    second = await asyncpg.connect(os.environ["TKG_TEST_POSTGRES_DSN"], server_settings={"search_path": f"{schema},public"})
    old_ingest_started, release_old_ingest = asyncio.Event(), asyncio.Event()
    receipts = [uuid4(), uuid4()]
    submissions = []

    async def serve(request):
        record = json.loads(request.content)["record"]
        if request.url.path.endswith("/preview"):
            return httpx.Response(
                200,
                json={
                    "schema_version": "soorin.ingestion-preview.v1",
                    "persistent_writes": False,
                    "canonical_event": {**record, "source_record_id": record["alert_row_id"], "event_type": "security_alert"},
                },
            )
        submissions.append(request.content)
        if len(submissions) == 1:
            old_ingest_started.set()
            await release_old_ingest.wait()
            receipt = receipts[0]
        else:
            receipt = receipts[1]
        return httpx.Response(
            200,
            json={
                "schema_version": "soorin.ingestion-receipt.v1",
                "status": "submitted",
                "receipt_id": str(receipt),
            },
        )

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as http:
            async with asyncio.TaskGroup() as group:
                group.create_task(deliver(conn, http))
                try:
                    await asyncio.wait_for(old_ingest_started.wait(), timeout=3)
                    assert await deliver(second, http) is False
                    await second.execute("UPDATE tkg_alert_deliveries SET next_attempt=now()-interval '1 second'")
                    assert await deliver(second, http)
                finally:
                    release_old_ingest.set()
        delivery = await second.fetchrow("SELECT receipt_id,attempts,state FROM tkg_alert_deliveries")
        assert (delivery["receipt_id"], delivery["attempts"], delivery["state"]) == (receipts[1], 2, "pending_materialization")
        assert len(submissions) == 2 and submissions[0] == submissions[1]
    finally:
        await second.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("marker,retry", [("soc_normalizer_busy", True), ("soc_normalizer_timeout", True), ("identity_conflict", False)])
async def test_normalizer_overload_is_distinct_from_conflict(marker, retry):
    from app.services.tkg.worker import DeliveryError, request_json

    transport = httpx.MockTransport(lambda _: httpx.Response(409, json={"error": marker}))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(DeliveryError) as failure:
            await request_json(client, "POST", "https://fixture.test/soc/preview", "fixture-only")
    assert failure.value.transient is retry
    assert failure.value.code == (marker if retry else "http_409")


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [64, 640], ids=["small", "medium"])
async def test_splunk_qualification_corpus(store, count, monkeypatch):
    """Production-shaped synthetic rows through PostgreSQL and the real TKG Python adapter."""
    import runpy
    import time
    from collections import Counter, defaultdict
    from uuid import NAMESPACE_URL, uuid5

    checkout = os.getenv("TKG_TEST_CHECKOUT")
    if not checkout:
        pytest.skip("requires adjacent TKG checkout")
    monkeypatch.syspath_prepend(checkout)
    root = Path(checkout)
    generate = runpy.run_path(str(root / "soorin/tests/mock_splunk/scripts/curated_qa_dataset.py"))["make_record"]
    normalize = runpy.run_path(str(root / "soorin/ops/http_adapter.py"))["normalize"]
    conn, owners = store
    dispositions = (
        "true_positive",
        "false_positive",
        "benign",
        "benign_true_positive",
        "needs_review",
        "auto_closed",
        "context_suppressed",
        "memory_suppressed",
        "new",
    )
    sql = """INSERT INTO alerts(id,tenant_id,connector_id,connector_type,llm_payload,raw_event,
                status,title,rule_id,source_event_ids)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id) DO NOTHING"""
    counts = Counter()
    exported = []
    durations = defaultdict(list)
    bindings = {b.id: b for b in owners}
    cases = {}

    for i in range(count):
        binding = owners[i % 2]
        vendor = generate(i)
        row_id = uuid5(NAMESPACE_URL, f"synthetic-soorin-sprint3/{i}")
        vendor["llm_payload"]["alert_id"] = str(row_id)
        vendor["finding"] = json.loads(vendor["raw_data"])["raw_event"]["finding"]
        vendor["_time"] = vendor["event_time"]
        # The Go normalizer stores an encoded connector envelope under raw_data.
        raw = {
            "source_connector_id": str(binding.connector_id),
            "tenant_uid": str(binding.tenant_id),
            "finding": vendor["finding"],
            "raw_data": json.dumps({"raw_event": vendor}),
        }
        rich = vendor["llm_payload"]
        variant = ("go-envelope", "nested", "api-enriched", "compact", "fractional-offset", "high-cardinality")[i % 6]
        if variant == "nested":
            raw["raw_data"] = {"raw_event": {"raw_event": vendor}}
            rich = {"llm_payload": json.dumps({"llm_payload": rich})}
        if variant == "compact":
            raw = {**vendor, "raw_data": None, "llm_payload": None}
            rich = None
        if variant == "fractional-offset":
            rich["event_time"] = "2026-10-20T03:30:00.123456+03:30"
        if variant == "high-cardinality":
            vendor["source_event_ids"] += [f"fixture-{i}-{j}" for j in range(20)]
            raw["raw_data"] = {"raw_event": vendor}

        connector_type = "splunk"
        reason = None
        if i < 8:
            reason = (
                "missing_source_identity",
                "missing_or_invalid_source_time",
                "source_scope_mismatch",
                "conflicting_soc_alert_identity",
                "malformed_json",
                "record_too_large",
                "unsupported_profile",
                "invalid_source_event_ids",
            )[i]
            if i == 0:
                raw, rich = {"_time": vendor["_time"]}, None
                vendor["source_event_ids"] = []
            elif i == 1:
                rich = {**vendor["llm_payload"], "event_time": "yesterday"}
            elif i == 2:
                raw["tenant_uid"] = str(owners[1 - i % 2].tenant_id)
            elif i == 3:
                raw, rich = {"raw_event": vendor}, {"_meta": {"mode": "enriched_from_api"}, "alert_id": "different"}
            elif i == 4:
                rich = "not-json"
            elif i == 5:
                rich["synthetic_padding"] = "x" * 1_010_000
            elif i == 6:
                connector_type = "unsupported"
            elif i == 7:
                vendor["source_event_ids"] = "not-an-array"
                raw["raw_data"] = {"raw_event": vendor}

        values = (
            row_id,
            binding.tenant_id,
            binding.connector_id,
            connector_type,
            json.dumps(rich),
            json.dumps(raw),
            dispositions[i % len(dispositions)],
            vendor["search_name"],
            vendor["rule_id"],
            json.dumps(vendor["source_event_ids"]),
        )
        started = time.perf_counter()
        assert (await conn.execute(sql, *values)) == "INSERT 0 1"
        durations["postgres_insert_ms"].append((time.perf_counter() - started) * 1e3)
        if i % 8 == 0:
            assert (await conn.execute(sql, *values)) == "INSERT 0 0"
            counts["idempotent_replays"] += 1
        cases[row_id] = (variant, reason, vendor)

    deliveries = await conn.fetch("SELECT * FROM tkg_alert_deliveries")
    assert len(deliveries) == count
    invalid_ids = [key for key, (_, reason, _) in cases.items() if reason]
    await conn.execute("UPDATE tkg_alert_deliveries SET next_attempt=now()+interval '1 day' WHERE NOT (alert_row_id=ANY($1))", invalid_ids)
    for _ in invalid_ids:
        # A quarantined local projection must never reach the HTTP client.
        assert await deliver(conn, None)
    quarantined = await conn.fetch("SELECT alert_row_id,error_code FROM tkg_alert_deliveries WHERE state='quarantined'")
    assert {row["alert_row_id"]: row["error_code"] for row in quarantined} == {key: cases[key][1] for key in invalid_ids}
    counts["persisted_quarantines"] = len(quarantined)
    for delivery in deliveries:
        binding = bindings[delivery["binding_id"]]
        assert delivery["tenant_id"] == binding.tenant_id
        assert delivery["kb_id"] == binding.kb_id and delivery["source_id"] == binding.source_id
        variant, reason, vendor = cases[delivery["alert_row_id"]]
        snapshot = json.loads(delivery["snapshot"])
        if reason:
            with pytest.raises(RecordError, match=reason):
                freeze(snapshot, binding)
            counts["rejected." + reason] += 1
            continue
        started = time.perf_counter()
        body = freeze(snapshot, binding)
        durations["freeze_ms"].append((time.perf_counter() - started) * 1e3)
        record = json.loads(body)["record"]
        assert record["source_revision_id"] == vendor["source_revision_id"]
        assert record["source_event_ids"] == vendor["source_event_ids"]
        scope = dict(tenant_id=binding.tkg_tenant, source_system=binding.source_system, source_instance=binding.source_instance)
        started = time.perf_counter()
        preview = normalize({**json.loads(body), **scope})
        durations["normalize_ms"].append((time.perf_counter() - started) * 1e3)
        event = preview["canonical_event"]
        assert event["source_record_id"] == str(delivery["alert_row_id"])
        assert event["tenant_id"] == binding.tkg_tenant
        assert event["source_instance"] == binding.source_instance
        assert body == freeze(snapshot, binding)
        if len(durations["normalize_ms"]) % 8 == 0:
            assert event["content_checksum"] == normalize({**json.loads(body), **scope})["canonical_event"]["content_checksum"]
        counts["normalized." + variant] += 1
        if os.getenv("TKG_TEST_CURATED_CORPUS_DIR"):
            from dataclasses import replace

            http_binding = replace(binding, tkg_tenant="tenant-blue", source_instance="splunk-e2e")
            exported.append(freeze(snapshot, http_binding))

    if exported:
        target = Path(os.environ["TKG_TEST_CURATED_CORPUS_DIR"]) / f"curated-{count}.jsonl"
        target.write_bytes(b"\n".join(exported) + b"\n")
    assert sum(v for k, v in counts.items() if k.startswith("normalized.")) == count - 8
    metrics = {}
    for label, samples in durations.items():
        ordered = sorted(samples)
        metrics[label] = {
            "p50": round(ordered[len(ordered) // 2], 3),
            "p95": round(ordered[int((len(ordered) - 1) * 0.95)], 3),
            "max": round(ordered[-1], 3),
        }
    print(json.dumps({"records": count, "counts": counts, "latencies": metrics}, sort_keys=True))


@pytest.mark.asyncio
async def test_malformed_receipt_uses_fenced_retry(store):
    conn, (_, binding) = store
    await insert(conn, binding, "benign")

    def serve(request):
        record = json.loads(request.content)["record"]
        if request.url.path.endswith("/preview"):
            return httpx.Response(
                200,
                json={
                    "schema_version": "soorin.ingestion-preview.v1",
                    "persistent_writes": False,
                    "canonical_event": {**record, "source_record_id": record["alert_row_id"], "event_type": "security_alert"},
                },
            )
        return httpx.Response(
            200,
            json={
                "schema_version": "soorin.ingestion-receipt.v1",
                "receipt_id": str(uuid4()),
                "status": ["violates-schema"],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as http:
        assert await deliver(conn, http)
    row = await conn.fetchrow("SELECT state,error_code,receipt_id,receipt_status,attempts FROM tkg_alert_deliveries")
    assert tuple(row) == ("retry_scheduled", "invalid_receipt", None, None, 1)
