"""Unit tests for the Phase 3.1 fused-alert → Postgres sink.

Covers the skip/fail-soft decision logic with a stub pool. The real-container
insert path is gated by `.github/workflows/integration.yml`
(scripts/integration/spine_test.py) — asserting SQL against a live Postgres,
not a mock.
"""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager

import asyncpg
import pytest
from app.models.alert import (
    AlertSeverity,
    FusedAlert,
    FusionDecision,
    RawAlert,
)
from app.services.alert_sink import (
    AlertSink,
    PersistOutcome,
    _asyncpg_dsn,
    _entities,
    _iocs,
)

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
CONNECTOR = uuid.UUID("00000000-0000-0000-0000-0000000000c1")


def _fused(decision: FusionDecision = FusionDecision.NEW_ALERT) -> FusedAlert:
    raw = RawAlert(
        tenant_id=TENANT,
        source="CrowdStrike Falcon",
        title="Credential dumping via LSASS access",
        severity=AlertSeverity.CRITICAL,
        src_ip="10.20.30.40",
        hostname="WIN-DC01",
        username="svc-backup",
        mitre_techniques=["T1003"],
        connector_id=CONNECTOR,
        connector_type="crowdstrike_falcon",
        source_event_ids=["evt-1"],
        ocsf_class_uid=2004,
        rule_id="edr-cred-dump-1",
        rule_name="Credential dumping via LSASS access",
    )
    # Canonical, replay-stable id (issue #568) — the sink inserts it explicitly.
    raw.id = raw.deterministic_id()
    return FusedAlert(
        id=raw.id,
        tenant_id=TENANT,
        fusion_decision=decision,
        alert=raw,
    )


class _StubConn:
    def __init__(self, row):
        self._row = row
        self.calls: list[tuple] = []
        self.executes: list[tuple] = []

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        return self._row

    async def execute(self, sql, *args):
        self.executes.append((sql, args))
        return "UPDATE 1"


class _StubPool:
    def __init__(self, row, lookup_row=None):
        self.conn = _StubConn(row)
        self._lookup_row = lookup_row if lookup_row is not None else row

    @asynccontextmanager
    async def _acquire(self):
        yield self.conn

    def acquire(self):
        return self._acquire()

    async def fetchrow(self, sql, *args):
        self.conn.calls.append((sql, args))
        return self._lookup_row


def test_dsn_strips_sqlalchemy_driver():
    assert _asyncpg_dsn("postgresql+asyncpg://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"
    assert _asyncpg_dsn("postgresql://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"


def test_iocs_and_entities_extraction():
    fused = _fused()
    iocs = _iocs(fused)
    assert {"type": "ip", "value": "10.20.30.40"} in iocs
    entities = _entities(fused)
    assert {"type": "host", "value": "WIN-DC01"} in entities
    assert {"type": "user", "value": "svc-backup"} in entities


@pytest.mark.asyncio
async def test_duplicate_decision_still_attempts_idempotent_insert():
    """Redis DUPLICATE must not skip Postgres — sink INSERT is idempotent."""
    fused = _fused(FusionDecision.DUPLICATE)
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    async def _no_display(*_a, **_k):
        return None

    sink.lookup_display_duplicate = _no_display  # type: ignore[method-assign]
    result = await sink.persist(fused)
    assert result.outcome is PersistOutcome.INSERTED
    assert sink._pool.conn.calls  # INSERT was issued


@pytest.mark.asyncio
async def test_new_alert_is_inserted_with_canonical_id_and_provenance():
    fused = _fused()
    # The sink inserts the canonical id explicitly; the DB echoes it back.
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    async def _no_display(*_a, **_k):
        return None

    sink.lookup_display_duplicate = _no_display  # type: ignore[method-assign]
    result = await sink.persist(fused)

    assert result.outcome is PersistOutcome.INSERTED
    assert result.alert_id == str(fused.id)
    assert result.persisted is True
    (sql, args) = pool.conn.calls[0]
    assert "INSERT INTO alerts" in sql
    assert "WHERE NOT EXISTS" in sql  # content dedup guard
    assert "ON CONFLICT (id) DO NOTHING" in sql  # exact-replay idempotency
    # Positional args follow the _INSERT_SQL column order.
    assert args[0] == fused.id  # explicit canonical id
    assert args[1] == TENANT
    assert args[10] == fused.alert.fingerprint()  # dedup_hash
    assert args[17] == CONNECTOR  # connector_id
    assert args[18] == "crowdstrike_falcon"  # connector_type
    assert json.loads(args[19]) == ["evt-1"]  # source_event_ids
    assert args[20] == 2004  # ocsf_class_uid
    assert args[21] == "edr-cred-dump-1"  # rule_id
    assert json.loads(args[23]) == ["WIN-DC01"]  # affected_hosts
    assert "llm_payload" in sql  # migration 061 column
    assert args[24] is None  # no payload for a connector that emits none


@pytest.mark.asyncio
async def test_unknown_tenant_fails_without_reassignment():
    other = uuid.UUID("11111111-1111-1111-1111-111111111111")
    fused = _fused()
    fused.alert.tenant_id = other
    fused.tenant_id = other
    fused.id = fused.alert.deterministic_id()

    class _FkThenOkConn:
        def __init__(self):
            self.calls: list[tuple] = []

        async def fetchrow(self, sql, *args):
            self.calls.append((sql, args))
            if args[1] == other:
                raise asyncpg.ForeignKeyViolationError()
            return {"id": args[0]}

    class _FkThenOkPool:
        def __init__(self):
            self.conn = _FkThenOkConn()

        @asynccontextmanager
        async def _acquire(self):
            yield self.conn

        def acquire(self):
            return self._acquire()

        async def fetchrow(self, sql, *args):
            return None

    sink = AlertSink("postgresql://x")
    sink._pool = _FkThenOkPool()

    async def _no_display(*_a, **_k):
        return None

    sink.lookup_display_duplicate = _no_display  # type: ignore[method-assign]
    result = await sink.persist(fused)
    assert result.outcome is PersistOutcome.FAILED
    assert not result.durable
    assert [args[1] for _, args in sink._pool.conn.calls] == [other]


@pytest.mark.asyncio
async def test_unconfirmed_conflict_does_not_claim_durability():
    pool = _StubPool(row=None)  # WHERE NOT EXISTS / ON CONFLICT filtered it out
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    async def _no_display(*_a, **_k):
        return None

    sink.lookup_display_duplicate = _no_display  # type: ignore[method-assign]
    result = await sink.persist(_fused())
    assert result.outcome is PersistOutcome.FAILED
    assert result.alert_id is None
    assert not result.durable


@pytest.mark.asyncio
async def test_dedup_hit_returns_existing_postgres_id():
    existing = uuid.uuid4()
    pool = _StubPool(row=None, lookup_row={"id": str(existing)})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    async def _no_display(*_a, **_k):
        return None

    sink.lookup_display_duplicate = _no_display  # type: ignore[method-assign]
    result = await sink.persist(_fused())
    assert result.outcome is PersistOutcome.DUPLICATE
    assert result.alert_id == str(existing)
    assert result.durable is True


@pytest.mark.asyncio
async def test_db_unavailable_is_distinct_from_duplicate(monkeypatch):
    sink = AlertSink("postgresql://nope:nope@127.0.0.1:1/none")

    async def _fail_start():
        sink._pool = None

    monkeypatch.setattr(sink, "start", _fail_start)
    result = await sink.persist(_fused())
    # Fail-soft (no raise) but observably UNAVAILABLE — retryable, NOT a dup.
    assert result.outcome is PersistOutcome.UNAVAILABLE
    assert result.durable is False


@pytest.mark.asyncio
async def test_persist_exception_is_failed_not_duplicate():
    class _BoomPool(_StubPool):
        def acquire(self):
            raise RuntimeError("connection reset")

    sink = AlertSink("postgresql://x")
    sink._pool = _BoomPool(row=None)

    async def _no_display(*_a, **_k):
        return None

    sink.lookup_display_duplicate = _no_display  # type: ignore[method-assign]
    result = await sink.persist(_fused())
    assert result.outcome is PersistOutcome.FAILED
    assert result.durable is False


@pytest.mark.asyncio
async def test_durable_persist_clears_fusion_persist_failed_badge():
    """Successful sink writes heal the Connectors 'Persist failed' counter."""
    fused = _fused()
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    async def _no_display(*_a, **_k):
        return None

    sink.lookup_display_duplicate = _no_display  # type: ignore[method-assign]
    result = await sink.persist(fused)
    assert result.outcome is PersistOutcome.INSERTED
    assert any("fusion_persist_failed = 0" in sql for sql, _ in pool.conn.executes)


@pytest.mark.asyncio
async def test_display_duplicate_skips_insert_and_bumps_occurrence(monkeypatch):
    """When AISOC_ALERT_DISPLAY_DEDUP is on, same title+rule+host collapses."""
    from app.core import config as fusion_config

    monkeypatch.setattr(fusion_config.settings, "alert_display_dedup_enabled", True)
    fused = _fused()
    existing = str(uuid.uuid4())
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    async def _hit(*_a, **_k):
        return existing

    touched: list[tuple] = []

    async def _touch(tenant_id, fingerprint, *, event_time=None, original_id=None):
        touched.append((str(tenant_id), fingerprint, original_id))
        return True

    sink.lookup_display_duplicate = _hit  # type: ignore[method-assign]
    sink.touch_duplicate = _touch  # type: ignore[method-assign]
    result = await sink.persist(fused)
    assert result.outcome is PersistOutcome.DUPLICATE
    assert result.alert_id == existing
    assert pool.conn.calls == []  # no INSERT
    assert touched and touched[0][2] == existing


def test_deterministic_id_is_replay_stable():
    # Same tenant + content ⇒ same canonical id across independent builds.
    a = _fused().alert
    b = _fused().alert
    assert a.id == b.id == a.deterministic_id()
    # And it is a proper uuid5 (not the random default_factory).
    assert a.id != uuid.uuid4()

@pytest.mark.asyncio
async def test_llm_payload_is_persisted_as_jsonb():
    """The curated LLM evidence payload lands in its own column (migration 061)."""
    fused = _fused()
    fused.alert.llm_payload = {"alert_id": "a-1", "rule_name": "ESCU - 3CX", "alert_fields": {"query": "www.3cx.com"}}
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    async def _no_display(*_a, **_k):
        return None

    sink.lookup_display_duplicate = _no_display  # type: ignore[method-assign]
    result = await sink.persist(fused)

    assert result.outcome is PersistOutcome.INSERTED
    (sql, args) = pool.conn.calls[0]
    assert "llm_payload" in sql
    assert "$25::jsonb" in sql
    assert json.loads(args[24]) == fused.alert.llm_payload

@pytest.mark.asyncio
async def test_empty_llm_payload_is_written_as_null():
    """{} must not reach Postgres as an empty object ("evidence exists")."""
    fused = _fused()
    fused.alert.llm_payload = {}
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    async def _no_display(*_a, **_k):
        return None

    sink.lookup_display_duplicate = _no_display  # type: ignore[method-assign]
    await sink.persist(fused)

    (_sql, args) = pool.conn.calls[0]
    assert args[24] is None


def test_splunk_fingerprint_scopes_connector_and_recognizes_legacy():
    alert = _fused().alert
    alert.connector_type = "splunk"
    alert.connector_id = uuid.UUID(int=101)
    alert.source_event_ids = ["vendor-notable-1"]
    second = alert.model_copy(update={"connector_id": uuid.UUID(int=102)})
    assert alert.fingerprint(legacy=True) == second.fingerprint(legacy=True)
    assert alert.fingerprint() != second.fingerprint()
    assert alert.deterministic_id() != second.deterministic_id()
    assert alert.model_copy().deterministic_id() == alert.deterministic_id()


@pytest.mark.asyncio
async def test_splunk_sql_preserves_legacy_and_outboxes_distinct_connectors():
    import os

    dsn = os.getenv("TKG_TEST_CHAIN_DSN")
    if not dsn:
        pytest.skip("requires disposable SOC migration-chain database")
    conn = await asyncpg.connect(dsn)
    tenant, old_connector, new_connector, legacy_id = [uuid.uuid4() for _ in range(4)]
    try:
        async with conn.transaction():
            await conn.execute("INSERT INTO tenants(id,name,slug) VALUES ($1,'Sprint fixture',$2)", tenant, str(tenant))
            for connector in (old_connector, new_connector):
                await conn.execute(
                    "INSERT INTO connectors(id,tenant_id,name,connector_type) VALUES ($1,$2,'fixture','splunk')", connector, tenant
                )
                await conn.execute("""INSERT INTO workspace_tkg_bindings
                    (tenant_id,instance,kb_id,source_id,tkg_tenant,source_system,source_instance,connector_id,enabled,auto_ingest)
                    VALUES ($1,'fixture',$2,$3,'fixture','splunk',$4,$5,true,true)""",
                    tenant, uuid.uuid4(), uuid.uuid4(), str(connector), connector)
            fused = _fused()
            fused.alert.tenant_id = tenant
            fused.alert.connector_type = "splunk"
            fused.alert.connector_id = old_connector
            fused.alert.source_event_ids = ["same-finding"]
            await conn.execute("""INSERT INTO alerts(id,tenant_id,connector_id,connector_type,title,dedup_hash)
                VALUES ($1,$2,$3,'splunk','historical',$4)""",
                legacy_id, tenant, old_connector, fused.alert.fingerprint(legacy=True))
            sink = AlertSink(dsn)

            class SameConnection:
                @asynccontextmanager
                async def acquire(self):
                    yield conn

                async def fetchrow(self, sql, *args):
                    return await conn.fetchrow(sql, *args)

            sink._pool = SameConnection()
            fused.id = fused.alert.deterministic_id()
            old = await sink.persist(fused)
            assert (old.outcome, old.alert_id) == (PersistOutcome.DUPLICATE, str(legacy_id))

            fused.alert.connector_id = new_connector
            fused.id = fused.alert.deterministic_id()
            inserted = await sink.persist(fused)
            assert inserted.outcome is PersistOutcome.INSERTED
            assert (await sink.persist(fused)).outcome is PersistOutcome.DUPLICATE
            actual = await conn.fetch("SELECT alert_row_id FROM tkg_alert_deliveries WHERE tenant_id=$1", tenant)
            assert {row["alert_row_id"] for row in actual} == {legacy_id, fused.id}
            raise RuntimeError("rollback fixture")
    except RuntimeError as exc:
        if str(exc) != "rollback fixture":
            raise
    finally:
        await conn.close()
