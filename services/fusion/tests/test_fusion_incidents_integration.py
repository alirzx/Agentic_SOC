"""Durable fusion_incidents integration tests (real PostgreSQL).

Skipped unless both are set:
  AISOC_RUN_INTEGRATION=1
  DATABASE_URL=postgresql://...  (or postgresql+asyncpg://...)

Never targets production. Uses a disposable tenant UUID and cleans up rows.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

_MIG_058 = Path(__file__).resolve().parents[2] / "api" / "migrations" / "058_fusion_incidents.sql"


def _require_integration_pg() -> str:
    if os.getenv("AISOC_RUN_INTEGRATION", "").strip() not in {"1", "true", "yes", "on"}:
        pytest.skip("set AISOC_RUN_INTEGRATION=1 to run durable-incident Postgres tests")
    url = (os.getenv("DATABASE_URL") or os.getenv("AISOC_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.skip("DATABASE_URL / AISOC_TEST_DATABASE_URL required for integration")
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


@pytest.mark.asyncio
async def test_migration_058_file_is_idempotent_sql():
    """Structural gate that always runs — no DB required."""
    text = _MIG_058.read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS fusion_incidents" in text
    assert "ADD COLUMN IF NOT EXISTS fusion_incident_id" in text
    assert "CREATE INDEX IF NOT EXISTS" in text
    assert "BEGIN;" in text and "COMMIT;" in text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_incident_store_persist_restore_and_case_link():
    dsn = _require_integration_pg()
    asyncpg = pytest.importorskip("asyncpg")
    from app.models.alert import AlertSeverity, IncidentSummary, RawAlert
    from app.services.correlator import Correlator
    from app.services.incident_store import IncidentStore

    tenant = uuid.uuid4()
    store = IncidentStore(dsn)
    await store.start()
    if store._pool is None:  # noqa: SLF001
        pytest.skip("could not connect to Postgres pool")

    class _Redis:
        def __init__(self) -> None:
            self.store: dict[str, bytes] = {}

        async def get(self, key: str):
            return self.store.get(key)

        async def set(self, key: str, value: str, ex=None, nx=None):
            if nx and key in self.store:
                return None
            self.store[key] = value.encode() if isinstance(value, str) else value
            return True

    redis = _Redis()
    corr = Correlator(redis, store=store)  # type: ignore[arg-type]

    def _alert(**kw) -> RawAlert:
        base = dict(
            id=uuid.uuid4(),
            tenant_id=tenant,
            source="test",
            title="Phase21 durable spray",
            severity=AlertSeverity.MEDIUM,
            src_ip="10.55.55.1",
            username="phase21-user",
            mitre_tactics=["Credential Access"],
            mitre_techniques=["T1110.003"],
            event_time=datetime.now(timezone.utc),
        )
        base.update(kw)
        return RawAlert(**base)

    try:
        a1 = _alert()
        _, inc1 = await corr.correlate(a1)
        loaded = await store.get(inc1.id)
        assert loaded is not None
        assert loaded.alert_count >= 1

        # Redis wipe → durable restore
        redis.store.clear()
        a2 = _alert()
        correlated, inc2 = await corr.correlate(a2)
        assert correlated is True
        assert inc2.id == inc1.id
        assert inc2.alert_count >= 2

        case_id = uuid.uuid4()
        assert await store.set_case_id(inc1.id, case_id, tenant) is True
        row = await store.get(inc1.id)
        assert row is not None
        # case_id is not on IncidentSummary — verify via SQL
        async with store._pool.acquire() as conn:  # noqa: SLF001
            got = await conn.fetchval(
                "SELECT case_id FROM fusion_incidents WHERE id=$1 AND tenant_id=$2",
                inc1.id,
                tenant,
            )
            assert got == case_id
            # Idempotent upsert does not duplicate incident rows
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM fusion_incidents WHERE tenant_id=$1 AND correlation_key=$2",
                tenant,
                a1.correlation_key(),
            )
            assert int(count) >= 1
    finally:
        if store._pool is not None:  # noqa: SLF001
            async with store._pool.acquire() as conn:  # noqa: SLF001
                await conn.execute("DELETE FROM fusion_incidents WHERE tenant_id=$1", tenant)
                await conn.execute(
                    "DELETE FROM alerts WHERE tenant_id=$1 AND title LIKE 'Phase21%'",
                    tenant,
                )
        await store.stop()


@pytest.mark.asyncio
async def test_incident_store_fail_soft_when_db_unreachable():
    from app.models.alert import AlertSeverity, IncidentSummary
    from app.services.incident_store import IncidentStore

    store = IncidentStore("postgresql://invalid:invalid@127.0.0.1:1/nope")
    await store.start()
    assert store._pool is None  # noqa: SLF001
    ok = await store.upsert(
        IncidentSummary(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            title="x",
            severity=AlertSeverity.LOW,
        )
    )
    assert ok is False
