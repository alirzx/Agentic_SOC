"""DB-backed integration tests for the KPI Level 1 evaluation and metrics system.

Why a real database, not mocks:
  * ``KPIMetricsCalculator._calculate_alert_reduction`` now queries ``aisoc_cases``
    via raw SQL. Only a real Postgres can prove the query parses and returns data.
  * ``_calculate_cluster_purity`` uses ``SELECT unnest(alert_ids) FROM aisoc_cases``
    — the ``alert_ids`` column is ``uuid[]`` in the real table. A mock pool cannot
    catch a regression from JSONB to array unnesting.
  * The FK on ``case_evaluations.case_id → aisoc_cases(id)`` is enforced by
    Postgres; inserting an evaluation without a matching ``aisoc_cases`` row must
    raise a FK violation so we know the constraint is correct.

Connection: ``DATABASE_URL`` env var (set by ``docs/ahmadi/start-dev-local.ps1``).
Skip gracefully when the env var is not set or Postgres is unreachable.

Run with:
    DATABASE_URL=postgresql+asyncpg://... pytest services/api/tests/test_kpi_evaluation.py -v
or via the integration gate:
    AISOC_RUN_INTEGRATION=1 pytest -m integration services/api/tests/test_kpi_evaluation.py -v
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


def _db_url() -> str:
    raw = os.environ.get("DATABASE_URL", "").strip()
    if not raw:
        pytest.skip("DATABASE_URL not set — KPI DB-backed tests require Postgres")
    return raw


@pytest_asyncio.fixture
async def db() -> AsyncSession:
    """Async session connected to the Docker Postgres, cleaned up after each test."""
    engine = create_async_engine(_db_url(), echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    tenant_id = uuid.uuid4()
    slug = f"kpi-test-{uuid.uuid4().hex[:8]}"

    async with factory() as session:
        # Create a minimal tenant so FK constraints on tenants(id) pass
        await session.execute(
            text(
                "INSERT INTO tenants (id, name, slug, mssp_role) "
                "VALUES (:id, :name, :slug, 'standalone')"
            ),
            {"id": tenant_id, "name": "KPI Test Tenant", "slug": slug},
        )
        await session.commit()

        session.info["tenant_id"] = tenant_id
        yield session

        # Cleanup — tenant CASCADE removes case_evaluations, false_alert_records,
        # kpi_metrics rows that have tenant FK. aisoc_cases rows need explicit delete.
        await session.execute(
            text("DELETE FROM case_evaluations WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        await session.execute(
            text("DELETE FROM false_alert_records WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        await session.execute(
            text("DELETE FROM kpi_metrics WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        await session.execute(
            text("DELETE FROM alerts WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        await session.execute(
            text("DELETE FROM aisoc_cases WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        await session.execute(
            text("DELETE FROM tenants WHERE id = :tid"),
            {"tid": tenant_id},
        )
        await session.commit()

    await engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


async def _insert_alert(session: AsyncSession, tenant_id: uuid.UUID) -> uuid.UUID:
    """Insert a minimal alert row; return its id."""
    alert_id = uuid.uuid4()
    await session.execute(
        text(
            "INSERT INTO alerts (id, tenant_id, title, severity, status, created_at, updated_at) "
            "VALUES (:id, :tid, 'KPI test alert', 'medium', 'new', now(), now())"
        ),
        {"id": alert_id, "tid": tenant_id},
    )
    return alert_id


async def _insert_aisoc_case(
    session: AsyncSession, tenant_id: uuid.UUID, alert_ids: list[uuid.UUID]
) -> uuid.UUID:
    """Insert a minimal aisoc_cases row with the given alert_ids uuid[] array."""
    case_id = uuid.uuid4()
    await session.execute(
        text(
            "INSERT INTO aisoc_cases "
            "(id, tenant_id, title, severity, status, alert_ids, opened_at, created_at, updated_at, created_by) "
            "VALUES (:id, :tid, 'KPI test case', 'medium', 'new', :aids, now(), now(), now(), 'kpi-test')"
        ),
        {"id": case_id, "tid": tenant_id, "aids": [str(a) for a in alert_ids]},
    )
    return case_id


async def _insert_evaluation(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID,
    is_correct: bool,
) -> uuid.UUID:
    """Insert a case_evaluations row; return its id."""
    eval_id = uuid.uuid4()
    evaluator_id = uuid.uuid4()
    await session.execute(
        text(
            "INSERT INTO case_evaluations "
            "(id, tenant_id, case_id, evaluator_id, is_correct, confidence_score, evaluated_at, created_at) "
            "VALUES (:id, :tid, :cid, :evid, :correct, 85, now(), now())"
        ),
        {
            "id": eval_id,
            "tid": tenant_id,
            "cid": case_id,
            "evid": evaluator_id,
            "correct": is_correct,
        },
    )
    return eval_id


# ─────────────────────────────────────────────────────────────────────────────
# FK constraint test — proves the fix is in place
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fk_rejects_evaluation_for_nonexistent_case(db: AsyncSession) -> None:
    """Inserting an evaluation for a case_id not in aisoc_cases must raise FK violation.

    This test proves that the case_evaluations.case_id FK points to aisoc_cases,
    not to the ORM-managed empty ``cases`` table.
    """
    tenant_id: uuid.UUID = db.info["tenant_id"]
    ghost_id = uuid.uuid4()  # never inserted into aisoc_cases

    with pytest.raises(Exception) as exc_info:
        await db.execute(
            text(
                "INSERT INTO case_evaluations "
                "(id, tenant_id, case_id, evaluator_id, is_correct, confidence_score, evaluated_at, created_at) "
                "VALUES (:id, :tid, :cid, :evid, true, 80, now(), now())"
            ),
            {
                "id": uuid.uuid4(),
                "tid": tenant_id,
                "cid": ghost_id,
                "evid": uuid.uuid4(),
            },
        )
        await db.flush()
    await db.rollback()

    # Must be a FK / integrity error, not a 404
    err = str(exc_info.value).lower()
    assert any(word in err for word in ("foreign key", "violates", "fkey", "constraint")), (
        f"Expected FK violation but got: {exc_info.value}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# _calculate_alert_reduction — queries aisoc_cases
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alert_reduction_counts_aisoc_cases(db: AsyncSession) -> None:
    """_calculate_alert_reduction must count rows from aisoc_cases, not the ORM ``cases``."""
    from app.services.kpi_metrics import KPIMetricsCalculator

    tenant_id: uuid.UUID = db.info["tenant_id"]

    # Insert 4 alerts and 1 case in aisoc_cases
    alert_ids = [await _insert_alert(db, tenant_id) for _ in range(4)]
    await db.commit()
    await _insert_aisoc_case(db, tenant_id, alert_ids)
    await db.commit()

    start = datetime.now(UTC) - timedelta(hours=1)
    end = datetime.now(UTC) + timedelta(hours=1)

    result = await KPIMetricsCalculator._calculate_alert_reduction(
        db, str(tenant_id), start, end
    )

    assert result["raw_alerts"] == 4
    assert result["created_cases"] == 1
    assert result["rate"] == pytest.approx(0.75)  # (4 - 1) / 4


# ─────────────────────────────────────────────────────────────────────────────
# _calculate_cluster_purity — unnest on uuid[] column
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cluster_purity_unnests_uuid_array(db: AsyncSession) -> None:
    """_calculate_cluster_purity must work with aisoc_cases.alert_ids (uuid[] column).

    Before the fix this called ``func.unnest(Case.alert_ids)`` on a JSONB column,
    which Postgres rejects. The corrected query uses raw SQL against aisoc_cases.
    """
    from app.services.kpi_metrics import KPIMetricsCalculator

    tenant_id: uuid.UUID = db.info["tenant_id"]

    # 3 alerts in a case; mark 1 as false → purity = 2/3
    alert_ids = [await _insert_alert(db, tenant_id) for _ in range(3)]
    await db.commit()
    case_id = await _insert_aisoc_case(db, tenant_id, alert_ids)
    await db.commit()

    # Insert a false_alert_records row for one of the alerts
    await db.execute(
        text(
            "INSERT INTO false_alert_records "
            "(id, tenant_id, case_id, alert_id, evaluator_id, created_at) "
            "VALUES (:id, :tid, :cid, :aid, :evid, now())"
        ),
        {
            "id": uuid.uuid4(),
            "tid": tenant_id,
            "cid": case_id,
            "aid": alert_ids[0],
            "evid": uuid.uuid4(),
        },
    )
    await db.commit()

    purity, details = await KPIMetricsCalculator._calculate_cluster_purity(
        db, str(tenant_id)
    )

    # 2 correct out of 3 total → 0.666…
    assert purity == pytest.approx(2 / 3, abs=0.01)


# ─────────────────────────────────────────────────────────────────────────────
# Full calculate_daily_metrics — end-to-end
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_calculate_daily_metrics_end_to_end(db: AsyncSession) -> None:
    """Full KPI calculation returns a valid metrics dict with correct shapes."""
    from app.services.kpi_metrics import KPIMetricsCalculator

    tenant_id: uuid.UUID = db.info["tenant_id"]
    today = datetime.now(UTC).strftime("%Y-%m-%d")

    # Insert 5 alerts, 1 case, 2 evaluations (1 correct / 1 incorrect)
    alert_ids = [await _insert_alert(db, tenant_id) for _ in range(5)]
    await db.commit()
    case_id = await _insert_aisoc_case(db, tenant_id, alert_ids[:3])
    await db.commit()
    await _insert_evaluation(db, tenant_id, case_id, is_correct=True)
    # Second case for the false evaluation
    case_id2 = await _insert_aisoc_case(db, tenant_id, alert_ids[3:])
    await db.commit()
    await _insert_evaluation(db, tenant_id, case_id2, is_correct=False)
    await db.commit()

    metrics = await KPIMetricsCalculator.calculate_daily_metrics(db, str(tenant_id), today)

    assert metrics["metric_date"] == today
    assert metrics["metric_period"] == "daily"
    assert metrics["raw_alerts_count"] == 5
    assert metrics["created_cases_count"] == 2
    assert metrics["evaluated_cases_count"] == 2
    assert metrics["correct_cases_count"] == 1
    # precision = 1/2 = 0.5
    assert metrics["precision"] == pytest.approx(0.5, abs=0.01)
    # alert_reduction = (5 - 2) / 5 = 0.6
    assert metrics["alert_reduction_rate"] == pytest.approx(0.6, abs=0.01)


# ─────────────────────────────────────────────────────────────────────────────
# persist_metrics — round-trip through kpi_metrics table
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_persist_and_retrieve_metrics(db: AsyncSession) -> None:
    """Persisted KPI snapshot can be read back via get_latest_metrics."""
    from app.services.kpi_metrics import KPIMetricsCalculator

    tenant_id: uuid.UUID = db.info["tenant_id"]
    today = datetime.now(UTC).strftime("%Y-%m-%d")

    metrics_dict = {
        "metric_date": today,
        "metric_period": "daily",
        "alert_reduction_rate": 0.9,
        "precision": 0.8,
        "cluster_purity": 0.95,
        "false_correlation_rate": 0.02,
        "sample_size": 10,
        "raw_alerts_count": 100,
        "created_cases_count": 10,
        "evaluated_cases_count": 10,
        "correct_cases_count": 8,
        "cases_with_false_alerts_count": 1,
    }

    kpi_row = await KPIMetricsCalculator.persist_metrics(db, str(tenant_id), metrics_dict)
    assert kpi_row.id is not None

    rows = await KPIMetricsCalculator.get_latest_metrics(db, str(tenant_id), "daily", 7)
    assert len(rows) == 1
    assert float(rows[0].precision) == pytest.approx(0.8, abs=0.001)
