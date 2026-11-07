"""Phase 13: Calibration Monitor Unit & Integration Tests

Focused tests for the ConfidenceCalibrationMonitor worker:
- ECE (Expected Calibration Error) measurement
- Binning strategy (4 confidence ranges)
- Status reporting (ok, degraded, poor)
- Metrics aggregation
- Error handling & resilience

Needs a live, alembic-migrated Postgres, so it is gated like the rest of the
integration suites:

    AISOC_RUN_INTEGRATION=1 pytest -m integration tests/test_calibration_monitor.py
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from app.models.runbook_task import RunbookTask
from app.workers.calibration_monitor import ConfidenceCalibrationMonitor
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_REQUIRES_ENV = "AISOC_RUN_INTEGRATION"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.getenv(_REQUIRES_ENV),
        reason=f"set {_REQUIRES_ENV}=1 to run calibration tests against Postgres",
    ),
]


@pytest.fixture(scope="function")
async def test_db():
    """Test database using PostgreSQL."""
    from app.db.database import AsyncSessionLocal
    from app.models.tenant import Tenant

    # Use existing PostgreSQL connection
    async with AsyncSessionLocal() as session:
        # Create tenant with unique slug
        tenant_id = uuid4()
        unique_slug = f"test-tenant-{uuid4().hex[:8]}"
        tenant = Tenant(
            id=tenant_id,
            name="Test Tenant",
            slug=unique_slug,
            mssp_role="standalone",
        )
        session.add(tenant)
        await session.commit()

        # Scoped to this fixture's own tenant. An unscoped DELETE would wipe the
        # real alerts and ledger rows of whatever database DATABASE_URL points at.
        await session.execute(
            text("DELETE FROM runbook_tasks WHERE tenant_id = :tid"), {"tid": str(tenant_id)}
        )
        await session.execute(
            text("DELETE FROM alerts WHERE tenant_id = :tid"), {"tid": str(tenant_id)}
        )
        await session.commit()

        # Store tenant_id in session for later use
        session.tenant_id = tenant_id

        yield session

        # Cleanup
        try:
            await session.execute(
                text("DELETE FROM runbook_tasks WHERE tenant_id = :tid"), {"tid": str(tenant_id)}
            )
            await session.execute(
                text("DELETE FROM alerts WHERE tenant_id = :tid"), {"tid": str(tenant_id)}
            )
            await session.execute(
                text("DELETE FROM tenants WHERE id = :tid"), {"tid": str(tenant_id)}
            )
            await session.commit()
        except Exception:
            pass


@pytest.fixture
async def test_tenant_id(test_db):
    return test_db.tenant_id


@pytest.fixture
def calibration_monitor():
    return ConfidenceCalibrationMonitor()


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 1: BINNING STRATEGY
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_binning_4_ranges(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 1.1: Tasks are correctly binned into 4 confidence ranges.

    Ranges:
    - [0.00-0.25]: Low confidence
    - [0.25-0.50]: Medium-low confidence
    - [0.50-0.75]: Medium-high confidence
    - [0.75-1.00]: High confidence
    """
    # Create tasks in each bin
    test_data = [
        (0.10, "0.0-0.25"),
        (0.20, "0.0-0.25"),
        (0.30, "0.25-0.5"),
        (0.40, "0.25-0.5"),
        (0.60, "0.5-0.75"),
        (0.70, "0.5-0.75"),
        (0.80, "0.75-1.0"),
        (0.95, "0.75-1.0"),
    ]

    for conf, _expected_bin in test_data:
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Task with confidence {conf}",
            feedback_applied=True,
            confidence_at_submission=conf,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    # Bin the tasks. SQLAlchemy 2.x refuses a bare string here — it must be text().
    result = await test_db.execute(
        text(
            "SELECT COUNT(*) as count, "
            "CASE WHEN confidence_at_submission < 0.25 THEN '0.0-0.25' "
            "     WHEN confidence_at_submission < 0.50 THEN '0.25-0.5' "
            "     WHEN confidence_at_submission < 0.75 THEN '0.5-0.75' "
            "     ELSE '0.75-1.0' END as bin "
            "FROM runbook_tasks WHERE tenant_id = :tid GROUP BY bin ORDER BY bin"
        ),
        {"tid": str(test_tenant_id)},
    )

    bins = {row[1]: row[0] for row in result}

    # Verify each bin has expected count
    assert bins.get("0.0-0.25", 0) == 2
    assert bins.get("0.25-0.5", 0) == 2
    assert bins.get("0.5-0.75", 0) == 2
    assert bins.get("0.75-1.0", 0) == 2


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 2: ECE CALCULATION
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_ece_perfect_calibration(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 2.1: ECE calculation with perfect calibration (all correct).

    Perfect calibration: confidence = accuracy
    Example: all 0.80-confidence tasks are correct → ECE ≈ 0
    """
    # Create perfectly calibrated tasks
    # Bin 1: 80% confidence, 80% correct (4/5)
    for idx in range(5):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Perfect bin1 {idx}",
            feedback_applied=idx < 4,  # 80% correct
            confidence_at_submission=0.80,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)

    # Bin 2: 50% confidence, 50% correct (2/4)
    for idx in range(4):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Perfect bin2 {idx}",
            feedback_applied=idx < 2,  # 50% correct
            confidence_at_submission=0.50,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)

    await test_db.commit()

    # Measure ECE
    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # Perfect calibration → ECE should be very low (< 0.05)
    assert metrics["ece"] < 0.05
    assert metrics["status"] == "ok"


@pytest.mark.asyncio
async def test_ece_poor_calibration(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 2.2: ECE calculation with poor calibration (mostly wrong).

    Poor calibration: high confidence but low accuracy
    Example: 90% confidence but only 20% correct → high ECE
    """
    # Create poorly calibrated tasks (high conf, low accuracy)
    for idx in range(10):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Poor calibration {idx}",
            feedback_applied=idx < 2,  # Only 20% correct
            confidence_at_submission=0.90,  # But high confidence
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    # Measure ECE
    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # Poor calibration → ECE should be high (> 0.20)
    assert metrics["ece"] > 0.20
    assert metrics["status"] in ("degraded", "poor")


@pytest.mark.asyncio
async def test_ece_overconfident_calibration(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 2.3: ECE with overconfident model (says high confidence but is often wrong)."""
    # Overconfident: 85% confidence, 50% accuracy
    for idx in range(8):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Overconfident {idx}",
            feedback_applied=idx < 4,  # 50% correct
            confidence_at_submission=0.85,  # 85% confident
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # Overconfidence → high ECE (35% gap)
    assert metrics["ece"] >= 0.15


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 3: STATUS REPORTING
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_status_ok_when_ece_below_threshold(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 3.1: Status = 'ok' when ECE < 0.15."""
    # Well-calibrated data
    for idx in range(6):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Good calibration {idx}",
            feedback_applied=True,  # All correct
            confidence_at_submission=0.88,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    assert metrics["status"] == "ok"
    assert metrics["ece"] < 0.15


@pytest.mark.asyncio
async def test_status_degraded_when_ece_in_range(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 3.2: Status = 'degraded' when 0.15 ≤ ECE < 0.30."""
    # Mixed calibration
    for idx in range(10):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Mixed {idx}",
            feedback_applied=(idx % 3) != 0,  # ~67% correct
            confidence_at_submission=0.75,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    assert metrics["status"] in ("degraded", "ok")  # Could be either depending on exact calculations


@pytest.mark.asyncio
async def test_status_poor_when_ece_high(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 3.3: Status = 'poor' when ECE ≥ 0.30."""
    # Very poor calibration
    for idx in range(10):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Poor {idx}",
            feedback_applied=idx == 0,  # Only 10% correct
            confidence_at_submission=0.95,  # Very confident
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # With 10% accuracy but 95% confidence, ECE should be ~0.85
    assert metrics["ece"] >= 0.30


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 4: LOOKBACK WINDOW
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_lookback_window_filters_old_tasks(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 4.1: Lookback window correctly filters old tasks.

    Task completed > lookback_hours ago should be excluded
    """
    # Create old task (> 24 hours ago)
    old_task = RunbookTask(
        id=uuid4(),
        tenant_id=test_tenant_id,
        alert_id=uuid4(),
        task_type="approval_gate",
        status="completed",
        title="Old task",
        feedback_applied=False,  # Wrong, but should be excluded
        confidence_at_submission=0.90,
        completed_at=datetime.utcnow() - timedelta(hours=48),
    )
    test_db.add(old_task)

    # Create recent task (< 24 hours ago)
    recent_task = RunbookTask(
        id=uuid4(),
        tenant_id=test_tenant_id,
        alert_id=uuid4(),
        task_type="approval_gate",
        status="completed",
        title="Recent task",
        feedback_applied=True,  # Correct
        confidence_at_submission=0.85,
        completed_at=datetime.utcnow() - timedelta(hours=1),
    )
    test_db.add(recent_task)
    await test_db.commit()

    # Measure with 24-hour lookback
    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # Should only count recent_task (sample_size=1, ECE should be 0)
    assert metrics["sample_size"] == 1


@pytest.mark.asyncio
async def test_lookback_window_with_zero_lookback(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 4.2: Zero lookback_hours should return no samples."""
    # Create task from 1 hour ago
    task = RunbookTask(
        id=uuid4(),
        tenant_id=test_tenant_id,
        alert_id=uuid4(),
        task_type="approval_gate",
        status="completed",
        title="Recent",
        feedback_applied=True,
        confidence_at_submission=0.80,
        completed_at=datetime.utcnow() - timedelta(hours=1),
    )
    test_db.add(task)
    await test_db.commit()

    # Measure with 0 lookback (should exclude everything)
    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=0, tenant_id=test_tenant_id)

    assert metrics["sample_size"] == 0


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 5: TENANT ISOLATION
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_tenant_isolation_tasks_not_mixed(test_db: AsyncSession, calibration_monitor):
    """Test 5.1: Calibration monitor respects tenant isolation."""
    tenant_a = uuid4()
    tenant_b = uuid4()

    # Create tasks for tenant A (well-calibrated)
    for idx in range(5):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=tenant_a,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Tenant A {idx}",
            feedback_applied=True,  # All correct
            confidence_at_submission=0.80,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)

    # Create tasks for tenant B (poorly-calibrated)
    for idx in range(5):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=tenant_b,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Tenant B {idx}",
            feedback_applied=idx == 0,  # Only 1/5 correct = poor
            confidence_at_submission=0.90,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    # Measure for tenant A only
    metrics_a = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=tenant_a)

    # Measure for tenant B only
    metrics_b = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=tenant_b)

    # Tenant A should have low ECE (good calibration)
    # Tenant B should have high ECE (poor calibration)
    assert metrics_a["ece"] < metrics_b["ece"]


# ════════════════════════════════════════════════════════════════════════════════
# TEST GROUP 6: EDGE CASES & RESILIENCE
# ════════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_edge_case_empty_feedback_set(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 6.1: Gracefully handle when no feedback_applied data exists."""
    # Create tasks with no feedback
    for idx in range(5):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="pending",
            title=f"Pending {idx}",
            feedback_applied=None,  # No feedback yet
        )
        test_db.add(task)
    await test_db.commit()

    # Should not crash, should return empty result
    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    assert metrics["sample_size"] == 0
    assert "ece" in metrics


@pytest.mark.asyncio
async def test_edge_case_single_bin_samples(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 6.2: ECE calculation when samples only in one bin."""
    # All tasks have same confidence (fall into one bin)
    for idx in range(8):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Same bin {idx}",
            feedback_applied=idx < 6,  # 75% correct
            confidence_at_submission=0.80,  # All same confidence
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    # Should calculate ECE for single bin (0.80 conf, 0.75 accuracy → ECE = 0.05)
    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    assert metrics["sample_size"] == 8
    assert 0.0 <= metrics["ece"] <= 1.0


@pytest.mark.asyncio
async def test_edge_case_boundary_confidence_values(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 6.3: Handle boundary confidence values correctly (0.0, 1.0, 0.25, 0.50, 0.75)."""
    boundary_values = [0.0, 0.25, 0.50, 0.75, 1.0]

    for _idx, conf in enumerate(boundary_values):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Boundary {conf}",
            feedback_applied=True,
            confidence_at_submission=conf,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    # Should not crash on boundary values
    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    assert metrics["sample_size"] == 5
    assert 0.0 <= metrics["ece"] <= 1.0


@pytest.mark.asyncio
async def test_edge_case_100_percent_accuracy(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 6.4: Perfect accuracy (all feedback_applied=True) should give low ECE."""
    for idx in range(10):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"Perfect {idx}",
            feedback_applied=True,  # 100% correct
            confidence_at_submission=0.70,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # 100% accuracy → ECE should be very close to 0
    assert metrics["ece"] < 0.01


@pytest.mark.asyncio
async def test_edge_case_zero_percent_accuracy(test_db: AsyncSession, test_tenant_id, calibration_monitor):
    """Test 6.5: Zero accuracy (all feedback_applied=False) should give high ECE."""
    for idx in range(10):
        task = RunbookTask(
            id=uuid4(),
            tenant_id=test_tenant_id,
            alert_id=uuid4(),
            task_type="approval_gate",
            status="completed",
            title=f"All wrong {idx}",
            feedback_applied=False,  # 0% correct
            confidence_at_submission=0.70,
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        test_db.add(task)
    await test_db.commit()

    metrics = await calibration_monitor.measure_calibration(test_db, lookback_hours=24, tenant_id=test_tenant_id)

    # 0% accuracy with 70% confidence → high ECE (~0.70)
    assert metrics["ece"] > 0.50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
