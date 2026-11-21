"""KPI Level 1 Metrics Calculator

Calculates four core metrics for measuring case quality:
1. Alert Reduction Rate - (raw_alerts - created_cases) / raw_alerts
2. Precision - correct_cases / all_evaluated_cases
3. Cluster Purity - avg(correct_alerts_in_case / total_alerts_in_case)
4. False Correlation Rate - cases_with_false_alerts / all_cases
"""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import Integer, and_, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.case import CaseEvaluation, FalseAlertRecord, KPIMetrics


class KPIMetricsCalculator:
    """Calculate and persist KPI Level 1 metrics."""

    TARGET_ALERT_REDUCTION = 0.90
    TARGET_PRECISION = 0.75
    TARGET_CLUSTER_PURITY = 0.85
    TARGET_FALSE_CORRELATION_MAX = 0.05

    @staticmethod
    async def calculate_daily_metrics(
        db: AsyncSession,
        tenant_id: str,
        metric_date: str = None,
    ) -> dict:
        """
        Calculate daily KPI metrics for a tenant.

        Args:
            db: AsyncSession
            tenant_id: UUID of tenant
            metric_date: Date to calculate for (YYYY-MM-DD), defaults to yesterday

        Returns:
            dict with calculated metrics
        """
        if metric_date is None:
            metric_date = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%d")

        # Parse date for query ranges
        start_of_day = datetime.strptime(metric_date, "%Y-%m-%d").replace(tzinfo=UTC)
        end_of_day = start_of_day + timedelta(days=1)

        # 1. Alert Reduction Rate
        alert_reduction = await KPIMetricsCalculator._calculate_alert_reduction(
            db, tenant_id, start_of_day, end_of_day
        )

        # 2. Precision
        precision = await KPIMetricsCalculator._calculate_precision(db, tenant_id)

        # 3. Cluster Purity
        cluster_purity, purity_details = await KPIMetricsCalculator._calculate_cluster_purity(
            db, tenant_id
        )

        # 4. False Correlation Rate
        false_correlation = await KPIMetricsCalculator._calculate_false_correlation_rate(
            db, tenant_id
        )

        # Collect detail counts
        raw_alerts_count = alert_reduction["raw_alerts"]
        created_cases_count = alert_reduction["created_cases"]
        evaluated_cases_count = precision["sample_size"]
        correct_cases_count = precision["correct_cases"]
        cases_with_false_alerts = false_correlation["cases_with_false_alerts"]

        return {
            "metric_date": metric_date,
            "metric_period": "daily",
            "alert_reduction_rate": float(alert_reduction["rate"]),
            "precision": float(precision["precision"]),
            "cluster_purity": float(cluster_purity),
            "false_correlation_rate": float(false_correlation["rate"]),
            "sample_size": evaluated_cases_count,
            "raw_alerts_count": raw_alerts_count,
            "created_cases_count": created_cases_count,
            "evaluated_cases_count": evaluated_cases_count,
            "correct_cases_count": correct_cases_count,
            "cases_with_false_alerts_count": cases_with_false_alerts,
        }

    @staticmethod
    async def _calculate_alert_reduction(
        db: AsyncSession,
        tenant_id: str,
        start_date: datetime,
        end_date: datetime,
    ) -> dict:
        """Calculate: (raw_alerts - created_cases) / raw_alerts"""

        # Count all alerts created in period
        stmt = select(func.count(Alert.id)).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= start_date,
                Alert.created_at < end_date,
            )
        )
        result = await db.execute(stmt)
        raw_alerts = result.scalar() or 0

        # Count cases created in period (aisoc_cases is the authoritative table)
        result = await db.execute(
            text(
                "SELECT COUNT(*) FROM aisoc_cases"
                " WHERE tenant_id = :tenant_id"
                "   AND created_at >= :start_date"
                "   AND created_at < :end_date"
            ),
            {"tenant_id": tenant_id, "start_date": start_date, "end_date": end_date},
        )
        created_cases = result.scalar() or 0

        # Calculate rate
        if raw_alerts == 0:
            rate = 0.0
        else:
            rate = (raw_alerts - created_cases) / raw_alerts
            rate = max(0.0, min(1.0, rate))  # Clamp to 0-1

        return {
            "raw_alerts": raw_alerts,
            "created_cases": created_cases,
            "rate": rate,
        }

    @staticmethod
    async def _calculate_precision(db: AsyncSession, tenant_id: str) -> dict:
        """Calculate: correct_cases / all_evaluated_cases"""

        # Get all evaluated cases for tenant
        stmt = select(
            func.count(CaseEvaluation.id),
            func.sum(func.cast(CaseEvaluation.is_correct, Integer)).label("correct_count"),
        ).where(CaseEvaluation.tenant_id == tenant_id)

        result = await db.execute(stmt)
        total_evaluated, correct_count = result.one()
        total_evaluated = total_evaluated or 0
        correct_count = correct_count or 0

        if total_evaluated == 0:
            precision = 0.0
        else:
            precision = correct_count / total_evaluated
            precision = max(0.0, min(1.0, precision))

        return {
            "sample_size": total_evaluated,
            "correct_cases": correct_count,
            "precision": precision,
        }

    @staticmethod
    async def _calculate_cluster_purity(db: AsyncSession, tenant_id: str) -> tuple:
        """
        Calculate: avg(correct_alerts_in_case / total_alerts_in_case)
        for all cases that have false_alert_records
        """

        # Get all cases with false alerts
        stmt = select(
            FalseAlertRecord.case_id,
            func.count(FalseAlertRecord.id).label("false_alerts_count"),
        ).where(
            FalseAlertRecord.tenant_id == tenant_id
        ).group_by(FalseAlertRecord.case_id)

        result = await db.execute(stmt)
        cases_with_false_alerts = {row[0]: row[1] for row in result.fetchall()}

        if not cases_with_false_alerts:
            return 0.95, {}  # Default high purity if no false alerts recorded

        purities = []
        for case_id, false_count in cases_with_false_alerts.items():
            # Count alerts listed in aisoc_cases.alert_ids (uuid[] column)
            result = await db.execute(
                text(
                    "SELECT COUNT(*) FROM alerts"
                    " WHERE tenant_id = :tenant_id"
                    "   AND id = ANY("
                    "       SELECT unnest(alert_ids) FROM aisoc_cases WHERE id = :case_id"
                    "   )"
                ),
                {"tenant_id": tenant_id, "case_id": str(case_id)},
            )
            total_alerts = result.scalar() or 0

            if total_alerts > 0:
                correct_alerts = total_alerts - false_count
                purity = correct_alerts / total_alerts
                purity = max(0.0, min(1.0, purity))
                purities.append(purity)

        cluster_purity = sum(purities) / len(purities) if purities else 0.95

        return cluster_purity, {"case_purities": purities}

    @staticmethod
    async def _calculate_false_correlation_rate(db: AsyncSession, tenant_id: str) -> dict:
        """Calculate: cases_with_false_alerts / all_evaluated_cases"""

        # Count evaluated cases
        stmt = select(func.count(CaseEvaluation.id)).where(
            CaseEvaluation.tenant_id == tenant_id
        )
        result = await db.execute(stmt)
        total_evaluated = result.scalar() or 0

        # Count distinct cases that have false alerts
        stmt = select(func.count(func.distinct(FalseAlertRecord.case_id))).where(
            FalseAlertRecord.tenant_id == tenant_id
        )
        result = await db.execute(stmt)
        cases_with_false_alerts = result.scalar() or 0

        if total_evaluated == 0:
            rate = 0.0
        else:
            rate = cases_with_false_alerts / total_evaluated
            rate = max(0.0, min(1.0, rate))

        return {
            "total_evaluated": total_evaluated,
            "cases_with_false_alerts": cases_with_false_alerts,
            "rate": rate,
        }

    @staticmethod
    async def persist_metrics(
        db: AsyncSession,
        tenant_id: str,
        metrics: dict,
    ) -> KPIMetrics:
        """Persist calculated metrics to database."""

        kpi = KPIMetrics(
            tenant_id=tenant_id,
            metric_date=metrics["metric_date"],
            metric_period=metrics["metric_period"],
            alert_reduction_rate=Decimal(str(metrics["alert_reduction_rate"])),
            precision=Decimal(str(metrics["precision"])),
            cluster_purity=Decimal(str(metrics["cluster_purity"])),
            false_correlation_rate=Decimal(str(metrics["false_correlation_rate"])),
            sample_size=metrics["sample_size"],
            raw_alerts_count=metrics["raw_alerts_count"],
            created_cases_count=metrics["created_cases_count"],
            evaluated_cases_count=metrics["evaluated_cases_count"],
            correct_cases_count=metrics["correct_cases_count"],
            cases_with_false_alerts_count=metrics["cases_with_false_alerts_count"],
        )

        db.add(kpi)
        await db.commit()
        await db.refresh(kpi)

        return kpi

    @staticmethod
    async def get_latest_metrics(
        db: AsyncSession,
        tenant_id: str,
        period: str = "daily",
        days: int = 30,
    ) -> list[KPIMetrics]:
        """Fetch latest KPI metrics for a tenant."""

        cutoff_date = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d")

        stmt = select(KPIMetrics).where(
            and_(
                KPIMetrics.tenant_id == tenant_id,
                KPIMetrics.metric_period == period,
                KPIMetrics.metric_date >= cutoff_date,
            )
        ).order_by(KPIMetrics.metric_date.desc())

        result = await db.execute(stmt)
        return result.scalars().all()

    @staticmethod
    async def get_metric_summary(
        db: AsyncSession,
        tenant_id: str,
        period: str = "daily",
    ) -> dict | None:
        """Get the most recent metric summary."""

        stmt = select(KPIMetrics).where(
            and_(
                KPIMetrics.tenant_id == tenant_id,
                KPIMetrics.metric_period == period,
            )
        ).order_by(KPIMetrics.metric_date.desc()).limit(1)

        result = await db.execute(stmt)
        kpi = result.scalars().first()

        if not kpi:
            return None

        return {
            "date": kpi.metric_date,
            "period": kpi.metric_period,
            "metrics": {
                "alert_reduction_rate": {
                    "value": float(kpi.alert_reduction_rate),
                    "target": KPIMetricsCalculator.TARGET_ALERT_REDUCTION,
                    "status": "✅ PASS" if float(kpi.alert_reduction_rate) >= KPIMetricsCalculator.TARGET_ALERT_REDUCTION else "❌ FAIL",
                },
                "precision": {
                    "value": float(kpi.precision),
                    "target": KPIMetricsCalculator.TARGET_PRECISION,
                    "status": "✅ PASS" if float(kpi.precision) >= KPIMetricsCalculator.TARGET_PRECISION else "❌ FAIL",
                },
                "cluster_purity": {
                    "value": float(kpi.cluster_purity),
                    "target": KPIMetricsCalculator.TARGET_CLUSTER_PURITY,
                    "status": (
                        "\u2705 PASS" if float(kpi.cluster_purity)
                        >= KPIMetricsCalculator.TARGET_CLUSTER_PURITY
                        else "\u274c FAIL"
                    ),
                },
                "false_correlation_rate": {
                    "value": float(kpi.false_correlation_rate),
                    "target": KPIMetricsCalculator.TARGET_FALSE_CORRELATION_MAX,
                    "status": (
                        "\u2705 PASS" if float(kpi.false_correlation_rate)
                        <= KPIMetricsCalculator.TARGET_FALSE_CORRELATION_MAX
                        else "\u274c FAIL"
                    ),
                },
            },
            "details": {
                "sample_size": kpi.sample_size,
                "raw_alerts": kpi.raw_alerts_count,
                "created_cases": kpi.created_cases_count,
                "evaluated_cases": kpi.evaluated_cases_count,
                "correct_cases": kpi.correct_cases_count,
                "cases_with_false_alerts": kpi.cases_with_false_alerts_count,
            },
        }
