"""KPI Level 1 Evaluation and Metrics Endpoints

Implements case evaluation (ground-truth marking) and KPI metrics calculation.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select

from app.api.v1.deps import AuthUser, DBSession
from app.models.case import CaseEvaluation, FalseAlertRecord, KPIMetrics
from app.services.kpi_metrics import KPIMetricsCalculator

router = APIRouter(prefix="/kpi", tags=["KPI Metrics"])


# ────────────────────────────────────────────────────────────────────────────
# Pydantic Models
# ────────────────────────────────────────────────────────────────────────────


class EvaluateCaseRequest(BaseModel):
    """Record ground-truth evaluation of a case."""

    is_correct: bool = Field(
        ...,
        description="TRUE=valid case, FALSE=false correlation"
    )
    confidence_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Evaluator confidence level (0-100)"
    )
    notes: str | None = Field(
        None,
        max_length=2000,
        description="Why this case is correct or incorrect"
    )


class FalseAlertMarkRequest(BaseModel):
    """Mark a specific alert as irrelevant in a case."""

    alert_id: str = Field(..., description="UUID of alert that doesn't belong")
    reason: str | None = Field(
        None,
        max_length=255,
        description="Why this alert doesn't belong in the case"
    )


class KPIValue(BaseModel):
    """Single KPI metric with target and status."""

    value: float = Field(..., ge=0.0, le=1.0)
    target: float = Field(..., ge=0.0, le=1.0)
    status: str = Field(..., description="✅ PASS or ❌ FAIL")


class KPIMetricsResponse(BaseModel):
    """Complete KPI metrics summary."""

    date: str = Field(..., description="YYYY-MM-DD")
    period: str = Field(..., description="daily/weekly/monthly")

    alert_reduction_rate: KPIValue = Field(..., description="(raw_alerts - cases) / raw_alerts")
    precision: KPIValue = Field(..., description="correct_cases / evaluated_cases")
    cluster_purity: KPIValue = Field(..., description="avg(correct_alerts / total_alerts)")
    false_correlation_rate: KPIValue = Field(..., description="cases_with_false_alerts / evaluated_cases")

    details: dict = Field(..., description="Raw calculation details")
    calculated_at: datetime


class EvaluationResponse(BaseModel):
    """Response after recording evaluation."""

    case_id: str
    status: str = "evaluated"
    is_correct: bool
    confidence_score: int
    evaluated_at: datetime


class FalseAlertResponse(BaseModel):
    """Response after marking false alert."""

    case_id: str
    alert_id: str
    status: str = "marked"
    marked_at: datetime


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.post(
    "/cases/{case_id}/evaluate",
    response_model=EvaluationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record case evaluation (correct/incorrect)"
)
async def evaluate_case(
    case_id: str,
    payload: EvaluateCaseRequest,
    db: DBSession,
    user: AuthUser,
) -> EvaluationResponse:
    """
    Record ground-truth evaluation of a case.

    **Purpose:** Analyst marks case as correct or incorrect to build training data.

    **Request:**
    ```json
    {
      "is_correct": true,
      "confidence_score": 85,
      "notes": "Valid campaign, all alerts are related"
    }
    ```

    **Response:**
    - Returns evaluation record with timestamp
    - Enables KPI calculation
    - Supports model improvement feedback

    **Tenant Isolation:** Case must belong to user's tenant
    """

    tenant_id = user.tenant_id
    evaluator_id = user.user_id

    # Verify case exists and belongs to tenant (aisoc_cases is authoritative)
    from sqlalchemy import text as _text
    case_result = await db.execute(
        _text("SELECT id FROM aisoc_cases WHERE id = :case_id AND tenant_id = :tenant_id"),
        {"case_id": case_id, "tenant_id": str(tenant_id)},
    )
    case_row = case_result.scalar_one_or_none()

    if not case_row:
        raise HTTPException(status_code=404, detail="Case not found")

    # Record evaluation
    now = datetime.now(UTC)
    evaluation = CaseEvaluation(
        tenant_id=tenant_id,
        case_id=case_id,
        evaluator_id=evaluator_id,
        is_correct=payload.is_correct,
        confidence_score=payload.confidence_score,
        notes=payload.notes,
        evaluated_at=now,
        created_at=now,
    )

    try:
        db.add(evaluation)
        await db.flush()
        await db.commit()
        await db.refresh(evaluation)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to record evaluation: {str(e)}") from e

    return EvaluationResponse(
        case_id=case_id,
        status="evaluated",
        is_correct=payload.is_correct,
        confidence_score=payload.confidence_score,
        evaluated_at=evaluation.evaluated_at,
    )


@router.post(
    "/cases/{case_id}/false-alerts",
    response_model=FalseAlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Mark alert as irrelevant in case"
)
async def mark_false_alert(
    case_id: str,
    payload: FalseAlertMarkRequest,
    db: DBSession,
    user: AuthUser,
) -> FalseAlertResponse:
    """
    Mark a specific alert as irrelevant/false in a case.

    **Purpose:** Analyst identifies which alerts don't belong, improving case purity.

    **Request:**
    ```json
    {
      "alert_id": "550e8400-e29b-41d4-a716-446655440000",
      "reason": "Different attack vector, not related to main campaign"
    }
    ```

    **Response:**
    - Returns marked alert record
    - Affects cluster_purity KPI calculation
    - Supports false correlation rate tracking

    **KPI Impact:**
    - ↑ false_correlation_rate if many alerts marked per case
    - ↓ cluster_purity for this case
    """

    tenant_id = user.tenant_id
    evaluator_id = user.user_id

    # Verify case exists and belongs to tenant (aisoc_cases is authoritative)
    from sqlalchemy import text as _text

    from app.models.alert import Alert

    case_result = await db.execute(
        _text("SELECT id FROM aisoc_cases WHERE id = :case_id AND tenant_id = :tenant_id"),
        {"case_id": case_id, "tenant_id": str(tenant_id)},
    )
    case_row = case_result.scalar_one_or_none()

    if not case_row:
        raise HTTPException(status_code=404, detail="Case not found")

    # Verify alert exists and belongs to tenant
    alert_stmt = select(Alert.id).where(
        and_(
            Alert.id == payload.alert_id,
            Alert.tenant_id == tenant_id,
        )
    )
    alert_result = await db.execute(alert_stmt)
    alert_row = alert_result.scalar_one_or_none()

    if not alert_row:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Record false alert
    now = datetime.now(UTC)
    false_alert = FalseAlertRecord(
        tenant_id=tenant_id,
        case_id=case_id,
        alert_id=payload.alert_id,
        evaluator_id=evaluator_id,
        reason=payload.reason,
        created_at=now,
    )

    try:
        db.add(false_alert)
        await db.flush()
        await db.commit()
        await db.refresh(false_alert)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to mark false alert: {str(e)}") from e

    return FalseAlertResponse(
        case_id=case_id,
        alert_id=str(payload.alert_id),
        status="marked",
        marked_at=false_alert.created_at,
    )


@router.get(
    "/metrics",
    response_model=KPIMetricsResponse,
    summary="Get latest KPI metrics for tenant"
)
async def get_kpi_metrics(
    db: DBSession,
    user: AuthUser,
    period: str = Query("daily", pattern="^(daily|weekly|monthly)$"),
) -> KPIMetricsResponse:
    """
    Fetch the most recent KPI metrics for the tenant.

    **Query Parameters:**
    - `period`: daily (default) | weekly | monthly

    **Response:**
    - alert_reduction_rate: Target > 0.90
    - precision: Target > 0.75
    - cluster_purity: Target > 0.85
    - false_correlation_rate: Target < 0.05

    **Example:**
    ```bash
    curl "http://localhost:8888/api/v1/kpi/metrics?period=daily"
    ```

    **Note:** Metrics are typically calculated daily at midnight (UTC).
    If no metrics exist yet, returns 404.
    """

    tenant_id = user.tenant_id

    # Fetch most recent metric
    stmt = select(KPIMetrics).where(
        and_(
            KPIMetrics.tenant_id == tenant_id,
            KPIMetrics.metric_period == period,
        )
    ).order_by(KPIMetrics.metric_date.desc()).limit(1)

    result = await db.execute(stmt)
    kpi = result.scalars().first()

    if not kpi:
        raise HTTPException(status_code=404, detail="No KPI metrics available yet")

    # Format response
    metric_summary = await KPIMetricsCalculator.get_metric_summary(
        db, str(tenant_id), period
    )

    if not metric_summary:
        raise HTTPException(status_code=404, detail="No KPI metrics available")

    return KPIMetricsResponse(
        date=metric_summary["date"],
        period=metric_summary["period"],
        alert_reduction_rate=KPIValue(**metric_summary["metrics"]["alert_reduction_rate"]),
        precision=KPIValue(**metric_summary["metrics"]["precision"]),
        cluster_purity=KPIValue(**metric_summary["metrics"]["cluster_purity"]),
        false_correlation_rate=KPIValue(**metric_summary["metrics"]["false_correlation_rate"]),
        details=metric_summary["details"],
        calculated_at=kpi.calculated_at,
    )


@router.get(
    "/metrics/history",
    response_model=list[KPIMetricsResponse],
    summary="Fetch KPI metrics history (last 30 days)"
)
async def get_kpi_metrics_history(
    db: DBSession,
    user: AuthUser,
    period: str = Query("daily", pattern="^(daily|weekly|monthly)$"),
    days: int = Query(30, ge=1, le=365),
) -> list[KPIMetricsResponse]:
    """
    Fetch KPI metrics history for trend analysis.

    **Query Parameters:**
    - `period`: daily (default) | weekly | monthly
    - `days`: Number of days to fetch (default 30, max 365)

    **Response:**
    - List of KPI metrics sorted by date (newest first)
    - Each entry includes all 4 metrics + targets + pass/fail status

    **Use Cases:**
    - Dashboard trend charts
    - Month-end reports
    - Anomaly detection

    **Example:**
    ```bash
    curl "http://localhost:8888/api/v1/kpi/metrics/history?period=daily&days=30"
    ```
    """

    tenant_id = user.tenant_id

    # Fetch metrics history
    metrics = await KPIMetricsCalculator.get_latest_metrics(
        db, str(tenant_id), period, days
    )

    if not metrics:
        return []

    # Convert to response objects
    responses = []
    for kpi in metrics:
        summary = await KPIMetricsCalculator.get_metric_summary(
            db, str(tenant_id), period
        )

        if summary:
            responses.append(
                KPIMetricsResponse(
                    date=kpi.metric_date,
                    period=kpi.metric_period,
                    alert_reduction_rate=KPIValue(
                        value=float(kpi.alert_reduction_rate),
                        target=KPIMetricsCalculator.TARGET_ALERT_REDUCTION,
                        status="✅ PASS" if float(kpi.alert_reduction_rate) >= KPIMetricsCalculator.TARGET_ALERT_REDUCTION else "❌ FAIL",
                    ),
                    precision=KPIValue(
                        value=float(kpi.precision),
                        target=KPIMetricsCalculator.TARGET_PRECISION,
                        status="✅ PASS" if float(kpi.precision) >= KPIMetricsCalculator.TARGET_PRECISION else "❌ FAIL",
                    ),
                    cluster_purity=KPIValue(
                        value=float(kpi.cluster_purity),
                        target=KPIMetricsCalculator.TARGET_CLUSTER_PURITY,
                        status=(
                            "\u2705 PASS" if float(kpi.cluster_purity)
                            >= KPIMetricsCalculator.TARGET_CLUSTER_PURITY
                            else "\u274c FAIL"
                        ),
                    ),
                    false_correlation_rate=KPIValue(
                        value=float(kpi.false_correlation_rate),
                        target=KPIMetricsCalculator.TARGET_FALSE_CORRELATION_MAX,
                        status=(
                            "\u2705 PASS" if float(kpi.false_correlation_rate)
                            <= KPIMetricsCalculator.TARGET_FALSE_CORRELATION_MAX
                            else "\u274c FAIL"
                        ),
                    ),
                    details={
                        "sample_size": kpi.sample_size,
                        "raw_alerts": kpi.raw_alerts_count,
                        "created_cases": kpi.created_cases_count,
                        "evaluated_cases": kpi.evaluated_cases_count,
                        "correct_cases": kpi.correct_cases_count,
                        "cases_with_false_alerts": kpi.cases_with_false_alerts_count,
                    },
                    calculated_at=kpi.calculated_at,
                )
            )

    return responses


@router.get(
    "/metrics/calculate",
    response_model=KPIMetricsResponse,
    summary="Force calculation and persist daily KPI metrics"
)
async def calculate_kpi_metrics(
    db: DBSession,
    user: AuthUser,
    metric_date: str = Query(None, description="YYYY-MM-DD, defaults to yesterday"),
) -> KPIMetricsResponse:
    """
    **ADMIN ONLY:** Calculate and persist KPI metrics for a specific date.

    **Query Parameters:**
    - `metric_date`: Date to calculate for (YYYY-MM-DD). Defaults to yesterday.

    **Use Cases:**
    - Manual calculation trigger (normally runs as a scheduler job)
    - Backfill missing metrics
    - Testing

    **Response:**
    - Calculated metrics + targets + pass/fail status
    - Saved to database for history tracking

    **Note:** Idempotent — calculating the same date twice produces the same result.
    """

    tenant_id = user.tenant_id

    # Calculate metrics
    metrics = await KPIMetricsCalculator.calculate_daily_metrics(
        db, str(tenant_id), metric_date
    )

    # Persist to database
    persisted = await KPIMetricsCalculator.persist_metrics(
        db, str(tenant_id), metrics
    )

    # Format response
    summary = await KPIMetricsCalculator.get_metric_summary(
        db, str(tenant_id), metrics["metric_period"]
    )

    if not summary:
        raise HTTPException(status_code=500, detail="Failed to calculate metrics")

    return KPIMetricsResponse(
        date=summary["date"],
        period=summary["period"],
        alert_reduction_rate=KPIValue(**summary["metrics"]["alert_reduction_rate"]),
        precision=KPIValue(**summary["metrics"]["precision"]),
        cluster_purity=KPIValue(**summary["metrics"]["cluster_purity"]),
        false_correlation_rate=KPIValue(**summary["metrics"]["false_correlation_rate"]),
        details=summary["details"],
        calculated_at=persisted.calculated_at,
    )
