"""Poll receipt status with a dedicated scoped PAT. Run independently of submission."""

import asyncio
import logging
import random

import asyncpg
import httpx
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .binding import Binding, BindingError, tls_context
from .worker import DeliveryError, receipt_state, request_json

logger = logging.getLogger(__name__)
DATABASE_UNAVAILABLE = (asyncpg.PostgresConnectionError, OSError, TimeoutError)

CLAIM = """
WITH due AS (
    SELECT d.id FROM tkg_alert_deliveries d JOIN workspace_tkg_bindings b
      ON (b.id,b.tenant_id)=(d.binding_id,d.tenant_id)
    WHERE d.state='pending_materialization' AND d.receipt_id IS NOT NULL
      AND d.reconcile_after <= now() AND b.enabled
    ORDER BY d.reconcile_after,d.id
    LIMIT $1 FOR UPDATE OF d SKIP LOCKED
)
UPDATE tkg_alert_deliveries d SET
  reconcile_after=now()+$2::double precision*interval '1 second',
  reconcile_fence=d.reconcile_fence+1
FROM due WHERE d.id=due.id
RETURNING d.id,d.tenant_id,d.binding_id,d.receipt_id,d.reconcile_fence,d.reconcile_failures
"""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AISOC_TKG_RECONCILE_", extra="ignore")
    enabled: bool = False
    interval_seconds: int = Field(30, ge=1, le=300)
    batch_size: int = Field(30, ge=20, le=50)
    concurrency: int = Field(1, ge=1, le=2)
    request_timeout_seconds: float = Field(10, ge=1, le=20)
    pending_warn_seconds: int = Field(300, ge=30, le=86400)
    pending_alert_seconds: int = Field(1800, ge=60, le=604800)
    database_url: str = Field("", repr=False)

    @model_validator(mode="after")
    def check_age_thresholds(self):
        if self.pending_alert_seconds <= self.pending_warn_seconds:
            raise ValueError("pending alert age must exceed warning age")
        return self


async def fetch_status(pool, http, row, settings):
    async with pool.acquire() as conn:
        binding_row = await conn.fetchrow(
            """SELECT id,tenant_id,instance,kb_id,source_id,tkg_tenant,source_system,source_instance,connector_id,enabled
               FROM workspace_tkg_bindings WHERE tenant_id=$1 AND id=$2 AND enabled""",
            row["tenant_id"], row["binding_id"],
        )
    if binding_row is None:
        return
    binding = Binding.from_row(binding_row, row["tenant_id"])
    delay = float(settings.interval_seconds)
    result = {}
    code = None
    try:
        url = f"{binding.origin()}/api/v1/kbs/{binding.kb_id}/knowledge/receipts/{row['receipt_id']}/status"
        result = await request_json(http, "GET", url, binding.credential("diagnostics"), timeout=settings.request_timeout_seconds)
        if result.get("receipt_id") != str(row["receipt_id"]) or result.get("source_id") != str(binding.source_id):
            raise DeliveryError("receipt_identity_mismatch")
        status = result.get("status")
        processing = result.get("delivery_state")
        if not isinstance(status, str) or (processing is not None and not isinstance(processing, str)):
            raise DeliveryError("invalid_receipt_status")
        state = receipt_state(status, processing)
        failed = processing in {"failed_recoverable", "retryable_failure"} or state == "quarantined"
        code = "materialization_" + processing if failed and processing in {"failed_recoverable", "retryable_failure", "terminal_failure"} else None
        failures = 0
    except (DeliveryError, BindingError) as exc:
        state, status, processing = "pending_materialization", None, None
        code = exc.code if isinstance(exc, DeliveryError) else "receipt_credential_unavailable"
        failures = min(row["reconcile_failures"] + 1, 12)
        delay = random.uniform(delay, max(delay, min(900, delay * 2**failures)))

    async with pool.acquire() as conn:
        updated = await conn.execute(
            """UPDATE tkg_alert_deliveries SET state=$2,
                  receipt_status=COALESCE($3,receipt_status),
                  receipt_delivery_state=COALESCE($4,receipt_delivery_state),
                  error_code=$5,reconcile_failures=$6,
                  reconcile_after=now()+$7*interval '1 second',updated_at=now()
                WHERE id=$1 AND state='pending_materialization' AND reconcile_fence=$8
                  AND EXISTS (SELECT 1 FROM workspace_tkg_bindings b
                    WHERE b.id=tkg_alert_deliveries.binding_id AND b.tenant_id=tkg_alert_deliveries.tenant_id
                      AND b.enabled)""",
            row["id"], state, status, processing, code, failures, delay, row["reconcile_fence"],
        )
    logger.info("tkg_receipt delivery=%s state=%s code=%s persisted=%s", row["id"], state, code, updated == "UPDATE 1")


async def reconcile_batch(pool, http, settings):
    # Claim only a wave at a time. The next poll never leases a long in-memory queue.
    for remaining in range(settings.batch_size, 0, -settings.concurrency):
        async with pool.acquire() as conn:
            rows = await conn.fetch(CLAIM, min(settings.concurrency, remaining), settings.request_timeout_seconds * 3 + 10)
        if not rows:
            break
        async with asyncio.TaskGroup() as group:
            for row in rows:
                group.create_task(fetch_status(pool, http, row, settings))
    async with pool.acquire() as conn:
        health = await conn.fetchrow(
            """SELECT count(*) pending, coalesce(max(extract(epoch from now()-coalesce(receipt_accepted_at,created_at))),0) oldest
               FROM tkg_alert_deliveries WHERE state='pending_materialization'"""
        )
    severity = logging.ERROR if health["oldest"] >= settings.pending_alert_seconds else (
        logging.WARNING if health["oldest"] >= settings.pending_warn_seconds else logging.INFO
    )
    logger.log(severity, "tkg_receipt_queue pending=%s oldest_seconds=%s", health["pending"], int(health["oldest"]))


async def main():
    settings = Settings()
    if not settings.enabled:
        return
    if not settings.database_url:
        raise ValueError("AISOC_TKG_RECONCILE_DATABASE_URL is required")
    logging.basicConfig(level=logging.INFO)
    async with (
        asyncpg.create_pool(settings.database_url.replace("postgresql+asyncpg://","postgresql://"), min_size=1,
                            max_size=settings.concurrency, timeout=10, command_timeout=10) as pool,
        httpx.AsyncClient(trust_env=False, verify=tls_context(), timeout=settings.request_timeout_seconds) as http,
    ):
        delay = 1.0
        while True:
            try:
                try:
                    await reconcile_batch(pool, http, settings)
                except* DATABASE_UNAVAILABLE as exc:
                    raise ConnectionError("receipt database temporarily unavailable") from exc
            except ConnectionError:
                logger.warning("tkg_receipt_database_unavailable")
                await asyncio.sleep(random.uniform(delay / 2, delay))
                delay = min(30, delay * 2)
            else:
                delay = 1.0
                await asyncio.sleep(settings.interval_seconds)


if __name__ == "__main__":
    asyncio.run(main())
