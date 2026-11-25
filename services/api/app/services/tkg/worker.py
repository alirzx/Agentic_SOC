"""Bounded, fenced outbox delivery. Run via python -m app.services.tkg.worker."""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import random
import time
from uuid import UUID

import asyncpg
import httpx
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.services.tkg.binding import Binding, BindingError, tls_context
from app.services.tkg import metrics
from app.services.tkg.projection import freeze
from app.services.tkg_evaluation.sender import RecordError

logger = logging.getLogger(__name__)

NORMALIZER_RETRY_CODES = {"soc_normalizer_busy", "soc_normalizer_timeout"}
CLAIM = """
SELECT d.id AS delivery, d.alert_row_id, d.snapshot, d.payload, d.attempts, b.*
FROM tkg_alert_deliveries d JOIN workspace_tkg_bindings b
 ON (d.binding_id,d.tenant_id)=(b.id,b.tenant_id)
WHERE b.enabled AND d.state IN ('not_submitted','retry_scheduled','submitting')
 AND d.next_attempt <= now()
ORDER BY d.next_attempt,d.id LIMIT 1 FOR UPDATE OF d SKIP LOCKED
"""


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AISOC_TKG_WORKER_", extra="ignore", env_ignore_empty=True)
    max_attempts: int = Field(6, ge=1, le=12)
    lease_seconds: float = Field(60, ge=30, le=300)
    request_timeout_seconds: float = Field(15, ge=1, le=60)
    db_timeout_seconds: float = Field(10, ge=1, le=30)
    db_command_seconds: float = Field(15, ge=1, le=45)
    idle_seconds: float = Field(5, ge=1, le=60)
    rate: int = Field(1, ge=1, le=5)
    retry_base_seconds: float = Field(3, ge=1, le=30)
    retry_max_seconds: float = Field(300, ge=30, le=3600)
    reconnect_max_seconds: float = Field(30, ge=5, le=120)
    metrics_interval_seconds: float = Field(30, ge=15, le=300)

    @model_validator(mode="after")
    def check_lease(self):
        if self.lease_seconds <= 2 * self.request_timeout_seconds + self.db_command_seconds:
            raise ValueError("worker lease must cover both HTTP requests and lease verification")
        return self


class DeliveryError(Exception):
    def __init__(self, code, transient=False):
        super().__init__(code)
        self.code = code
        self.transient = transient


async def request_json(http, method, url, token, data=None, *, timeout=15):
    try:
        async with (
            asyncio.timeout(timeout),
            http.stream(
                method, url, content=data, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            ) as reply,
        ):
            if reply.status_code not in {200, 409}:
                raise DeliveryError(f"http_{reply.status_code}", reply.status_code in {408, 429, 500, 502, 503, 504})
            buf = bytearray()
            size_limit = 4096 if reply.status_code == 409 else 1048576
            async for part in reply.aiter_bytes():
                buf.extend(part)
                if len(buf) > size_limit:
                    raise DeliveryError("http_409" if reply.status_code == 409 else "response_too_large")
            if reply.status_code == 409:
                try:
                    conflict = json.loads(buf)
                except ValueError:
                    conflict = {}
                if isinstance(conflict, dict):
                    # Existing TKG releases expose the stable marker as error.
                    # Keep unknown and authority conflicts terminal.
                    for key in ("code", "error"):
                        marker = conflict.get(key)
                        if isinstance(marker, str) and marker in NORMALIZER_RETRY_CODES:
                            raise DeliveryError(marker, transient=True)
                raise DeliveryError("http_409")
            result = json.loads(buf)
            if not isinstance(result, dict):
                raise ValueError
            return result
    except (TimeoutError, httpx.TransportError):
        raise DeliveryError("transport_uncertain", True) from None
    except ValueError:
        raise DeliveryError("invalid_response") from None


def receipt_state(status, delivery_state=None):
    if status not in ("pending", "registered", "submitted", "bound", "failed", "quarantined"):
        raise DeliveryError("unknown_receipt_status")
    if delivery_state not in (
        None, "accepted", "queued", "running", "waiting_for_dependency", "bound", "quarantined",
        "failed", "failed_recoverable", "retryable_failure", "terminal_failure",
    ):
        raise DeliveryError("unknown_receipt_delivery_state")
    if status == "bound":
        return "bound"
    if delivery_state in {"failed_recoverable", "retryable_failure"} and status != "quarantined":
        return "pending_materialization"
    if status in {"failed", "quarantined"} or delivery_state in {"failed", "terminal_failure", "quarantined"}:
        return "quarantined"
    if status in {"pending", "registered", "submitted"}:
        return "pending_materialization"
    raise DeliveryError("unknown_receipt_delivery_state")


def validate_preview(preview, binding, alert_row):
    """The source bearer authenticates the route; additional scope fields are optional in v1."""
    event = preview.get("canonical_event")
    expected = {
        "source_record_id": str(alert_row),
        "tenant_id": binding.tkg_tenant,
        "source_system": binding.source_system,
        "source_instance": binding.source_instance,
        "event_type": "security_alert",
    }
    if (
        preview.get("schema_version") != "soorin.ingestion-preview.v1"
        or preview.get("persistent_writes") is not False
        or not isinstance(event, dict)
        or any(event.get(k) != v for k, v in expected.items())
        or preview.get("knowledge_base_id", str(binding.kb_id)) != str(binding.kb_id)
        or preview.get("source_id", str(binding.source_id)) != str(binding.source_id)
    ):
        raise DeliveryError("preview_scope_or_identity_mismatch")


async def deliver(conn, http, settings=None):
    settings = settings or WorkerSettings()
    async with conn.transaction():
        row = await conn.fetchrow(CLAIM)
        if row is None:
            return False
        delivery = row["delivery"]
        binding = Binding.from_row(row, row["tenant_id"])
        try:
            if row["attempts"] >= settings.max_attempts:
                raise RecordError("attempts_exhausted")
            payload = row["payload"] or freeze(json.loads(row["snapshot"]), binding)
        except (RecordError, ValueError, TypeError) as exc:
            await conn.execute(
                "UPDATE tkg_alert_deliveries SET state='quarantined',snapshot=NULL,error_code=$2,updated_at=now() WHERE id=$1",
                delivery,
                getattr(exc, "code", "invalid_snapshot"),
            )
            metrics.deliveries.labels("quarantined").inc()
            return True
        attempt = row["attempts"] + 1
        await conn.execute(
            """UPDATE tkg_alert_deliveries SET state='submitting',attempts=$2,payload=$3,
            payload_hash=$4,snapshot=NULL,next_attempt=now()+$5::double precision*interval '1 second',updated_at=now()
            WHERE id=$1""",
            delivery,
            attempt,
            payload,
            hashlib.sha256(payload).hexdigest(),
            settings.lease_seconds,
        )

    receipt = status = processing = code = None
    delay = 0
    submission_started = time.monotonic()
    try:
        base = f"{binding.origin()}/api/v1/sources/{binding.source_id}/soc"
        token = binding.credential("ingest")
        preview = await request_json(http, "POST", base + "/preview", token, payload, timeout=settings.request_timeout_seconds)
        validate_preview(preview, binding, row["alert_row_id"])
        # Recheck disable and lease ownership after preview. An ingest already
        # in flight can finish after disable; no lock spans network I/O.
        live = await conn.fetchval(
            """SELECT EXISTS (
            SELECT 1 FROM tkg_alert_deliveries d JOIN workspace_tkg_bindings b
            ON (d.binding_id,d.tenant_id)=(b.id,b.tenant_id)
            WHERE d.id=$1 AND d.attempts=$2 AND d.state='submitting'
              AND d.next_attempt > clock_timestamp() AND b.enabled)""",
            delivery,
            attempt,
        )
        if not live:
            metrics.deliveries.labels("fenced").inc()
            return True
        try:
            result = await request_json(http, "POST", base + "/ingest", token, payload, timeout=settings.request_timeout_seconds)
        except DeliveryError as exc:
            if exc.code in {"invalid_response", "response_too_large"}:
                raise DeliveryError("invalid_receipt", transient=True) from None
            raise
        if result.get("schema_version") != "soorin.ingestion-receipt.v1":
            raise DeliveryError("invalid_receipt", transient=True)
        try:
            receipt = UUID(str(result.get("receipt_id")))
            status = result.get("status")
            processing = result.get("delivery_state")
            state = receipt_state(status, processing)
        except (ValueError, TypeError, DeliveryError):
            receipt = status = processing = None
            raise DeliveryError("invalid_receipt", transient=True) from None
    except (DeliveryError, BindingError, ValueError, TypeError) as exc:
        code = getattr(exc, "code", "invalid_binding_or_receipt")
        retry = isinstance(exc, DeliveryError) and exc.transient and attempt < settings.max_attempts
        state = "retry_scheduled" if retry else "quarantined"
        delay = random.uniform(1, min(settings.retry_max_seconds, settings.retry_base_seconds * 2**attempt)) if retry else 0
    updated = await conn.execute(
        """UPDATE tkg_alert_deliveries SET state=$2,receipt_id=$3,receipt_status=$4,
        error_code=$5,next_attempt=now()+$6::double precision*interval '1 second',updated_at=now(),receipt_delivery_state=$8,
        receipt_accepted_at=CASE WHEN $3::uuid IS NULL THEN receipt_accepted_at ELSE COALESCE(receipt_accepted_at,now()) END
        WHERE id=$1 AND attempts=$7 AND state='submitting'""",
        delivery,
        state,
        receipt,
        status,
        code,
        delay,
        attempt,
        processing,
    )
    logger.info(
        "tkg_delivery id=%s workspace=%s receipt=%s state=%s code=%s attempt=%s elapsed_ms=%s persisted=%s",
        delivery,
        binding.tenant_id,
        receipt,
        state,
        code,
        attempt,
        round((time.monotonic() - submission_started) * 1000),
        updated == "UPDATE 1",
    )
    metrics.deliveries.labels(state if updated == "UPDATE 1" else "fenced").inc()
    metrics.delivery_seconds.observe(time.monotonic() - submission_started)
    return True


async def report_queue(conn):
    stats = await conn.fetchrow(
        """SELECT count(*) total,count(*) FILTER (WHERE next_attempt <= now()) due,
           coalesce(max(extract(epoch from now()-created_at)),0) oldest
           FROM tkg_alert_deliveries WHERE state IN ('not_submitted','retry_scheduled','submitting')"""
    )
    metrics.queue.labels("outbox").set(stats["total"])
    metrics.queue.labels("due").set(stats["due"])
    metrics.oldest.labels("outbox").set(float(stats["oldest"]))
    metrics.export("sync")


async def backfill(conn, args):
    # Each invocation processes one page. The last UUID is its resume cursor.
    async with conn.transaction():
        rows = await conn.fetch(
            """SELECT a.id FROM alerts a WHERE a.tenant_id=$1
            AND ($2::uuid IS NULL OR a.connector_id=$2) AND ($3::uuid IS NULL OR a.id>$3)
            AND EXISTS (SELECT 1 FROM workspace_tkg_bindings b WHERE b.enabled
              AND (b.tenant_id,b.connector_id)=(a.tenant_id,a.connector_id))
            ORDER BY a.id LIMIT $4""",
            args.workspace,
            args.connector,
            args.after,
            args.batch,
        )
        if args.apply:
            await conn.execute(
                """SELECT tkg_enqueue(a,b) FROM alerts a JOIN workspace_tkg_bindings b
              ON (a.tenant_id,a.connector_id)=(b.tenant_id,b.connector_id)
              WHERE a.tenant_id=$1 AND a.id=ANY($2::uuid[]) AND b.enabled""",
                args.workspace,
                [r["id"] for r in rows],
            )
    if rows:
        await asyncio.sleep(len(rows) / args.rate)
    print(json.dumps({"apply": args.apply, "examined": len(rows), "after": str(rows[-1]["id"]) if rows else None}))


async def refresh_receipts(conn, http, args):
    # Explicit operator diagnostics only. The ordinary worker never needs this grant.
    rows = await conn.fetch(
        """SELECT d.id AS delivery,d.receipt_id,b.* FROM tkg_alert_deliveries d
        JOIN workspace_tkg_bindings b ON (b.id,b.tenant_id)=(d.binding_id,d.tenant_id)
        WHERE d.tenant_id=$1 AND b.enabled AND d.state='pending_materialization'
        ORDER BY d.updated_at LIMIT $2""",
        args.workspace,
        args.batch,
    )
    for row in rows:
        live = await conn.fetchrow(
            "SELECT * FROM workspace_tkg_bindings WHERE id=$1 AND tenant_id=$2 AND enabled", row["id"], args.workspace
        )
        if not live:
            continue
        b = Binding.from_row(live, args.workspace)
        url = f"{b.origin()}/api/v1/kbs/{b.kb_id}/knowledge/receipts/{row['receipt_id']}/status"
        result = await request_json(http, "GET", url, b.credential("diagnostics"))
        if result.get("receipt_id") != str(row["receipt_id"]):
            raise DeliveryError("receipt_identity_mismatch")
        state = receipt_state(result.get("status"), result.get("delivery_state"))
        await conn.execute(
            """UPDATE tkg_alert_deliveries SET state=$2, receipt_status=$3,
            error_code=$4,receipt_delivery_state=$5,updated_at=now() WHERE id=$1 AND state='pending_materialization' AND receipt_id=$6""",
            row["delivery"],
            state,
            result["status"],
            "materialization_failed" if state == "quarantined" else None,
            result.get("delivery_state"),
            row["receipt_id"],
        )
        await asyncio.sleep(1 / args.rate)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["run", "backfill", "receipts"])
    parser.add_argument("--workspace", type=UUID)
    parser.add_argument("--connector", type=UUID)
    parser.add_argument("--after", type=UUID)
    parser.add_argument("--batch", type=int, choices=range(1, 101), default=10, metavar="1..100")
    parser.add_argument("--rate", type=int, choices=range(1, 6))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.mode != "run" and not args.workspace:
        parser.error("--workspace required")
    if args.mode == "run" and os.getenv("AISOC_TKG_AUTO_INGEST_ENABLED", "false").lower() != "true":
        return
    settings = WorkerSettings()
    args.rate = args.rate or settings.rate
    logging.basicConfig(level=logging.INFO)
    dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
    async with httpx.AsyncClient(trust_env=False, timeout=settings.request_timeout_seconds, verify=tls_context()) as http:
        reconnect_delay = 1.0
        next_metrics = 0.0
        while True:
            conn = None
            try:
                conn = await asyncpg.connect(dsn, timeout=settings.db_timeout_seconds, command_timeout=settings.db_command_seconds)
                if args.mode == "backfill":
                    await backfill(conn, args)
                    return
                if args.mode == "receipts":
                    await refresh_receipts(conn, http, args)
                    return
                while True:
                    worked = await deliver(conn, http, settings)
                    if time.monotonic() >= next_metrics:
                        await report_queue(conn)
                        next_metrics = time.monotonic() + settings.metrics_interval_seconds
                    reconnect_delay = 1.0
                    await asyncio.sleep(1 / args.rate if worked else settings.idle_seconds)
            except (OSError, TimeoutError, asyncpg.PostgresConnectionError) as exc:
                if args.mode != "run":
                    raise
                logger.warning("tkg_worker_database_reconnect type=%s", type(exc).__name__)
            finally:
                if conn is not None:
                    try:
                        await conn.close(timeout=5)
                    except (OSError, TimeoutError, asyncpg.PostgresConnectionError):
                        conn.terminate()
            await asyncio.sleep(random.uniform(reconnect_delay / 2, reconnect_delay))
            reconnect_delay = min(settings.reconnect_max_seconds, reconnect_delay * 2)


if __name__ == "__main__":
    asyncio.run(main())
