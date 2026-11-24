"""Bounded, fenced outbox delivery. Run via python -m app.services.tkg.worker."""
import argparse
import asyncio
import hashlib
import json
import os
import random
from uuid import UUID

import asyncpg
import httpx

from app.services.tkg.binding import Binding, BindingError
from app.services.tkg.projection import freeze
from app.services.tkg_evaluation.sender import RecordError

MAX_ATTEMPTS = 6
CLAIM = """
SELECT d.id AS delivery, d.alert_row_id, d.snapshot, d.payload, d.attempts, b.*
FROM tkg_alert_deliveries d JOIN workspace_tkg_bindings b
 ON (d.binding_id,d.tenant_id)=(b.id,b.tenant_id)
WHERE b.enabled AND d.state IN ('not_submitted','retry_scheduled','submitting')
 AND d.next_attempt <= now()
ORDER BY d.next_attempt,d.id LIMIT 1 FOR UPDATE OF d SKIP LOCKED
"""


class DeliveryError(Exception):
    def __init__(self, code, transient=False):
        self.code = code
        self.transient = transient


async def request_json(http, method, url, token, data=None):
    try:
        async with asyncio.timeout(15), http.stream(
            method, url, content=data, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        ) as reply:
            if reply.status_code != 200:
                raise DeliveryError(f"http_{reply.status_code}", reply.status_code in {408,429,502,503,504})
            buf = bytearray()
            async for part in reply.aiter_bytes():
                buf.extend(part)
                if len(buf) > 1048576:
                    raise DeliveryError("response_too_large")
            result = json.loads(buf)
            if not isinstance(result, dict):
                raise ValueError
            return result
    except (TimeoutError, httpx.TransportError):
        raise DeliveryError("transport_uncertain", True) from None
    except ValueError:
        raise DeliveryError("invalid_response") from None


def receipt_state(status, delivery_state=None):
    if status == "bound":
        return "bound"
    if status in {"failed", "quarantined"} or delivery_state in {"failed","terminal_failure","failed_recoverable","quarantined"}:
        return "quarantined"
    if status in {"pending","registered","submitted"}:
        return "pending_materialization"
    raise DeliveryError("unknown_receipt_status")


async def deliver(conn, http):
    async with conn.transaction():
        row = await conn.fetchrow(CLAIM)
        if row is None:
            return False
        delivery = row["delivery"]
        binding = Binding.from_row(row, row["tenant_id"])
        try:
            if row["attempts"] >= MAX_ATTEMPTS:
                raise RecordError("attempts_exhausted")
            payload = row["payload"] or freeze(json.loads(row["snapshot"]), binding)
        except (RecordError, ValueError, TypeError) as exc:
            await conn.execute("UPDATE tkg_alert_deliveries SET state='quarantined',error_code=$2,updated_at=now() WHERE id=$1",
                               delivery, getattr(exc, "code", "invalid_snapshot"))
            return True
        attempt = row["attempts"] + 1
        await conn.execute("""UPDATE tkg_alert_deliveries SET state='submitting',attempts=$2,payload=$3,
            payload_hash=$4,snapshot=NULL,next_attempt=now()+interval '60 seconds',updated_at=now()
            WHERE id=$1""", delivery, attempt, payload, hashlib.sha256(payload).hexdigest())

    # The row lock fences a stale claimant. The binding lock serializes disable
    # with the bounded HTTP operation. A crash here leaves the frozen lease.
    async with conn.transaction():
        live = await conn.fetchrow("""SELECT b.* FROM tkg_alert_deliveries d JOIN workspace_tkg_bindings b
            ON (b.id,b.tenant_id)=(d.binding_id,d.tenant_id)
            WHERE d.id=$1 AND d.attempts=$2 AND d.state='submitting' AND b.enabled
            FOR UPDATE OF d FOR SHARE OF b""", delivery, attempt)
        if live is None:
            return True
        receipt = status = code = None
        delay = 0
        try:
            binding = Binding.from_row(live, row["tenant_id"])
            base = f"{binding.origin()}/api/v1/sources/{binding.source_id}/soc"
            token = binding.credential("ingest")
            preview = await request_json(http,"POST",base+"/preview",token,payload)
            event = preview.get("canonical_event") or {}
            if (preview.get("schema_version") != "soorin.ingestion-preview.v1" or
                preview.get("knowledge_base_id") != str(binding.kb_id) or
                preview.get("source_id") != str(binding.source_id) or
                event.get("source_record_id") != str(row["alert_row_id"]) or
                any(event.get(k) != v for k,v in (("source_system",binding.source_system),
                    ("source_instance",binding.source_instance),("tenant_id",binding.tkg_tenant)))):
                raise DeliveryError("preview_scope_or_identity_mismatch")
            result = await request_json(http,"POST",base+"/ingest",token,payload)
            if result.get("schema_version") != "soorin.ingestion-receipt.v1":
                raise DeliveryError("invalid_receipt")
            receipt = UUID(str(result.get("receipt_id")))
            status = result.get("status")
            state = receipt_state(status)
        except (DeliveryError, BindingError, ValueError, TypeError) as exc:
            code = exc.code if isinstance(exc,DeliveryError) else "invalid_binding_or_receipt"
            retry = isinstance(exc,DeliveryError) and exc.transient and attempt < MAX_ATTEMPTS
            state = "retry_scheduled" if retry else "quarantined"
            delay = random.uniform(1, min(300, 3 * 2**attempt)) if retry else 0
        await conn.execute("""UPDATE tkg_alert_deliveries SET state=$2,receipt_id=$3,receipt_status=$4,
            error_code=$5,next_attempt=now()+$6*interval '1 second',updated_at=now() WHERE id=$1""",
            delivery,state,receipt,status,code,delay)
    return True


async def backfill(conn, args):
    # Each invocation processes one page. The last UUID is its resume cursor.
    async with conn.transaction():
        rows = await conn.fetch("""SELECT a.id FROM alerts a WHERE a.tenant_id=$1
            AND ($2::uuid IS NULL OR a.connector_id=$2) AND ($3::uuid IS NULL OR a.id>$3)
            AND EXISTS (SELECT 1 FROM workspace_tkg_bindings b WHERE b.enabled
              AND (b.tenant_id,b.connector_id)=(a.tenant_id,a.connector_id))
            ORDER BY a.id LIMIT $4""",args.workspace,args.connector,args.after,args.batch)
        if args.apply:
            await conn.execute("""SELECT tkg_enqueue(a,b) FROM alerts a JOIN workspace_tkg_bindings b
              ON (a.tenant_id,a.connector_id)=(b.tenant_id,b.connector_id)
              WHERE a.tenant_id=$1 AND a.id=ANY($2::uuid[]) AND b.enabled""",
              args.workspace,[r["id"] for r in rows])
    if rows:
        await asyncio.sleep(len(rows) / args.rate)
    print(json.dumps({"apply":args.apply,"examined":len(rows),"after":str(rows[-1]["id"]) if rows else None}))


async def refresh_receipts(conn, http, args):
    # Explicit operator diagnostics only. The ordinary worker never needs this grant.
    rows = await conn.fetch("""SELECT d.id AS delivery,d.receipt_id,b.* FROM tkg_alert_deliveries d
        JOIN workspace_tkg_bindings b ON (b.id,b.tenant_id)=(d.binding_id,d.tenant_id)
        WHERE d.tenant_id=$1 AND b.enabled AND d.state='pending_materialization'
        ORDER BY d.updated_at LIMIT $2""",args.workspace,args.batch)
    for row in rows:
        async with conn.transaction():
            live = await conn.fetchrow("SELECT * FROM workspace_tkg_bindings WHERE id=$1 AND tenant_id=$2 AND enabled FOR SHARE",
                                       row["id"],args.workspace)
            if not live:
                continue
            b = Binding.from_row(live,args.workspace)
            url = f"{b.origin()}/api/v1/kbs/{b.kb_id}/knowledge/receipts/{row['receipt_id']}/status"
            result = await request_json(http,"GET",url,b.credential("diagnostics"))
            if result.get("receipt_id") != str(row["receipt_id"]):
                raise DeliveryError("receipt_identity_mismatch")
            state = receipt_state(result.get("status"),result.get("delivery_state"))
            await conn.execute("""UPDATE tkg_alert_deliveries SET state=$2, receipt_status=$3,
                error_code=$4,updated_at=now() WHERE id=$1 AND state='pending_materialization'""",
                row["delivery"],state,result["status"],"materialization_failed" if state=="quarantined" else None)
        await asyncio.sleep(1 / args.rate)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode",choices=["run","backfill","receipts"])
    parser.add_argument("--workspace",type=UUID)
    parser.add_argument("--connector",type=UUID)
    parser.add_argument("--after",type=UUID)
    parser.add_argument("--batch",type=int,choices=range(1,101),default=10,metavar="1..100")
    parser.add_argument("--rate",type=int,choices=range(1,6),default=1)
    parser.add_argument("--apply",action="store_true")
    args = parser.parse_args()
    if args.mode != "run" and not args.workspace:
        parser.error("--workspace required")
    if args.mode == "run" and os.getenv("AISOC_TKG_AUTO_INGEST_ENABLED","false").lower() != "true":
        return
    conn = await asyncpg.connect(os.environ["DATABASE_URL"].replace("postgresql+asyncpg://","postgresql://"))
    try:
        async with httpx.AsyncClient(trust_env=False,timeout=10) as http:
            if args.mode == "backfill":
                await backfill(conn,args)
            elif args.mode == "receipts":
                await refresh_receipts(conn,http,args)
            else:
                while True:
                    worked = await deliver(conn,http)
                    await asyncio.sleep(1 / args.rate if worked else 5)
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
