"""Manual, gated push of a case's missing alerts into the TKG.

This is the one write path in the API, and it exists because the read path is
otherwise useless on a fresh install: a case whose alerts were never ingested
evaluates to 0% coverage, which is honest but gives an operator nothing to click.
The control surface is deliberately narrow:

* ``AISOC_TKG_ALLOW_SEND`` must be true (default false) — otherwise the endpoint
  refuses and the UI hides the button.
* ``dry_run`` defaults to true: the operator sees exactly which alerts would be
  sent, and which are already in the graph, before anything is written.
* Only alerts whose identity does **not** resolve are eligible; existing records
  are skipped, never re-sent.
* Every send returns the TKG receipt, which is the audit trail (the database row
  records the run too).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.services.tkg_evaluation import constants as C
from app.services.tkg_evaluation.client import TkgClient, TkgError, config_from_settings
from app.services.tkg_evaluation.sender import RecordError, build_curated_record
from app.services.tkg_evaluation.store import load_alerts, load_case, load_case_scope

logger = logging.getLogger(__name__)


async def sync_missing_alerts(
    db: Any,
    *,
    tenant_id: UUID,
    case_id: UUID,
    dry_run: bool = True,
    limit: int = 25,
    delay: float = 1.0,
    client: TkgClient | None = None,
    settings_obj: Any | None = None,
) -> dict[str, Any]:
    """Resolve each alert; push the ones the graph does not know about."""

    started = datetime.now(UTC)
    cfg = config_from_settings(settings_obj)
    if not cfg.configured:
        return {"ok": False, "reason": C.R_TKG_NOT_CONFIGURED, "dry_run": dry_run}

    case = await load_case(db, case_id, tenant_id)
    if not case:
        raise LookupError("Case not found.")

    excluded, _filters = await load_case_scope(db, case_id, tenant_id)
    alerts = await load_alerts(db, tenant_id, case_id, [str(value) for value in case["alert_ids"]], set(excluded))
    alerts = alerts[: max(1, limit)]

    own_client = client is None
    tkg = client or TkgClient(cfg)
    plan: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []

    try:
        for alert in alerts:
            try:
                record, warnings = build_curated_record(alert)
            except RecordError as exc:
                invalid.append({"alert_id": str(alert.get("id")), "error": exc.code})
                continue

            notable_id = record["notable_id"]
            try:
                resolved = await tkg.resolve(notable_id)
            except TkgError as exc:
                resolved = {"status": "error", "error": exc.code}
            entity = ((resolved.get("candidates") or [{}])[0] or {}).get("entity_id")
            if entity:
                skipped.append(
                    {"alert_id": str(alert.get("id")), "notable_id": notable_id, "status": resolved.get("status"), "entity_id": entity}
                )
                continue

            plan.append({"alert_id": str(alert.get("id")), "notable_id": notable_id, "warnings": warnings, "record": record})

        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "would_send": [
                    {"alert_id": item["alert_id"], "notable_id": item["notable_id"], "warnings": item["warnings"]} for item in plan
                ],
                "already_in_graph": skipped,
                "invalid": invalid,
                "counts": {"would_send": len(plan), "already_in_graph": len(skipped), "invalid": len(invalid)},
                "allow_send": cfg.allow_send,
                "started_at": started.isoformat(),
            }

        if not cfg.allow_send:
            return {
                "ok": False,
                "reason": "tkg_send_disabled",
                "detail": "Set AISOC_TKG_ALLOW_SEND=true to enable manual sends.",
                "would_send": [{"alert_id": item["alert_id"], "notable_id": item["notable_id"]} for item in plan],
                "already_in_graph": skipped,
                "invalid": invalid,
                "allow_send": False,
            }

        source_id, ingest_token = await tkg.ensure_source()
        sent: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []

        for index, item in enumerate(plan):
            if index and delay > 0:
                # The graph's extractor rate-limits its own model; spacing sends
                # is what keeps the receipts from turning into 429s.
                await asyncio.sleep(delay)
            body = {"profile": C.PROFILE, "record": item["record"]}
            try:
                response = await tkg.ingest(source_id, ingest_token, body)
            except TkgError as exc:
                target = rejected if exc.status == 422 else failed
                target.append(
                    {"alert_id": item["alert_id"], "notable_id": item["notable_id"], "error": exc.code, "detail": exc.detail[:200]}
                )
                continue
            receipt = response.get("receipt_id")
            if receipt:
                sent.append(
                    {
                        "alert_id": item["alert_id"],
                        "notable_id": item["notable_id"],
                        "receipt_id": receipt,
                        "job_id": response.get("job_id"),
                        "status": response.get("status"),
                    }
                )
            else:
                failed.append({"alert_id": item["alert_id"], "notable_id": item["notable_id"], "error": "no_receipt_id"})

        return {
            "ok": True,
            "dry_run": False,
            "source_id": source_id,
            "sent": sent,
            "rejected": rejected,
            "failed": failed,
            "already_in_graph": skipped,
            "invalid": invalid,
            "counts": {
                "sent": len(sent),
                "rejected": len(rejected),
                "failed": len(failed),
                "already_in_graph": len(skipped),
                "invalid": len(invalid),
            },
            "allow_send": True,
            "note": "Receipts mean the graph accepted the record; materialisation is asynchronous.",
            "started_at": started.isoformat(),
        }
    finally:
        if own_client:
            await tkg.aclose()
