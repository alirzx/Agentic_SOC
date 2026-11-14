"""Shadow compare legacy display grouping vs Layer-2 logical keys.

Read-only against the API database. Does not write alerts/cases/funnel.

Usage:
  python -m app.scripts.shadow_dedup_compare --tenant-id <uuid> [--limit 500]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid

from sqlalchemy import text

from app.db.database import async_session_factory
from app.services.dedup.shadow import compare_grouping


async def _run(tenant_id: uuid.UUID, limit: int) -> dict:
    async with async_session_factory() as db:
        rows = (
            await db.execute(
                text(
                    """
                    SELECT id, title, severity, disposition, rule_id, rule_name,
                           affected_hosts, affected_ips, affected_users,
                           source_event_ids, created_at, event_time,
                           connector_type, llm_payload, raw_event, iocs
                      FROM alerts
                     WHERE tenant_id = :tid
                     ORDER BY created_at DESC
                     LIMIT :lim
                    """
                ).bindparams(tid=tenant_id, lim=limit)
            )
        ).mappings().all()
    payload = [{**dict(r), "tenant_id": str(tenant_id)} for r in rows]
    report = compare_grouping(payload, window_seconds=900)
    report["tenant_id"] = str(tenant_id)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--limit", type=int, default=500)
    args = parser.parse_args()
    report = asyncio.run(_run(uuid.UUID(args.tenant_id), args.limit))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
