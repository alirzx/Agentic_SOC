"""CLI: re-enrich existing Splunk alerts with wide Mission Control fields.

Usage (inside the API container)::

    python -m app.scripts.reenrich_splunk_alerts
    python -m app.scripts.reenrich_splunk_alerts --force --limit 1000
    python -m app.scripts.reenrich_splunk_alerts --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid

from app.api.v1.dev_auth import DEMO_TENANT_ID
from app.db.database import AsyncSessionLocal
from app.services.splunk_notable import reenrich_tenant_splunk_alerts


async def _main(tenant_id: uuid.UUID, *, limit: int, force: bool, dry_run: bool) -> int:
    async with AsyncSessionLocal() as session:
        result = await reenrich_tenant_splunk_alerts(
            session,
            tenant_id=tenant_id,
            limit=limit,
            force=force,
            dry_run=dry_run,
        )
    print(json.dumps(result, indent=2, default=str))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-enrich Splunk alerts from live notables")
    parser.add_argument("--tenant-id", default=str(DEMO_TENANT_ID))
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    raise SystemExit(
        asyncio.run(
            _main(
                uuid.UUID(args.tenant_id),
                limit=args.limit,
                force=args.force,
                dry_run=args.dry_run,
            )
        )
    )


if __name__ == "__main__":
    main()
