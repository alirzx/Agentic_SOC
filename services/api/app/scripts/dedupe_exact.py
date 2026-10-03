"""CLI: purge exact-duplicate alerts and cases for a tenant.

Usage (inside the API container)::

    python -m app.scripts.dedupe_exact
    python -m app.scripts.dedupe_exact --dry-run
    python -m app.scripts.dedupe_exact --tenant-id 00000000-0000-0000-0000-000000000001
"""

from __future__ import annotations

import argparse
import asyncio
import json
import uuid

from app.api.v1.dev_auth import DEMO_TENANT_ID
from app.db.database import AsyncSessionLocal
from app.services.exact_dedupe import dedupe_exact


async def _main(tenant_id: uuid.UUID, *, dry_run: bool) -> int:
    async with AsyncSessionLocal() as session:
        result = await dedupe_exact(session, tenant_id=tenant_id, dry_run=dry_run)
    print(json.dumps(result, indent=2, default=str))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Delete exact-duplicate alerts/cases")
    parser.add_argument(
        "--tenant-id",
        default=str(DEMO_TENANT_ID),
        help="Tenant UUID (default: demo tenant)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report only; do not delete",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_main(uuid.UUID(args.tenant_id), dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
