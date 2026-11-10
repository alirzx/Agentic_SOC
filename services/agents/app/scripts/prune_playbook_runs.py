"""Prune the heavy payloads of old playbook runs.

Retention decision (Phase 12): a ``playbook_runs`` row — who approved what, when,
and how the run ended — is audit value and is kept. ``playbook_snapshot``,
``context`` and ``step_results`` are bulk that only matters while a run can still
be resumed, so they are cleared once the run has been finished for the retention
window. Parked runs are never touched: they are still waiting on a human.

Run it from a cron / scheduled job:

    python -m app.scripts.prune_playbook_runs --days 90

or for one tenant only:

    python -m app.scripts.prune_playbook_runs --days 90 --tenant <uuid>
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from app.playbook.run_store import prune_payloads

logger = logging.getLogger("aisoc.scripts.prune_playbook_runs")


async def _run(days: int, tenant: str | None) -> int:
    pruned = await prune_payloads(days, tenant_ref=tenant)
    logger.info("playbook_runs.pruned", extra={"days": days, "rows": pruned, "tenant": tenant})
    print(f"pruned payloads for {pruned} run(s) older than {days} day(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=90, help="retention window in days (default: 90)")
    parser.add_argument("--tenant", default=None, help="limit to one tenant UUID/slug")
    args = parser.parse_args(argv)

    if args.days < 1:
        parser.error("--days must be at least 1")

    return asyncio.run(_run(args.days, args.tenant))


if __name__ == "__main__":
    sys.exit(main())
