"""Purge seeded demo alerts/cases so the console shows live connector data only.

Keeps the demo tenant + login user so operators can still sign in. Deletes
alerts, cases, investigation runs/artifacts/events, case tasks/timelines, and
seeded placeholder connectors (CrowdStrike Falcon, Microsoft Defender, etc.).

Usage (from the API container)::

    python -m app.scripts.purge_demo_data
    # or from the host:
    docker compose --project-directory . -f infra/compose/docker-compose.demo.yml \\
      exec -T api python -m app.scripts.purge_demo_data
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import delete, select, text

from app.api.v1.dev_auth import DEMO_TENANT_ID
from app.db.database import AsyncSessionLocal
from app.models.alert import Alert
from app.models.case import Case, CaseTask, CaseTimeline
from app.models.connector import Connector
from app.models.investigation import (
    InvestigationArtifact,
    InvestigationEvent,
    InvestigationRun,
)
from app.models.published_replay import PublishedReplay

# Placeholder connectors inserted by seed_demo — never real Splunk instances.
_SEEDED_CONNECTOR_NAMES = frozenset(
    {
        "CrowdStrike Falcon",
        "Microsoft Defender",
        "Splunk Cloud",
        "Cortex XDR",
        "AWS GuardDuty",
        "Okta",
        "Microsoft Sentinel",
        "Google Workspace",
        "GitHub Audit",
    }
)


async def _purge(session) -> dict[str, int]:
    tenant_id = DEMO_TENANT_ID
    counts: dict[str, int] = {}

    run_ids = (
        await session.execute(select(InvestigationRun.id).where(InvestigationRun.tenant_id == tenant_id))
    ).scalars().all()
    if run_ids:
        r1 = await session.execute(delete(InvestigationArtifact).where(InvestigationArtifact.run_id.in_(run_ids)))
        r2 = await session.execute(delete(InvestigationEvent).where(InvestigationEvent.run_id.in_(run_ids)))
        counts["investigation_artifacts"] = r1.rowcount or 0
        counts["investigation_events"] = r2.rowcount or 0
    r3 = await session.execute(delete(InvestigationRun).where(InvestigationRun.tenant_id == tenant_id))
    counts["investigation_runs"] = r3.rowcount or 0

    case_ids = (await session.execute(select(Case.id).where(Case.tenant_id == tenant_id))).scalars().all()
    if case_ids:
        r4 = await session.execute(delete(CaseTask).where(CaseTask.case_id.in_(case_ids)))
        r5 = await session.execute(delete(CaseTimeline).where(CaseTimeline.case_id.in_(case_ids)))
        counts["case_tasks"] = r4.rowcount or 0
        counts["case_timelines"] = r5.rowcount or 0
    r6 = await session.execute(delete(Case).where(Case.tenant_id == tenant_id))
    counts["cases"] = r6.rowcount or 0

    r7 = await session.execute(delete(Alert).where(Alert.tenant_id == tenant_id))
    counts["alerts"] = r7.rowcount or 0

    r8 = await session.execute(delete(PublishedReplay).where(PublishedReplay.tenant_id == tenant_id))
    counts["published_replays"] = r8.rowcount or 0

    r9 = await session.execute(
        delete(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.name.in_(_SEEDED_CONNECTOR_NAMES),
        )
    )
    counts["seeded_connectors"] = r9.rowcount or 0

    # Mirror table used by some list endpoints (best-effort; may not exist).
    try:
        await session.execute(text("DELETE FROM aisoc_cases WHERE tenant_id = :tid"), {"tid": str(tenant_id)})
    except Exception:
        pass

    return counts


async def _main_async() -> None:
    print("[purge] removing seeded demo alerts/cases for live Splunk ingest…", flush=True)
    async with AsyncSessionLocal() as session:
        try:
            counts = await _purge(session)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    for key, value in sorted(counts.items()):
        print(f"[purge] {key}: {value}")
    print("[purge] done — tenant/user retained; connect Splunk to populate the dashboard")


def main() -> None:
    asyncio.run(_main_async())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # pragma: no cover
        print(f"[purge] failed: {exc}", file=sys.stderr)
        sys.exit(1)
