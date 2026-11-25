"""DB-backed regression tests for the observation ledger and the case-link write path.

Why a real database, not a fake pool: both behaviours under test *are* SQL.

* ``CorrelationEngine._persist_observations`` upserts with
  ``alert_ids = ARRAY(SELECT DISTINCT ... correlation_observations.alert_ids ||
  EXCLUDED.alert_ids)``. A fake pool can only assert that the string was sent;
  it cannot catch a revert to ``alert_ids = EXCLUDED.alert_ids`` — the defect
  that erased the ledger evidence of every alert a previous cycle had just cased
  (case-2 run: 0/15 of the case's own alerts were covered, so the correlation
  graph rendered empty).
* ``CorrelationEngine._link_case`` stamps ownership onto ``alerts`` and then
  rebuilds ``aisoc_cases.alert_ids`` from that ownership inside one transaction.
  The bug it fixes was a cache that disagreed with ownership (13 ids in the case
  row, 15 alerts pointing at it), which only a real read-back can prove.

The tables are cloned into a throwaway schema with
``CREATE TABLE ... (LIKE public.<table> INCLUDING ALL)``: same columns, defaults,
primary key and the ``(tenant_id, observation_key)`` unique constraint the
upsert's ``ON CONFLICT`` needs. That makes the test fail if the engine writes a
column the deployment does not have, and it cannot touch a real row: everything
lives in ``correlation_test_*`` and is dropped afterwards.

Connection: ``CORRELATION_TEST_DSN``, falling back to ``DATABASE_URL`` (set by
``docs/ahmadi/start-dev-local.ps1`` to the Docker Postgres). With neither set,
or the database unreachable, the module skips — same contract as
``tests/isolation/test_live_stores.py``, so a unit-only run stays green.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from app.normalizer.extract_keys import Key
from app.services import diagnostics
from app.services.engine import CorrelationEngine
from app.services.observations import Observation

#: Real tables the cloned schema and the engine's SQL depend on. The last two
#: are optional for the write-path tests but let a full cycle run without its
#: best-effort except branches (frequency rollup, role overrides).
_CLONED_TABLES = (
    "alerts",
    "aisoc_cases",
    "correlation_observations",
    "value_frequency",
    "correlation_rule_roles",
    "correlation_rule_resolution_audits",
)


def _dsn() -> str:
    """Resolve the test DSN, or skip with a message that names both variables."""

    for variable in ("CORRELATION_TEST_DSN", "DATABASE_URL"):
        raw = os.environ.get(variable, "").strip()
        if raw:
            # The services speak SQLAlchemy-style URLs
            # (``postgresql+asyncpg://``); asyncpg wants the plain scheme.
            return re.sub(r"^postgres(?:ql)?\+asyncpg://", "postgresql://", raw)
    pytest.skip(
        "CORRELATION_TEST_DSN / DATABASE_URL not set — the DB-backed engine "
        "tests only run against a real Postgres (dev Docker host)"
    )


@pytest_asyncio.fixture
async def db() -> AsyncIterator[dict[str, Any]]:
    """A throwaway schema cloned from the deployed tables, plus a real pool."""

    asyncpg = pytest.importorskip("asyncpg")
    dsn = _dsn()

    try:
        admin = await asyncpg.connect(dsn, timeout=10)
    except Exception as exc:  # noqa: BLE001 — a dev shell may have the stack down
        pytest.skip(f"Postgres at the configured DSN is unreachable ({type(exc).__name__}: {exc})")

    schema = f"correlation_test_{uuid.uuid4().hex[:12]}"

    try:
        await admin.execute(f'CREATE SCHEMA "{schema}"')
        for table in _CLONED_TABLES:
            await admin.execute(
                f'CREATE TABLE "{schema}"."{table}" '
                f"(LIKE public.{table} INCLUDING ALL)"
            )

        # ``public`` stays on the path so cloned column defaults such as
        # ``uuid_generate_v4()`` resolve; our schema wins for table names.
        pool = await asyncpg.create_pool(
            dsn,
            min_size=1,
            max_size=2,
            server_settings={"search_path": f"{schema},public"},
        )
        try:
            yield {"pool": pool, "admin": admin, "schema": schema, "tenant": uuid.uuid4()}
        finally:
            await pool.close()
    finally:
        await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await admin.close()


def observation(
    key: str,
    *,
    alert_ids: list[uuid.UUID],
    host: str = "win-dc-01",
    role: str = "credential_access:lsass",
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    tokens: tuple[Key, ...] | None = None,
) -> Observation:
    keys = list(tokens) if tokens is not None else [Key("host", host, 2), Key("user", "administrator", 2)]
    return Observation(
        key=key,
        alert_ids=list(alert_ids),
        keys=keys,
        hosts=[host],
        users=["administrator"],
        techniques=["T1003.001"],
        stories=["Credential Access"],
        kill_chain=["Credential Access"],
        role=role,
        first_seen=first_seen or datetime(2026, 11, 11, 9, 0, tzinfo=UTC),
        last_seen=last_seen or datetime(2026, 11, 11, 9, 30, tzinfo=UTC),
        time_quality="first_event",
        normalizer_version="2.0.0",
    )


@pytest.mark.asyncio
async def test_observation_upsert_unions_alert_ids_across_cycles(db):
    """A second cycle must add its alerts to the ledger, never replace the list.

    This is the case-2 regression: ``_load_context`` returns only *uncased*
    alerts, so by the next cycle the alerts this observation already cased are
    no longer in the batch that re-writes the row. Overwriting the array erased
    them, and the case's own graph then found no ledger coverage.
    """

    engine = CorrelationEngine(db["pool"])
    tenant = db["tenant"]
    key = "entity|T1003.001|a1b2c3"
    cycle_one, cycle_two = uuid.uuid4(), uuid.uuid4()

    first = observation(
        key,
        alert_ids=[cycle_one],
        role="credential_access:lsass",
        first_seen=datetime(2026, 11, 11, 9, 0, tzinfo=UTC),
        last_seen=datetime(2026, 11, 11, 9, 30, tzinfo=UTC),
    )
    await engine._persist_observations(tenant, [first])

    # Cycle 2 sees the same action again — but only its *new* alert, because
    # cycle_one is already cased and therefore outside the loaded window.
    second = observation(
        key,
        alert_ids=[cycle_two],
        role="credential_access:lsass",
        first_seen=datetime(2026, 11, 11, 8, 45, tzinfo=UTC),
        last_seen=datetime(2026, 11, 11, 10, 15, tzinfo=UTC),
    )
    await engine._persist_observations(tenant, [second])

    rows = await db["admin"].fetch(
        'SELECT alert_ids, first_seen, last_seen, role FROM "' + db["schema"] + '".correlation_observations '
        "WHERE tenant_id = $1 AND observation_key = $2",
        tenant,
        key,
    )

    assert len(rows) == 1, "the upsert must stay one row per (tenant, observation_key)"
    assert set(rows[0]["alert_ids"]) == {cycle_one, cycle_two}
    # Metadata follows the newest write; only the id array is a union.
    assert rows[0]["role"] == "credential_access:lsass"
    assert rows[0]["first_seen"] == datetime(2026, 11, 11, 8, 45, tzinfo=UTC)
    assert rows[0]["last_seen"] == datetime(2026, 11, 11, 10, 15, tzinfo=UTC)

    # Re-persisting an id that is already in the array must not duplicate it.
    await engine._persist_observations(tenant, [observation(key, alert_ids=[cycle_one])])
    after = await db["admin"].fetchval(
        'SELECT alert_ids FROM "' + db["schema"] + '".correlation_observations '
        "WHERE tenant_id = $1 AND observation_key = $2",
        tenant,
        key,
    )
    assert sorted(after) == sorted({cycle_one, cycle_two}), "ARRAY(... SELECT DISTINCT ...) dedupes"


def _tenant_domain_payload(index: int) -> dict[str, Any]:
    """An alert whose only shared value is the tenant's own domain.

    Each payload carries a distinct file hash, so dedup keeps one observation
    per alert; the only thing any pair shares is the domain. That is the
    "tenant domain correlates the tenant with itself" shape in its purest form.
    """

    return {
        "rule_name": "ESCU - Suspicious File Write - Rule",
        "severity": "medium",
        "event_time_source": "first_event",
        "event_time": f"2026-11-12T10:{index:02d}:00+0330",
        "alert_fields": {
            "src_domain": "attackrange.local",
            "file_hash": hashlib.sha256(f"sample-{index}".encode()).hexdigest(),
        },
    }


@pytest.mark.asyncio
async def test_run_once_publishes_the_ambient_report(db):
    """A full cycle: the report is produced, cached, and no case is formed.

    Eight alerts that share nothing but the tenant's zone cannot become a
    campaign — every pair is vetoed — and the cycle must say so through
    ``result.diagnostics`` and the per-tenant cache the diagnostics endpoint
    reads, without needing the engine to be re-run by hand.
    """

    engine = CorrelationEngine(db["pool"])
    tenant = db["tenant"]
    schema = db["schema"]
    diagnostics.forget_all()

    for index in range(8):
        await db["admin"].execute(
            f'INSERT INTO "{schema}".alerts '
            "(tenant_id, title, severity, status, funnel_stage, llm_payload) "
            "VALUES ($1, $2, 'medium', 'new', 'ingested', $3::jsonb)",
            tenant,
            f"suspicious file write {index}",
            json.dumps(_tenant_domain_payload(index)),
        )

    result = await engine.run_once(tenant)

    assert result.claimed == 8
    assert result.observations == 8, "a distinct hash per alert keeps them apart"
    # 8 observations → 28 pairs; all of them share the ambient domain only.
    assert result.diagnostics is not None
    assert result.diagnostics["vetoed_pair_count"] == 28
    assert result.components == 0, "the tenant domain cannot form a campaign"
    assert result.cases_created == 0

    ambient = result.diagnostics["ambient_keys"]
    assert [item["token"] for item in ambient] == ["domain:attackrange.local"]
    assert "tenant-wide" in ambient[0]["reason"]

    # The endpoint serves the cached report, and it is the one this cycle built.
    cached = diagnostics.last(str(tenant))
    assert cached is not None
    assert cached["generated_at"] == result.diagnostics["generated_at"]
    assert cached["vetoed_pair_count"] == 28

    # And nothing was written to the case table by the run.
    assert await db["admin"].fetchval(f'SELECT count(*) FROM "{schema}".aisoc_cases') == 0


@pytest.mark.asyncio
async def test_case_coverage_repair_re_observes_cased_alerts_missing_from_the_ledger(db):
    """A cased alert that lost its ledger row is re-observed, not left blind.

    ``_load_context`` skips cased alerts, so a cased alert survives in the
    ledger only through the union on its old row. When that row is rewritten
    under a different key (grouping or normalizer change) or lost, the case's
    alerts remain cased while ``describe_alert_set`` finds no observation for
    them and the graph renders empty — measured on the case-2 dataset: 10 of 15
    case alerts uncovered, graph reduced to one observation at score 0.

    The repair must cover exactly the uncovered cased alerts, leave an alert
    that already has a row alone (no duplicate evidence), and never pull an
    uncased alert in (that is the discovery path's job).
    """

    engine = CorrelationEngine(db["pool"])
    tenant = db["tenant"]
    schema = db["schema"]

    case_id = uuid.uuid4()
    covered = uuid.uuid4()
    orphan = uuid.uuid4()
    uncased = uuid.uuid4()

    await db["admin"].execute(
        f'INSERT INTO "{schema}".aisoc_cases (id, tenant_id, title, status, alert_ids) '
        "VALUES ($1, $2, 'DC certificate theft', 'new', '{}')",
        case_id,
        tenant,
    )
    for alert_id, title, owner in (
        (covered, "certutil backup", case_id),
        (orphan, "certutil backup (orphaned row)", case_id),
        (uncased, "unrelated file write", None),
    ):
        await db["admin"].execute(
            f'INSERT INTO "{schema}".alerts '
            "(id, tenant_id, title, severity, status, case_id, funnel_stage, llm_payload) "
            "VALUES ($1, $2, $3, 'medium', 'new', $4, 'cased', $5::jsonb)",
            alert_id,
            tenant,
            title,
            owner,
            json.dumps(_tenant_domain_payload(1)),
        )

    # Only one of the two cased alerts is represented in the ledger.
    await engine._persist_observations(
        tenant, [observation("entity|T1649|covered", alert_ids=[covered])]
    )

    repaired = await engine._repair_case_coverage(
        tenant, freq={}, common=("attackrange.local",)
    )
    assert repaired == 1, "exactly the uncovered cased alert is re-observed"

    rows = await db["admin"].fetch(
        f'SELECT observation_key, alert_ids FROM "{schema}".correlation_observations '
        "WHERE tenant_id = $1",
        tenant,
    )
    listed = {str(alert_id) for row in rows for alert_id in row["alert_ids"]}
    assert str(orphan) in listed, "the orphaned cased alert is back in the ledger"
    assert str(orphan) not in {
        str(alert_id)
        for row in rows
        if row["observation_key"] == "entity|T1649|covered"
        for alert_id in row["alert_ids"]
    }, "the repair must not rewrite a row that already covers other alerts"
    assert str(covered) in listed
    assert str(uncased) not in listed, "uncased alerts belong to the discovery path"

    # Idempotent: a second run finds nothing left to repair.
    assert await engine._repair_case_coverage(tenant, freq={}, common=()) == 0


@pytest.mark.asyncio
async def test_case_link_reconcile_rebuilds_case_membership_from_ownership(db):
    """``aisoc_cases.alert_ids`` is a cache; ownership on ``alerts.case_id`` wins.

    The engine links a case in the API and then writes ownership. The API can
    only stamp the ids it was given, so the row it wrote is already stale by the
    time the engine finishes. ``_link_case`` must therefore rewrite the cache
    from ``alerts.case_id`` inside the same transaction — including members this
    call never touched.
    """

    engine = CorrelationEngine(db["pool"])
    tenant = db["tenant"]
    schema = db["schema"]

    case_id = uuid.uuid4()
    existing_member = uuid.uuid4()  # cased by an earlier cycle: not in this batch
    new_member = uuid.uuid4()  # canonical for this cycle
    dedup_loser = uuid.uuid4()  # soft-dedup loser: consumed, never a member

    await db["admin"].execute(
        f'INSERT INTO "{schema}".aisoc_cases (id, tenant_id, title, status, alert_ids) '
        "VALUES ($1, $2, $3, 'new', $4)",
        case_id,
        tenant,
        "LSASS credential access on win-dc-01",
        [new_member],  # stale: only what the API knew at creation time
    )

    await db["admin"].execute(
        f'INSERT INTO "{schema}".alerts '
        "(id, tenant_id, title, severity, status, case_id, funnel_stage, correlation_state, tags) "
        "VALUES ($1, $2, 'existing member', 'high', 'in_progress', $3, 'cased', 'cased', '[\"correlation-engine\"]'::jsonb)",
        existing_member,
        tenant,
        case_id,
    )
    await db["admin"].execute(
        f'INSERT INTO "{schema}".alerts '
        "(id, tenant_id, title, severity, status, funnel_stage, tags) "
        "VALUES ($1, $2, 'new canonical alert', 'high', 'new', 'ingested', '[]'::jsonb)",
        new_member,
        tenant,
    )
    await db["admin"].execute(
        f'INSERT INTO "{schema}".alerts '
        "(id, tenant_id, title, severity, status, funnel_stage, tags) "
        "VALUES ($1, $2, 'dedup loser', 'high', 'new', 'ingested', '[]'::jsonb)",
        dedup_loser,
        tenant,
    )

    await engine._link_case(
        tenant,
        case_id=str(case_id),
        canonical=[new_member],
        deduplicated=[dedup_loser],
    )

    case_row = await db["admin"].fetchrow(
        f'SELECT alert_ids FROM "{schema}".aisoc_cases WHERE id = $1', case_id
    )
    assert case_row is not None
    # Rebuilt from ownership: the earlier member is kept, the new one is added,
    # and the dedup loser (no case_id) is excluded. The stale list is replaced.
    assert sorted(case_row["alert_ids"]) == sorted({existing_member, new_member})

    canonical = await db["admin"].fetchrow(
        f'SELECT case_id, funnel_stage, correlation_state, status, tags FROM "{schema}".alerts WHERE id = $1',
        new_member,
    )
    assert canonical["case_id"] == case_id
    assert canonical["funnel_stage"] == "cased"
    assert canonical["correlation_state"] == "cased"
    assert canonical["status"] == "in_progress"
    # asyncpg hands jsonb back as text unless a codec is registered.
    assert set(json.loads(canonical["tags"])) >= {
        "agentic-promoted",
        "reportable",
        "correlation-engine",
    }

    loser = await db["admin"].fetchrow(
        f'SELECT case_id, correlation_state FROM "{schema}".alerts WHERE id = $1', dedup_loser
    )
    assert loser["case_id"] is None, "a soft-dedup loser is consumed, never a case member"
    assert loser["correlation_state"] == "deduplicated_into_case"

    # The member linked earlier keeps its own state: reconcile only rewrites the
    # cache row, it does not re-stamp every member (and must not erase them).
    member = await db["admin"].fetchrow(
        f'SELECT case_id, correlation_state FROM "{schema}".alerts WHERE id = $1', existing_member
    )
    assert member["case_id"] == case_id
    assert member["correlation_state"] == "cased"


@pytest.mark.asyncio
async def test_claim_never_resurrects_consumed_or_terminal_alerts(db):
    """The claim TTL retries an in-flight cycle; it must not un-eat evidence.

    Soft-dedup clears ``case_id`` on the losers it folds into a representative,
    so those rows stop satisfying the ownership-based skip while keeping their
    terminal ``correlation_state``. Once their claim aged past the TTL the old
    ``_claim`` took them again and stamped ``correlation_state='claimed'``: that
    is how the all-in-one run produced a 61-alert candidate at score 6 for a
    campaign that already had a case (measured: one identical
    ``correlation_claimed_at`` on 66 rows, 61 of them dedup losers).

    So: a dedup loser or a terminal row is never claimed, an alert the engine
    never touched (owner NULL) is claimed, a fresh in-flight claim is left
    alone, and only a *stale in-flight* claim is retried.
    """

    engine = CorrelationEngine(db["pool"])
    tenant = db["tenant"]
    schema = db["schema"]

    dedup_loser = uuid.uuid4()
    cased_without_case_id = uuid.uuid4()
    dedup_never_claimed = uuid.uuid4()
    stale_in_flight = uuid.uuid4()
    fresh_in_flight = uuid.uuid4()
    untouched = uuid.uuid4()

    # (id, funnel_stage, owner, correlation_state, claimed_minutes_ago)
    rows: list[tuple[uuid.UUID, str, str | None, str | None, int | None]] = [
        (dedup_loser, "deduplicated", "graph_engine", "cased", 240),
        (cased_without_case_id, "cased", "graph_engine", "cased", 240),
        (dedup_never_claimed, "deduplicated", None, None, None),
        (stale_in_flight, "triaged", "graph_engine", "claimed", 240),
        (fresh_in_flight, "triaged", "graph_engine", "claimed", 5),
        (untouched, "ingested", None, None, None),
    ]

    for alert_id, stage, owner, state, minutes in rows:
        await db["admin"].execute(
            f'INSERT INTO "{schema}".alerts '
            "(id, tenant_id, title, severity, status, funnel_stage, llm_payload, "
            " correlation_owner, correlation_state, correlation_claimed_at) "
            "VALUES ($1, $2, $3, 'medium', 'new', $4, $5::jsonb, $6, $7, "
            "        CASE WHEN $8::int IS NULL THEN NULL"
            "             ELSE now() - make_interval(mins => $8::int) END)",
            alert_id,
            tenant,
            f"{stage} alert",
            stage,
            json.dumps(_tenant_domain_payload(1)),
            owner,
            state,
            minutes,
        )

    claimed = set(await engine._claim(tenant, 100))

    assert claimed == {stale_in_flight, untouched}, (
        "only the stale in-flight claim and the never-claimed alert are eligible"
    )
    assert dedup_loser not in claimed, "a soft-dedup loser is consumed evidence, not new work"
    assert cased_without_case_id not in claimed, "a terminal state must never be re-claimed"
    assert dedup_never_claimed not in claimed, "a dedup loser is skipped before it is ever owned"
    assert fresh_in_flight not in claimed, "the TTL only retries claims that expired"

    states = {
        row["id"]: (row["funnel_stage"], row["correlation_owner"], row["correlation_state"])
        for row in await db["admin"].fetch(
            f'SELECT id, funnel_stage, correlation_owner, correlation_state '
            f'FROM "{schema}".alerts WHERE tenant_id = $1',
            tenant,
        )
    }

    # The rows the claim refused keep exactly the state that made them ineligible:
    # overwriting 'cased' with 'claimed' is what reopened the candidate queue.
    assert states[dedup_loser] == ("deduplicated", "graph_engine", "cased")
    assert states[cased_without_case_id] == ("cased", "graph_engine", "cased")
    assert states[dedup_never_claimed] == ("deduplicated", None, None)
    assert states[fresh_in_flight] == ("triaged", "graph_engine", "claimed")
    # And the two it accepted are stamped as claimed/owned.
    assert states[stale_in_flight][2] == "claimed"
    assert states[untouched][1:] == ("graph_engine", "claimed")
