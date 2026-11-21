"""A case is a claim that several *distinct* alerts agree with each other.

The floor is counted on the canonical alerts a case would list, which is the
only count the analyst sees. Counting the component's raw alerts instead is how
the engine ended up opening campaign cases that held exactly one alert: an
observation with eleven copies of the same detection folds into one canonical
winner plus ten soft-dedup losers.
"""

import pytest

from app.core.config import settings
from app.safe_db import safe_execute, safe_executemany, safe_fetch, safe_transaction
from app.services.engine import case_skip_reason
from app.services.observations import Observation


def observation(*, time_quality: str = "first_event") -> Observation:
    return Observation(key="k", alert_ids=["a"], time_quality=time_quality)


def reason(*, canonical, claimed, min_alerts=2, time_quality="first_event"):
    return case_skip_reason(
        canonical=canonical,
        claimed=claimed,
        members=[observation(time_quality=time_quality)],
        min_alerts=min_alerts,
    )


def test_default_floor_is_two_alerts():
    # Lowering this back to 1 re-opens the single-alert campaign cases.
    assert settings.min_case_alerts == 2


def test_one_canonical_alert_is_not_a_campaign():
    assert reason(canonical=["a"], claimed=["a"]) == "below_min_case_alerts"


def test_two_distinct_alerts_may_open_a_case():
    assert reason(canonical=["a", "b"], claimed=["a", "b"]) is None


def test_an_alert_already_in_another_case_does_not_count_towards_the_floor():
    # ``canonical`` is already filtered to the alerts this component owns, so a
    # lone leftover next to a stronger cluster cannot seed a case of its own.
    assert reason(canonical=["leftover"], claimed=["leftover"]) == "below_min_case_alerts"


def test_nothing_claimable_is_reported_as_already_owned():
    assert reason(canonical=["a", "b"], claimed=[]) == "already_owned"


def test_alert_time_fallback_cannot_seed_a_case():
    assert (
        reason(canonical=["a", "b"], claimed=["a", "b"], time_quality="alert_time_fallback")
        == "alert_time_fallback"
    )


def test_knob_can_be_lowered_for_one_alert_campaigns():
    # Explicit opt-in for corpora where a campaign genuinely is one alert.
    assert reason(canonical=["a"], claimed=["a"], min_alerts=1) is None


class _DummyConnection:
    def __init__(self):
        self.fetch_rows = [{"id": "abc"}]
        self.executed = []
        self.executemany_rows = []

    async def fetch(self, query, *args):
        return self.fetch_rows

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "OK"

    async def executemany(self, query, args_list):
        self.executemany_rows = list(args_list)
        return "OK"

    def transaction(self):
        return _DummyTransaction()


class _DummyTransaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_safe_db_helpers_accept_direct_connection_objects():
    conn = _DummyConnection()

    rows = await safe_fetch(conn, "SELECT 1", operation_name="direct_fetch")
    assert rows == [{"id": "abc"}]

    assert await safe_execute(conn, "UPDATE alerts SET status = 'new'", operation_name="direct_execute") is True

    assert await safe_executemany(
        conn,
        "INSERT INTO alerts (id) VALUES ($1)",
        [("x",)],
        operation_name="direct_executemany",
    ) is True

    assert await safe_transaction(
        conn,
        lambda inner: inner.execute("SELECT 2"),
        operation_name="direct_transaction",
    ) is True
