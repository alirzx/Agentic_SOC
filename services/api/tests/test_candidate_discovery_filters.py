from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from app.services.candidate_discovery import CandidateDiscovery, Observation


@pytest.mark.asyncio
async def test_candidate_discovery_skips_low_score_components(monkeypatch) -> None:
    discovery = CandidateDiscovery(session=None, theta=3, lookback_hours=72)

    observations = {
        "obs-a": Observation(
            signature="obs-a",
            alert_ids=["a1"],
            role="attacker",
            techniques=["T1003"],
            hosts=["host-a"],
            users=["alice"],
            ips=[],
            domains=[],
        ),
        "obs-b": Observation(
            signature="obs-b",
            alert_ids=["a2"],
            role="attacker",
            techniques=[],
            hosts=["host-b"],
            users=["bob"],
            ips=[],
            domains=[],
        ),
    }

    async def fake_load_observations(_tenant_id: str):
        return observations

    def fake_score_pairs(_obs_map):
        return {("obs-a", "obs-b"): 2}

    async def fake_load_alert_data(_tenant_id: str, _alert_ids: list[str]):
        now = datetime.now(UTC)
        return [
            {"id": "a1", "created_at": now, "severity": "high"},
            {"id": "a2", "created_at": now, "severity": "high"},
        ]

    async def fake_drop_cased(_tenant_id: str, obs_map):
        return obs_map

    monkeypatch.setattr(discovery, "_load_observations", fake_load_observations)
    monkeypatch.setattr(discovery, "_drop_cased_alerts", fake_drop_cased)

    monkeypatch.setattr(discovery, "_score_pairs", fake_score_pairs)
    monkeypatch.setattr(discovery, "_load_alert_data", fake_load_alert_data)

    results = await discovery.run("tenant-1")

    assert results == []


@pytest.mark.asyncio
async def test_candidate_discovery_stringifies_alert_ids(monkeypatch) -> None:
    discovery = CandidateDiscovery(session=None, theta=3, lookback_hours=72)
    alert_a = UUID("11111111-1111-4111-8111-111111111111")
    alert_b = UUID("22222222-2222-4222-8222-222222222222")

    observations = {
        "obs-a": Observation(
            signature="obs-a",
            alert_ids=[alert_a],
            role="attacker",
            techniques=["T1003"],
            hosts=["host-a"],
            users=["alice"],
            ips=[],
            domains=[],
        ),
        "obs-b": Observation(
            signature="obs-b",
            alert_ids=[alert_b],
            role="attacker",
            techniques=["T1003"],
            hosts=["host-b"],
            users=["alice"],
            ips=[],
            domains=[],
        ),
    }

    async def fake_load_observations(_tenant_id: str):
        return observations

    def fake_score_pairs(_obs_map):
        return {("obs-a", "obs-b"): 3}

    async def fake_load_alert_data(_tenant_id: str, _alert_ids: list[str]):
        now = datetime.now(UTC)
        return [
            {"id": alert_a, "created_at": now, "severity": "high"},
            {"id": alert_b, "created_at": now, "severity": "high"},
        ]

    async def fake_drop_cased(_tenant_id: str, obs_map):
        return obs_map

    monkeypatch.setattr(discovery, "_load_observations", fake_load_observations)
    monkeypatch.setattr(discovery, "_drop_cased_alerts", fake_drop_cased)

    monkeypatch.setattr(discovery, "_score_pairs", fake_score_pairs)
    monkeypatch.setattr(discovery, "_load_alert_data", fake_load_alert_data)

    results = await discovery.run("tenant-1")

    assert results
    assert results[0]["alert_ids"] == [str(alert_a), str(alert_b)]
    assert all(isinstance(item, str) for item in results[0]["alert_ids"])


def _same_alert_observations(alert_id: str) -> dict[str, Observation]:
    """One alert recorded under two observation signatures.

    This is what the all-in-one corpus produced: the ambient set changes the
    strong-key digest between cycles, so ``_persist_observations`` (which unions
    ``alert_ids`` per observation_key) ends up with two rows naming the same
    alert. Measured live: candidate ``component-3b6074d512a2``, 1 alert, 2
    observations, peak link 4 next to the singleton it came from.
    """

    shared = {"host:ar-win-dc", "user:unpriv2"}
    weights = {"host:ar-win-dc": 2, "user:unpriv2": 2}
    return {
        "entity|T1098|7befb2ac35a0cec7": Observation(
            signature="entity|T1098|7befb2ac35a0cec7",
            alert_ids=[alert_id],
            role="general:intrusion",
            techniques=["T1098"],
            hosts=["ar-win-dc", "ar-win-dc.attackrange.local"],
            users=["unpriv2"],
            ips=[],
            domains=["ar-win-dc.attackrange.local"],
            tokens=set(shared),
            token_weights=dict(weights),
            time_quality="alert_time_fallback",
        ),
        "entity|T1098|e7c0b3df388cd92b": Observation(
            signature="entity|T1098|e7c0b3df388cd92b",
            alert_ids=[alert_id],
            role="general:intrusion",
            techniques=["T1098"],
            hosts=["ar-win-dc", "ar-win-dc.attackrange.local"],
            users=["unpriv2"],
            ips=[],
            domains=["ar-win-dc.attackrange.local"],
            tokens=set(shared),
            token_weights=dict(weights),
            time_quality="alert_time_fallback",
        ),
    }


def test_identical_alert_sets_are_never_scored_as_a_pair() -> None:
    """Two rows about the same alert are one action, not a correlation."""

    discovery = CandidateDiscovery(session=None, theta=3, lookback_hours=72)
    observations = _same_alert_observations("33333333-3333-4333-8333-333333333333")

    # The shared host + user would score L1=4 on their own (θ is 3), so an empty
    # result proves the identical-evidence skip, not a low score.
    assert discovery._score_pairs(observations) == {}


@pytest.mark.asyncio
async def test_component_with_a_single_distinct_alert_is_not_a_candidate(monkeypatch) -> None:
    """Even if a pair score exists, one alert cannot be a campaign."""

    discovery = CandidateDiscovery(session=None, theta=3, lookback_hours=72)
    alert = UUID("33333333-3333-4333-8333-333333333333")
    observations = _same_alert_observations(str(alert))

    async def fake_load_observations(_tenant_id: str):
        return observations

    async def fake_drop_cased(_tenant_id: str, obs_map):
        return obs_map

    async def fake_load_alert_data(_tenant_id: str, _alert_ids: list[str]):
        now = datetime.now(UTC)
        return [{"id": alert, "created_at": now, "severity": "medium"}]

    monkeypatch.setattr(discovery, "_load_observations", fake_load_observations)
    monkeypatch.setattr(discovery, "_drop_cased_alerts", fake_drop_cased)
    monkeypatch.setattr(discovery, "_load_alert_data", fake_load_alert_data)
    monkeypatch.setattr(
        discovery,
        "_score_pairs",
        lambda _obs: {
            ("entity|T1098|7befb2ac35a0cec7", "entity|T1098|e7c0b3df388cd92b"): 4
        },
    )

    assert await discovery.run("tenant-1") == []
