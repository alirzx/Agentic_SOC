"""L1/L2/L3 scoring, θ gating, C2 veto and time-quality rules."""

from __future__ import annotations

from datetime import UTC, datetime

from app.normalizer.extract_keys import Key
from app.services.observations import Observation, parse_time
from app.services.scoring import (
    THETA,
    TenantGraph,
    connected_components,
    score_matrix,
    score_pair,
)


def obs(
    key: str,
    *,
    hosts: tuple[str, ...] = (),
    users: tuple[str, ...] = (),
    ips: tuple[str, ...] = (),
    guids: tuple[str, ...] = (),
    techniques: tuple[str, ...] = (),
    stories: tuple[str, ...] = (),
    kill_chain: tuple[str, ...] = (),
    role: str = "general:intrusion",
    time_quality: str = "first_event",
    alerts: tuple[str, ...] = (),
    extra: tuple[Key, ...] = (),
) -> Observation:
    keys = (
        [Key("host", h, 2) for h in hosts]
        + [Key("user", u, 2) for u in users]
        + [Key("ip", i, 2) for i in ips]
        + [Key("process_guid", g, 3, scope=hosts[0] if hosts else None) for g in guids]
        + list(extra)
    )
    return Observation(
        key=key,
        alert_ids=list(alerts) or [key],
        keys=keys,
        hosts=list(hosts),
        users=list(users),
        ips=list(ips),
        process_guids=list(guids),
        techniques=list(techniques),
        stories=list(stories),
        kill_chain=list(kill_chain),
        role=role,
        first_seen=datetime(2026, 11, 8, 18, 0, tzinfo=UTC),
        last_seen=datetime(2026, 11, 8, 19, 0, tzinfo=UTC),
        time_quality=time_quality,
    )


def test_shared_entities_sum_into_l1():
    a = obs("a", hosts=("srv1",), users=("administrator",))
    b = obs("b", hosts=("srv1",), users=("administrator",))
    pair = score_pair(a, b)

    assert pair.l1 == 4
    assert pair.l2 == 0  # no MITRE context on either side
    assert pair.l3 == 0  # direct overlap only
    assert pair.total == 4
    assert pair.passes


def test_unrelated_observations_do_not_correlate():
    a = obs("a", hosts=("srv1",), techniques=("T1003.001",))
    b = obs("b", hosts=("srv2",), techniques=("T1195.002",))
    pair = score_pair(a, b)

    assert pair.l1 == 0
    assert pair.total < THETA
    assert not pair.passes


def test_alias_spellings_of_one_host_do_not_inflate_l1():
    """One host fact is 2 points, not 6 (FQDN + short alias + domain twin).

    Regression guard for real Case 1 data: with aliases summed as independent
    evidence, a single shared DC cleared θ=3 on the hostname alone and
    unrelated alerts merged into one case.
    """
    keys = [
        Key("host", "ar-win-dc.attackrange.local", 2),
        Key("host", "ar-win-dc", 2, alias=True),
        Key("domain", "ar-win-dc.attackrange.local", 2, alias=True),
        Key("user", "administrator", 2),
    ]
    a = obs("a", extra=tuple(keys))
    b = obs("b", extra=tuple(keys))

    assert score_pair(a, b).l1 == 4  # host 2 + user 2


def test_host_alone_needs_progression_or_graph_evidence():
    a = obs("a", hosts=("ar-win-dc.attackrange.local",), techniques=("T1003.002",))
    b = obs("b", hosts=("ar-win-dc.attackrange.local",), techniques=("T1003.002",))

    pair = score_pair(a, b)
    assert pair.l1 == 2
    assert pair.total == 2  # same action, same host: below θ
    assert not pair.passes


def test_l3_requires_a_third_observation_with_two_distinct_keys():
    """A–K1–C–K2–B is a graph path; A–K1–B alone is just L1."""
    # a and b share the account, and the host/IP pair is joined through c.
    a = obs("a", hosts=("srv1",), users=("alice",))
    b = obs("b", ips=("10.0.0.5",), users=("alice",))
    c = obs("c", hosts=("srv1",), ips=("10.0.0.5",))
    graph = TenantGraph([a, b, c])

    bridged = score_pair(a, b, graph=graph)
    assert bridged.l1 == 2  # user:alice
    assert bridged.l3 == 1  # srv1 ↔ c ↔ 10.0.0.5 through distinct keys

    # Same L1 without the intermediate observation: no graph path, no L3.
    lonely_graph = TenantGraph([a, b])
    direct = score_pair(a, b, graph=lonely_graph)
    assert direct.l1 == 2
    assert direct.l3 == 0

    # L3 is gated on L1 ≥ 2: a path alone never scores.
    x = obs("x", hosts=("srv1",))
    y = obs("y", ips=("10.0.0.5",))
    unlinked = score_pair(x, y, graph=TenantGraph([x, y, c]))
    assert unlinked.l1 == 0
    assert unlinked.l3 == 0


def test_alert_time_fallback_earns_no_context_points():
    a = obs("a", hosts=("srv1",), techniques=("T1003.001",), kill_chain=("Exploitation",), time_quality="alert_time_fallback")
    b = obs("b", hosts=("srv1",), techniques=("T1195.002",), kill_chain=("Delivery",))
    pair = score_pair(a, b)

    assert pair.l1 == 2
    assert pair.l2 == 0
    assert pair.l3 == 0
    assert pair.total == 2


def test_kill_chain_progression_adds_l2():
    a = obs("a", hosts=("srv1",), techniques=("T1003.001",), kill_chain=("Exploitation",))
    b = obs("b", hosts=("srv1",), techniques=("T1048.003",), kill_chain=("Exfiltration",))
    pair = score_pair(a, b)

    assert pair.l1 == 2
    assert pair.l2 == 1
    assert pair.total == 3
    assert pair.passes


def test_distinct_c2_frameworks_are_vetoed():
    a = obs("a", hosts=("srv1",), techniques=("T1071.001",), role="c2:sliver")
    b = obs("b", hosts=("srv1",), techniques=("T1071.001",), role="c2:cobalt strike")
    pair = score_pair(a, b)

    assert pair.veto is not None
    assert pair.total == 0
    assert not pair.passes


def test_pair_sharing_only_ambient_keys_is_vetoed():
    """A tenant-wide domain plus other wallpaper must not reach θ on its own.

    Each of these keys is weak because ``extract_keys`` downgraded it: the AD
    domain of the tenant, a hub host and a high-frequency account. Three weak
    values used to sum to 3 = θ, which is how unrelated activity on one tenant
    domain correlated itself into a case.
    """

    wallpaper = (
        Key("domain", "attackrange.local", 1),
        Key("host", "win-dc-attack-range-84", 1),
        Key("user", "administrator", 1),
    )
    a = obs("a", extra=wallpaper)
    b = obs("b", extra=wallpaper)

    pair = score_pair(a, b)

    assert pair.veto is not None
    assert pair.veto.startswith("ambient_keys_only")
    assert pair.total == 0
    assert not pair.passes
    assert connected_components([a, b], score_matrix([a, b])) == []


def test_one_specific_key_keeps_an_otherwise_ambient_pair():
    wallpaper = (
        Key("domain", "attackrange.local", 1),
        Key("host", "win-dc-attack-range-84", 1),
        Key("hash", "9f2c1d", 3),
    )
    a = obs("a", extra=wallpaper)
    b = obs("b", extra=wallpaper)

    pair = score_pair(a, b)

    assert pair.veto is None
    # Ambient keys are listed on the pair but worth nothing: only the hash is
    # evidence. Counting the domain and the hub host as 1 each would let a
    # tenant-wide value lift a borderline pair over θ.
    assert pair.l1 == 3
    assert pair.passes


def test_ambient_alias_group_needs_every_twin_to_be_ambient():
    """An alias twin cannot launder a strong key into ambience (or back)."""

    # The domain twin of an FQDN collapses onto the host's alias group; the host
    # key is medium (a rare server), so the group is informative.
    a = obs("a", extra=(Key("host", "win-dc-01", 2), Key("domain", "win-dc-01.corp.local", 1)))
    b = obs("b", extra=(Key("host", "win-dc-01", 2), Key("domain", "win-dc-01.corp.local", 1)))

    assert score_pair(a, b).veto is None


def test_connected_components_require_two_observations():
    a = obs("a", hosts=("srv1",), users=("administrator",), alerts=("a1",))
    b = obs("b", hosts=("srv1",), users=("administrator",), alerts=("b1", "b2"))
    components = connected_components([a, b], score_matrix([a, b]))

    assert len(components) == 1
    assert components[0].alert_ids == ["a1", "b1", "b2"]
    assert components[0].score >= THETA


def test_single_observation_never_becomes_a_case():
    a = obs("a", hosts=("srv1",), users=("administrator",))
    assert connected_components([a], score_matrix([a])) == []


def test_parse_time_accepts_splunk_offsets():
    parsed = parse_time("2026-11-08T19:53:51+0330")
    assert parsed is not None
    assert parsed.utcoffset().total_seconds() == 3 * 3600 + 30 * 60
    assert parse_time("null") is None
    assert parse_time("not-a-time") is None
