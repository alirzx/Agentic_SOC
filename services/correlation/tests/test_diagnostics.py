"""The per-tenant ambient report: what was suppressed, and why."""

from __future__ import annotations

from datetime import UTC, datetime

from app.normalizer.extract_keys import H_HUB, T_USER_COMMON, Key
from app.services import diagnostics
from app.services.diagnostics import build_ambient_report, forget_all, last, remember
from app.services.observations import Observation
from app.services.scoring import score_pair


def obs(
    key: str,
    *,
    keys: tuple[Key, ...],
    role: str = "general:intrusion",
    alerts: tuple[str, ...] = (),
) -> Observation:
    return Observation(
        key=key,
        alert_ids=list(alerts) or [key],
        keys=list(keys),
        role=role,
        first_seen=datetime(2026, 11, 11, 9, 0, tzinfo=UTC),
        last_seen=datetime(2026, 11, 11, 9, 30, tzinfo=UTC),
        time_quality="first_event",
    )


def test_each_ambient_key_reports_the_rule_that_fired():
    freq = {
        ("host", "hub-dc-01"): H_HUB + 1,
        ("user", "svc-backup"): T_USER_COMMON + 1,
        ("domain", "microsoft.com"): 3,
        ("domain", "attackrange.local"): 20,
    }
    report = build_ambient_report(
        tenant_id="t1",
        freq=freq,
        ambient={"hub-dc-01", "svc-backup", "microsoft.com", "attackrange.local"},
        observations=[],
        pairs=[],
        total_alerts=20,
        theta=3,
    )

    by_token = {item["token"]: item for item in report["ambient_keys"]}
    assert set(by_token) == {
        "host:hub-dc-01",
        "user:svc-backup",
        "domain:microsoft.com",
        "domain:attackrange.local",
    }
    assert str(H_HUB) in by_token["host:hub-dc-01"]["reason"]
    assert str(T_USER_COMMON) in by_token["user:svc-backup"]["reason"]
    assert "allow-list" in by_token["domain:microsoft.com"]["reason"]
    # 20 of 20 alerts: the ratio rule, not the 30-day absolute one.
    assert "tenant-wide" in by_token["domain:attackrange.local"]["reason"]
    assert by_token["domain:attackrange.local"]["share"] == 1.0
    assert by_token["domain:attackrange.local"]["frequency"] == 20


def test_the_ratio_rule_is_named_before_the_absolute_one():
    """A large window clears the absolute count too; the report must not lie.

    Regression from the real corpus: ``attackrange.local`` on 166 of 166 alerts
    was reported as "well-known domain (seen 166× > 100)", which describes a
    different rule than the one that actually flagged it.
    """

    freq = {("domain", "attackrange.local"): 166, ("domain", "vendor.example"): 150}
    report = build_ambient_report(
        tenant_id="t1",
        freq=freq,
        ambient={"attackrange.local", "vendor.example"},
        observations=[],
        pairs=[],
        total_alerts=166,  # the corpus window
        theta=3,
    )
    by_token = {item["token"]: item for item in report["ambient_keys"]}

    assert "tenant-wide" in by_token["domain:attackrange.local"]["reason"]
    # 150 hits in a 5 000-alert window is frequent, not tenant-wide: the same
    # count means different things depending on the window it is measured in.
    wide = build_ambient_report(
        tenant_id="t1",
        freq=freq,
        ambient={"vendor.example"},
        observations=[],
        pairs=[],
        total_alerts=5000,
        theta=3,
    )
    assert "frequent domain" in wide["ambient_keys"][0]["reason"]


def test_vetoed_pairs_name_the_ambient_keys_and_skip_real_links():
    ambient_keys = (Key("domain", "attackrange.local", 1), Key("host", "win-dc-01", 1))
    hash_key = Key("hash", "9f2c1d", 3)

    # a and b also share a rare hash, so they are genuinely linked; c carries the
    # wallpaper only, so both of its pairs must be vetoed.
    a = obs("a", keys=ambient_keys + (hash_key,), role="credential_access:lsass", alerts=("a1", "a2"))
    b = obs("b", keys=ambient_keys + (hash_key,), role="lateral_movement:smb", alerts=("b1",))
    c = obs("c", keys=ambient_keys, role="execution:powershell", alerts=("c1",))

    pairs = [score_pair(a, b), score_pair(a, c), score_pair(b, c)]
    report = build_ambient_report(
        tenant_id="t1",
        freq={("domain", "attackrange.local"): 20, ("host", "win-dc-01"): 20},
        ambient={"attackrange.local", "win-dc-01"},
        observations=[a, b, c],
        pairs=pairs,
        total_alerts=20,
        theta=3,
    )

    # c shares only wallpaper, so its two pairs are vetoed and listed with both
    # roles and the exact keys that caused it. a↔b shares a rare hash: not listed.
    assert report["vetoed_pair_count"] == 2
    assert report["vetoed_pairs_truncated"] is False
    assert {(entry["left"], entry["right"]) for entry in report["vetoed_pairs"]} == {
        ("a", "c"),
        ("b", "c"),
    }
    for entry in report["vetoed_pairs"]:
        assert set(entry["ambient_keys"]) == {"domain:attackrange.local", "host:win-dc-01"}
    a_vs_c = next(e for e in report["vetoed_pairs"] if e["left"] == "a")
    assert {a_vs_c["left_role"], a_vs_c["right_role"]} == {
        "credential_access:lsass",
        "execution:powershell",
    }
    assert a_vs_c["alerts"] == 3  # 2 on a + 1 on c: what the operator expected merged

    # The report never claims a pair was vetoed when it scored.
    assert report["pair_count"] == 3
    assert all({e["left"], e["right"]} != {"a", "b"} for e in report["vetoed_pairs"])


def test_pair_listing_is_capped_but_the_count_is_complete():
    ambient = (Key("domain", "attackrange.local", 1),)
    observations = [obs(f"o{i}", keys=ambient) for i in range(4)]
    pairs = []
    for i, left in enumerate(observations):
        for right in observations[i + 1 :]:
            pairs.append(score_pair(left, right))

    report = build_ambient_report(
        tenant_id="t1",
        freq={("domain", "attackrange.local"): 4},
        ambient={"attackrange.local"},
        observations=observations,
        pairs=pairs,
        total_alerts=8,
        theta=3,
        pair_limit=2,
    )

    assert report["vetoed_pair_count"] == 6, "the count is complete even when the list is not"
    assert len(report["vetoed_pairs"]) == 2
    assert report["vetoed_pairs_truncated"] is True


def test_nothing_ambient_reports_cleanly():
    a = obs("a", keys=(Key("host", "rare-srv", 2),), alerts=("a1",))
    b = obs("b", keys=(Key("host", "rare-srv", 2),), alerts=("b1",))
    report = build_ambient_report(
        tenant_id="t1",
        freq={("host", "rare-srv"): 1},
        ambient=set(),
        observations=[a, b],
        pairs=[score_pair(a, b)],
        total_alerts=2,
        theta=3,
    )

    assert report["ambient_keys"] == []
    assert report["ambient_key_count"] == 0
    assert report["vetoed_pair_count"] == 0
    # An empty report still says what it covers — not a blank dict.
    assert report["note"].startswith("Ambient values")
    assert "not persisted history" in report["note"]


def test_last_cycle_cache_is_per_tenant_and_bounded():
    forget_all()
    try:
        for index in range(diagnostics.MAX_CACHED_TENANTS + 1):
            remember({"tenant_id": f"t{index}", "ambient_keys": []})

        assert last("t0") is None, "the oldest tenant is evicted"
        assert last("t1") is not None
        latest = last(f"t{diagnostics.MAX_CACHED_TENANTS}")
        assert latest is not None and latest["tenant_id"] == f"t{diagnostics.MAX_CACHED_TENANTS}"

        # Callers get a copy; mutating it must not rewrite the cached report.
        latest["ambient_keys"].append("mutation")
        again = last(f"t{diagnostics.MAX_CACHED_TENANTS}")
        assert again is not None and again["ambient_keys"] == []
    finally:
        forget_all()
