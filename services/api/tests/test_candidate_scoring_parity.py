"""The candidate list must score a pair exactly the way the engine scored it.

Regression guard for a real divergence. The list used a flat 3/3/2/1 per entity
*kind* plus +1 for a matching role and up to +2 for temporal proximity, while the
engine (``services/correlation/app/services/scoring.py``) sums per-key weights,
caps L1 at 18 and awards L2 for a shared analytic story or a kill-chain step.
"Peak link score" therefore filtered on a number that had never gated anything,
and pairs the engine refused (distinct C2 frameworks) still showed up as
candidates.
"""

from __future__ import annotations

from typing import Any

from app.services.candidate_discovery import (
    L1_CAP,
    CandidateDiscovery,
    Observation,
)


def obs(key: str, **kwargs: Any) -> Observation:
    defaults: dict[str, Any] = {
        "signature": key,
        "alert_ids": [key],
        "role": "general:intrusion",
        "techniques": [],
        "hosts": [],
        "users": [],
        "ips": [],
        "domains": [],
        "time_quality": "first_event",  # rule event time, so context can score
    }
    defaults.update(kwargs)
    return Observation(**defaults)


def score(*observations: Observation) -> tuple[dict[tuple[str, str], dict], dict]:
    discovery = CandidateDiscovery(session=None)
    scores = discovery._score_pairs({o.signature: o for o in observations})
    return discovery.pair_details, scores


def test_l1_sums_key_weights_instead_of_one_point_per_kind() -> None:
    tokens = {"host:web-01", "user:alice"}
    weights = {"host:web-01": 2, "user:alice": 3}
    details, scores = score(
        obs("a", tokens=set(tokens), token_weights=dict(weights)),
        obs("b", tokens=set(tokens), token_weights=dict(weights)),
    )

    # 2 + 3, not "one host +3 and one user +3".
    assert details[("a", "b")]["l1"] == 5
    assert scores[("a", "b")] == 5


def test_pair_sharing_only_ambient_keys_is_not_a_candidate() -> None:
    """The list must reject the pairs the engine refused to merge.

    Three weak ambient values (the tenant's own domain, a hub host, a
    high-frequency account) sum to θ=3, which is exactly how a tenant-wide
    domain used to correlate unrelated activity with itself.
    """

    tokens = {"domain:attackrange.local", "host:win-dc-01", "user:administrator"}
    weights = dict.fromkeys(tokens, 1)
    details, scores = score(
        obs("a", tokens=set(tokens), token_weights=dict(weights)),
        obs("b", tokens=set(tokens), token_weights=dict(weights)),
    )

    assert details == {}
    assert scores == {}


def test_one_specific_key_keeps_the_pair_a_candidate() -> None:
    tokens = {"domain:attackrange.local", "host:win-dc-01", "hash:9f2c1d"}
    weights = {"domain:attackrange.local": 1, "host:win-dc-01": 1, "hash:9f2c1d": 3}
    details, scores = score(
        obs("a", tokens=set(tokens), token_weights=dict(weights)),
        obs("b", tokens=set(tokens), token_weights=dict(weights)),
    )

    # Only the hash counts: the ambient domain and hub host are listed with
    # weight 0, exactly as the engine suppresses them.
    assert details[("a", "b")]["l1"] == 3
    assert scores[("a", "b")] == 3
    ambient = [m for m in details[("a", "b")]["matched"] if m.get("ambient")]
    assert {m["value"] for m in ambient} == {"attackrange.local", "win-dc-01"}


def test_l1_is_capped_at_eighteen() -> None:
    tokens = {f"hash:{i}" for i in range(8)}
    weights = dict.fromkeys(tokens, 3)
    details, _ = score(
        obs("a", tokens=set(tokens), token_weights=dict(weights)),
        obs("b", tokens=set(tokens), token_weights=dict(weights)),
    )

    assert details[("a", "b")]["l1"] == L1_CAP


def test_matching_role_earns_no_points() -> None:
    tokens = {"host:web-01"}
    details, _ = score(
        obs("a", role="credential_access:lsass", tokens=set(tokens), token_weights={"host:web-01": 2}),
        obs("b", role="credential_access:lsass", tokens=set(tokens), token_weights={"host:web-01": 2}),
    )
    assert details[("a", "b")]["l1"] == 2


def test_l2_fires_on_a_shared_analytic_story() -> None:
    tokens = {"host:web-01"}
    details, _ = score(
        obs("a", tokens=set(tokens), token_weights={"host:web-01": 2}, stories=["Endpoint"]),
        obs("b", tokens=set(tokens), token_weights={"host:web-01": 2}, stories=["Endpoint"]),
    )
    assert details[("a", "b")]["l2"] == 1


def test_l2_fires_on_kill_chain_progression() -> None:
    tokens = {"host:web-01"}
    details, _ = score(
        obs("a", tokens=set(tokens), token_weights={"host:web-01": 2}, kill_chain=["recon"]),
        obs("b", tokens=set(tokens), token_weights={"host:web-01": 2}, kill_chain=["execution"]),
    )
    assert details[("a", "b")]["l2"] == 1


def test_l2_fires_on_distinct_techniques_over_a_shared_key() -> None:
    tokens = {"user:alice"}
    details, _ = score(
        obs("a", tokens=set(tokens), token_weights={"user:alice": 2}, techniques=["T1003.001"]),
        obs("b", tokens=set(tokens), token_weights={"user:alice": 2}, techniques=["T1021.002"]),
    )
    assert details[("a", "b")]["l2"] == 1


def test_l2_is_not_temporal_proximity() -> None:
    tokens = {"host:web-01"}
    details, _ = score(
        obs("a", tokens=set(tokens), token_weights={"host:web-01": 2}, techniques=["T1003.001"]),
        obs("b", tokens=set(tokens), token_weights={"host:web-01": 2}, techniques=["T1003.001"]),
    )
    # Same action on the same host, seconds apart: the engine adds nothing.
    assert details[("a", "b")]["l2"] == 0


def test_alert_time_fallback_forfeits_context_points() -> None:
    tokens = {"host:web-01"}
    details, _ = score(
        obs(
            "a",
            tokens=set(tokens),
            token_weights={"host:web-01": 2},
            stories=["Endpoint"],
            kill_chain=["recon"],
            time_quality="alert_time_fallback",
        ),
        obs(
            "b",
            tokens=set(tokens),
            token_weights={"host:web-01": 2},
            stories=["Endpoint"],
            kill_chain=["execution"],
        ),
    )
    assert details[("a", "b")]["l2"] == 0


def test_distinct_c2_frameworks_never_score() -> None:
    tokens = {"host:web-01"}
    _, scores = score(
        obs("a", role="c2:cobalt strike", tokens=set(tokens), token_weights={"host:web-01": 2}),
        obs("b", role="c2:sliver", tokens=set(tokens), token_weights={"host:web-01": 2}),
    )
    assert scores == {}


def test_alias_spellings_of_one_host_are_a_single_l1_slot() -> None:
    """One host is 2 points, however many ways extract_keys spells it.

    Regression guard for real Case 1 data: the FQDN host, its short alias and
    the domain twin of the FQDN were summed as independent evidence (6), so any
    two alerts on a busy DC cleared θ=3 on the hostname alone.
    """

    tokens = {
        "host:ar-win-dc.attackrange.local",
        "host:ar-win-dc",
        "domain:ar-win-dc.attackrange.local",
        "user:administrator",
    }
    weights = dict.fromkeys(tokens, 2)
    details, _ = score(
        obs("a", tokens=set(tokens), token_weights=dict(weights)),
        obs("b", tokens=set(tokens), token_weights=dict(weights)),
    )

    assert details[("a", "b")]["l1"] == 4  # host 2 + user 2
    # The displayed weights still sum to L1: alias twins are listed at 0.
    matched = details[("a", "b")]["matched"]
    assert sum(item["weight"] for item in matched) == 4
    assert any(item["weight"] == 0 and item.get("alias_of") for item in matched)


def test_short_host_alias_bridges_an_fqdn_counterpart() -> None:
    details, _ = score(
        obs(
            "a",
            tokens={"host:ar-win-dc.attackrange.local", "host:ar-win-dc"},
            token_weights={"host:ar-win-dc.attackrange.local": 2, "host:ar-win-dc": 2},
        ),
        obs("b", tokens={"host:ar-win-dc"}, token_weights={"host:ar-win-dc": 2}),
    )

    assert details[("a", "b")]["l1"] == 2


def test_legacy_rows_without_weights_use_the_engine_defaults() -> None:
    details, _ = score(
        obs("a", tokens={"host:web-01"}),
        obs("b", tokens={"host:web-01"}),
    )
    # extract_keys() default for a host seen once is medium (2).
    assert details[("a", "b")]["l1"] == 2


def describe(*observations: Observation) -> dict:
    """Score the set, then build the inspect payload the modal receives."""

    discovery = CandidateDiscovery(session=None)
    by_key = {o.signature: o for o in observations}
    discovery._score_pairs(by_key)
    return discovery._describe_component(list(by_key), by_key, [], 0)


def test_observation_payload_lists_every_contributed_key_with_its_weight() -> None:
    payload = describe(
        obs(
            "a",
            tokens={"host:web-01", "hash:md5=abc"},
            token_weights={"host:web-01": 2, "hash:md5=abc": 3},
        ),
        obs("b", tokens={"user:alice"}, token_weights={"user:alice": 2}),
    )

    tokens = {item["observation_key"]: item["tokens"] for item in payload["observations"]}
    # Strongest first, so the inspector opens on the deciding evidence.
    assert [item["token"] for item in tokens["a"]] == ["hash:md5=abc", "host:web-01"]
    assert tokens["a"][0] == {
        "token": "hash:md5=abc",
        "kind": "hash",
        "value": "md5=abc",
        "weight": 3,
        "estimated": False,
    }


def test_legacy_observation_tokens_are_flagged_estimated() -> None:
    payload = describe(
        obs("a", tokens={"host:web-01"}),
        obs("b", tokens={"host:web-01"}),
    )

    tokens = payload["observations"][0]["tokens"]
    assert tokens[0]["weight"] == 2
    assert tokens[0]["estimated"] is True


def test_graph_puts_hash_and_process_guid_keys_on_the_canvas() -> None:
    """Every scored key is a node; key edges carry the weight, not a flat 1."""

    payload = describe(
        obs(
            "a",
            tokens={"host:web-01", "hash:md5=abc", "process_guid:web-01|1111"},
            token_weights={"host:web-01": 2, "hash:md5=abc": 3, "process_guid:web-01|1111": 3},
        ),
        obs(
            "b",
            tokens={"host:web-01", "hash:md5=abc"},
            token_weights={"host:web-01": 2, "hash:md5=abc": 3},
        ),
    )

    nodes = {node["id"]: node for node in payload["graph"]["nodes"]}
    assert nodes["hash:md5=abc"]["kind"] == "hash"
    assert nodes["process_guid:web-01|1111"]["kind"] == "process_guid"
    # The full key survives even though the label is truncated for the canvas.
    assert nodes["process_guid:web-01|1111"]["token"] == "process_guid:web-01|1111"

    edges = {edge["id"]: edge for edge in payload["graph"]["edges"]}
    assert edges["obs:a->host:web-01"]["weight"] == 2
    assert edges["obs:a->hash:md5=abc"]["weight"] == 3
    assert edges["obs:a->hash:md5=abc"]["kind"] == "MATCHES_HASH"
    assert edges["obs:a->process_guid:web-01|1111"]["kind"] == "INVOKES_PROCESS"
