"""Observation-as-edge projection of the correlation graph.

The graph payload is what the case workspace renders, so the projection rules
are asserted here rather than in the browser: an observation is a relation, and
a relation has two endpoints.
"""

from __future__ import annotations

import pytest

from app.api.v1.endpoints.cases import _observation_mode
from app.services.candidate_discovery import (
    MAX_OBSERVATION_EDGE_ENDPOINTS,
    CandidateDiscovery,
    Observation,
    correlation_anchor,
    observation_endpoints,
    observation_projection_pairs,
)


def discovery() -> CandidateDiscovery:
    return CandidateDiscovery(session=None, lookback_hours=0)  # type: ignore[arg-type]


def observation(
    key: str,
    *,
    role: str = "general:intrusion",
    alerts: int = 2,
    tokens: dict[str, int] | None = None,
) -> Observation:
    """An observation whose token weights drive the projection order."""

    weights = tokens if tokens is not None else {"host:it000": 2}
    return Observation(
        signature=key,
        alert_ids=[f"alert-{key}-{i}" for i in range(alerts)],
        role=role,
        techniques=["T1003.006"],
        hosts=[token.split(":", 1)[1] for token in weights if token.startswith("host:")],
        users=[token.split(":", 1)[1] for token in weights if token.startswith("user:")],
        ips=[token.split(":", 1)[1] for token in weights if token.startswith("ip:")],
        domains=[token.split(":", 1)[1] for token in weights if token.startswith("domain:")],
        tokens=set(weights),
        token_weights=dict(weights),
        stories=[],
        kill_chain=[],
        first_seen=None,
        last_seen=None,
        time_quality="first_event",
    )


def role_edges(graph: dict) -> list[dict]:
    return [edge for edge in graph["edges"] if edge["kind"] == "OBSERVATION"]


def test_node_mode_keeps_the_historical_shape():
    obs = observation("obs-a", tokens={"host:it000": 2, "user:alice": 2})

    graph = discovery()._build_graph(["obs-a"], {"obs-a": obs}, [], observation_mode="node")

    assert graph["observation_mode"] == "node"
    assert {node["id"] for node in graph["nodes"]} == {"obs:obs-a", "host:it000", "user:alice"}
    assert role_edges(graph) == []
    assert {(edge["source"], edge["target"]) for edge in graph["edges"]} == {
        ("obs:obs-a", "host:it000"),
        ("obs:obs-a", "user:alice"),
    }


def test_edge_mode_draws_a_relation_between_the_observations_entities():
    obs = observation(
        "obs-a",
        role="credential_access:kerberos",
        tokens={"host:it000": 2, "user:admin": 2, "domain:cao.ir": 2},
    )

    graph = discovery()._build_graph(["obs-a"], {"obs-a": obs}, [], observation_mode="edge")

    assert graph["observation_mode"] == "edge"
    assert "obs:obs-a" not in {node["id"] for node in graph["nodes"]}
    edges = role_edges(graph)
    assert len(edges) == 3  # three endpoints → three pairs
    assert {edge["role"] for edge in edges} == {"credential_access:kerberos"}
    assert {edge["source"] for edge in edges} | {edge["target"] for edge in edges} == {
        "host:it000",
        "user:admin",
        "domain:cao.ir",
    }
    assert all(len(edge["observations"]) == 1 for edge in edges)


def test_duplicate_pairs_collapse_into_one_labelled_edge():
    first = observation("obs-a", alerts=3, tokens={"host:it000": 2, "user:alice": 2})
    second = observation("obs-b", alerts=4, tokens={"host:it000": 2, "user:alice": 2})

    graph = discovery()._build_graph(
        ["obs-a", "obs-b"], {"obs-a": first, "obs-b": second}, [], observation_mode="edge"
    )

    edges = role_edges(graph)
    assert len(edges) == 1
    edge = edges[0]
    assert edge["count"] == 2
    assert edge["alert_count"] == 7
    assert edge["observations"] == ["obs-a", "obs-b"]
    assert edge["endpoint_count"] == 2


def test_wide_observations_are_tree_projected_not_clique_projected():
    tokens = {
        "host:h1": 2,
        "user:u1": 3,
        "domain:d1": 2,
        "ip:10.0.0.9": 3,
        "hash:abc123": 3,
    }
    obs = observation("obs-wide", tokens=tokens)

    graph = discovery()._build_graph(["obs-wide"], {"obs-wide": obs}, [], observation_mode="edge")

    edges = role_edges(graph)
    assert len(tokens) > MAX_OBSERVATION_EDGE_ENDPOINTS
    assert len(edges) == len(tokens) - 1  # spanning tree
    assert all(edge["endpoint_count"] == len(tokens) for edge in edges)


def test_single_endpoint_observations_keep_their_node():
    obs = observation("obs-only-host", tokens={"host:it000": 2})

    graph = discovery()._build_graph(
        ["obs-only-host"], {"obs-only-host": obs}, [], observation_mode="edge"
    )

    assert "obs:obs-only-host" in {node["id"] for node in graph["nodes"]}
    assert role_edges(graph) == []


def test_correlation_pairs_reanchor_on_distinct_entities():
    left = observation("obs-a", tokens={"host:h1": 2, "user:shared": 2})
    right = observation("obs-b", tokens={"host:h2": 2, "user:shared": 2})
    pairs = [
        {
            "source": "obs-a",
            "target": "obs-b",
            "score": 5,
            "threshold_met": True,
            "matched": [{"kind": "user", "value": "shared", "weight": 2}],
            "l3_via": None,
        }
    ]

    graph = discovery()._build_graph(
        ["obs-a", "obs-b"], {"obs-a": left, "obs-b": right}, pairs, observation_mode="edge"
    )

    correlation = [edge for edge in graph["edges"] if edge["kind"] == "CORRELATION"]
    assert len(correlation) == 1
    assert (correlation[0]["source"], correlation[0]["target"]) == ("host:h1", "host:h2")
    assert correlation[0]["weight"] == 5
    assert correlation[0]["threshold_met"] is True


def test_projection_helpers_are_pure_and_deterministic():
    endpoints = observation_endpoints(
        [
            {"token": "host:h1", "kind": "host", "value": "h1", "weight": 2},
            {"token": "user:u1", "kind": "user", "value": "u1", "weight": 2},
            {"token": "key:weird", "kind": "weird", "value": "x", "weight": 1},
        ]
    )
    assert [endpoint["node_id"] for endpoint in endpoints] == ["host:h1", "user:u1"]
    assert len(observation_projection_pairs(endpoints)) == 1
    assert correlation_anchor(endpoints, endpoints) is None  # same entity on both sides


def test_observation_mode_resolution_prefers_request_then_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AISOC_CORRELATION_GRAPH_EDGES", raising=False)
    assert _observation_mode(None) == "node"
    assert _observation_mode("edge") == "edge"
    assert _observation_mode("nonsense") == "node"

    monkeypatch.setenv("AISOC_CORRELATION_GRAPH_EDGES", "1")
    assert _observation_mode(None) == "edge"
    assert _observation_mode("node") == "node"  # explicit request wins
