"""End-to-end correlation over the real 166-alert corpus (regression guard).

This is the test that pins the behaviour the engine was built for: 166 noisy
Splunk notables collapse into a small number of observation-backed campaigns,
with the isolated alerts (MSI privesc) and competing C2 frameworks correctly
left out. Numbers are asserted because they come from real data — if a change
alters them, that is a behaviour change worth reviewing, not a flaky test.
"""

from __future__ import annotations

import pytest
from app.normalizer.extract_keys import extract_keys
from app.normalizer.roles import assign_role
from app.services.observations import build_observation, group_observations
from app.services.scoring import TenantGraph, connected_components, score_matrix


@pytest.fixture(scope="module")
def pipeline(corpus):
    observations = []
    for payload in corpus:
        keys = extract_keys(payload)
        role = assign_role(
            rule_name=payload.get("rule_name"),
            alert_fields=payload.get("alert_fields"),
            techniques=keys.techniques,
        )
        observations.append(build_observation(payload, keys, alert_id=payload["alert_id"], role=role))
    observations = group_observations(observations)
    pairs = score_matrix(observations, graph=TenantGraph(observations))
    components = connected_components(observations, pairs)
    return observations, components


def test_corpus_shape(pipeline):
    observations, components = pipeline
    assert len(observations) == 58
    assert len(components) == 8


def test_one_campaign_spans_three_hosts_and_two_techniques(pipeline):
    observations, components = pipeline
    by_key = {o.key: o for o in observations}
    top = components[0]

    hosts = {h for key in top.observation_keys for h in by_key[key].hosts}
    techniques = {t for key in top.observation_keys for t in by_key[key].techniques}

    assert top.score >= 3
    assert {"win-dc-8537412.attackrange.local", "mswin-dc01.attackrange.local", "ar-win-dc.attackrange.local"} <= hosts
    assert {"T1003.001", "T1195.002"} <= techniques


def test_isolated_privesc_alert_is_not_cased(pipeline):
    observations, components = pipeline
    msi = next(o for o in observations if o.role == "privilege_escalation:msi")

    assert "win10-21h1" in msi.hosts
    for component in components:
        assert msi.key not in component.observation_keys


def test_competing_c2_frameworks_never_share_a_campaign(pipeline):
    observations, components = pipeline
    by_key = {o.key: o for o in observations}

    for component in components:
        roles = {by_key[key].role for key in component.observation_keys}
        c2_roles = {r for r in roles if r.startswith("c2:")}
        assert len(c2_roles) <= 1, f"merged distinct C2 frameworks: {c2_roles}"


def test_every_component_has_at_least_two_observations(pipeline):
    _, components = pipeline
    for component in components:
        assert len(component.observation_keys) >= 2
        assert len(component.alert_ids) >= 2


def _two_pass(corpus: list[dict]) -> tuple[set[str], list, list]:
    """Extract with the tenant baseline, the way a real cycle does.

    The ``pipeline`` fixture above skips this (no frequency available from a
    bare payload), and the ambient rules only exist on this path, so they need
    their own run over real payloads.
    """

    from app.services.frequency import common_values, count_keys

    first = [extract_keys(payload) for payload in corpus]
    freq = count_keys(first)
    common = common_values(freq, total_alerts=len(corpus))
    observations = []
    for payload in corpus:
        keys = extract_keys(payload, freq=freq, common_values=common)
        role = assign_role(
            rule_name=payload.get("rule_name"),
            alert_fields=payload.get("alert_fields"),
            techniques=keys.techniques,
        )
        observations.append(
            build_observation(payload, keys, alert_id=payload["alert_id"], role=role)
        )
    observations = group_observations(observations)
    pairs = score_matrix(observations, graph=TenantGraph(observations))
    return set(common), pairs, connected_components(observations, pairs)


def test_a_tenant_wide_domain_changes_nothing(corpus):
    """The regression the ambient rule exists for, measured on the real corpus.

    Every alert in a tenant carries the tenant's own zone (the AD domain in the
    lab). Before the rule that zone was a shared key on every pair and worth 1
    to L1, so it lifted borderline pairs (2) over θ=3 and pulled extra alerts
    into existing campaigns. With the rule the run is identical to the run
    without the domain — same components, same scores, same alerts cased — and
    the pairs that share *only* it are vetoed rather than scored.
    """

    import copy

    baseline_common, baseline_pairs, baseline_components = _two_pass(corpus)

    injected = []
    for payload in corpus:
        clone = copy.deepcopy(payload)
        clone.setdefault("alert_fields", {})["src_domain"] = "attackrange.local"
        injected.append(clone)

    common, pairs, components = _two_pass(injected)

    assert "attackrange.local" in common
    assert "attackrange.local" not in baseline_common
    assert [(c.score, c.observation_keys, c.alert_ids) for c in components] == [
        (c.score, c.observation_keys, c.alert_ids) for c in baseline_components
    ]
    assert sum(1 for p in pairs if p.passes) == sum(1 for p in baseline_pairs if p.passes)
    # Not silently equal because it still scores: the ambient-only pairs are vetoed.
    assert sum(1 for p in pairs if p.veto and p.veto.startswith("ambient_keys_only")) > 0
