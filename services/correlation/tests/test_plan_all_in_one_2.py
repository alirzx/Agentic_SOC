"""Plan-driven regression tests over the ``all-in-one-2`` corpus.

The corpus in ``docs/plans/case/all-in-one-2`` is the analyst-authored
expectation for the graph engine: four scenarios (``filter_presets.json``), the
664 ``llm_payload`` records that produced them (``llm_payload_only.json``) and a
report whose alert totals are 256 / 18 / 254 / 17 (``گزارش کیسهای تولیدی.docx``).

These tests run the engine's *pure* pipeline — extraction, weighting,
observation dedup, L1/L2/L3 scoring, connected components — exactly as
``CorrelationEngine.run_once`` does, without Postgres or HTTP, and compare the
components it finds with the four presets.

Two of the four scenarios are single-host and are reproduced today (case 3 and
case 4). The other two are not, and the reasons are structural rather than a
missing test: see
``docs/plans/case/all-in-one-2/REPORT-20261118-graph-engine-review-fa.md``.
Those expectations are pinned as strict ``xfail`` so the suite stays green while
the gap is documented, and an engine change that closes it turns the marker into
an XPASS failure that must be removed deliberately.
"""

from __future__ import annotations

import json
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from app.normalizer.extract_keys import extract_keys
from app.normalizer.roles import assign_role
from app.services.frequency import common_values, count_keys
from app.services.observations import MAX_OBSERVATION_KEY_CHARS as KEY_LIMIT
from app.services.observations import build_observation, group_observations
from app.services.scoring import L1_CAP, THETA, TenantGraph, connected_components, score_matrix

DATA = Path(__file__).resolve().parents[3] / "docs" / "plans" / "case" / "all-in-one-2"

pytestmark = pytest.mark.skipif(
    not (DATA / "llm_payload_only.json").exists(),
    reason="the all-in-one-2 corpus is not present in this checkout",
)

#: The alert total the report quotes for each scenario.
DOCUMENTED_TOTALS = {
    "case-1-Comprehensive-attack-chain": 256,
    "case-2-dc-kerberos-replication": 18,
    "case-3-dc-certificate-theft-sliver": 254,
    "case-4-webshell-ransomware-precursor": 17,
    "control-single-alert": 0,
}

#: Scenario rules that the report itself says have no alert in this capture.
RULES_WITHOUT_ALERTS = {
    "case-1-Comprehensive-attack-chain": {"Executable File Written in Administrative SMB Share"},
}


def _short_rule(name: str | None) -> str:
    """``ESCU - X - Rule`` → ``X``, the form the presets use."""
    return (name or "").replace("ESCU - ", "").replace(" - Rule", "")


def _load_corpus() -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for line in (DATA / "llm_payload_only.json").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        raw = json.loads(line)["llm_payload"]
        payloads.append(json.loads(raw) if isinstance(raw, str) else raw)
    return payloads


@lru_cache(maxsize=1)
def _pipeline() -> dict[str, Any]:
    """Run the engine's pure pipeline once for the whole corpus."""

    payloads = _load_corpus()
    # Pass 1 measures the tenant baseline, pass 2 weights with it — the same
    # two-pass shape ``run_once`` uses.
    first = [extract_keys(payload) for payload in payloads]
    freq = count_keys(first)
    common = common_values(freq, total_alerts=len(payloads))

    observations = []
    for payload in payloads:
        keys = extract_keys(payload, freq=freq, common_values=common)
        alert_fields = payload.get("alert_fields")
        role = assign_role(
            rule_name=payload.get("rule_name") or "",
            alert_fields=alert_fields if isinstance(alert_fields, dict) else None,
            techniques=keys.techniques,
        )
        observations.append(
            build_observation(payload, keys, alert_id=payload["alert_id"], role=role)
        )

    grouped = group_observations(observations)
    pairs = score_matrix(grouped, graph=TenantGraph(grouped))
    components = connected_components(grouped, pairs)
    return {
        "payloads": payloads,
        "common": common,
        "observations": grouped,
        "pairs": pairs,
        "components": components,
    }


@lru_cache(maxsize=1)
def _scenarios() -> dict[str, set[str]]:
    """``preset id → alert ids of its rules``, exactly as the plan groups them."""

    presets = json.loads((DATA / "filter_presets.json").read_text(encoding="utf-8"))["presets"]
    payloads = _load_corpus()
    return {
        preset["id"]: {
            payload["alert_id"]
            for payload in payloads
            if _short_rule(payload.get("rule_name")) in set(preset["rule_names"])
        }
        for preset in presets
    }


def _best_component(preset: str) -> tuple[set[str], int]:
    """The component that overlaps the preset most (Jaccard), with its score."""

    expected = _scenarios()[preset]
    best: tuple[set[str], int] = (set(), 0)
    best_jaccard = 0.0
    for component in _pipeline()["components"]:
        members = set(component.alert_ids)
        overlap, union = len(members & expected), len(members | expected)
        if not union:
            continue
        jaccard = overlap / union
        if jaccard > best_jaccard:
            best, best_jaccard = (members, component.score), jaccard
    return best


def _coverage(preset: str) -> tuple[int, int]:
    """``(alerts of the preset inside some component, alerts of the preset)``."""

    expected = _scenarios()[preset]
    reached: set[str] = set()
    for component in _pipeline()["components"]:
        reached |= set(component.alert_ids) & expected
    return len(reached), len(expected)


# ── the corpus itself ──────────────────────────────────────────────────────


def test_corpus_matches_the_report_totals():
    """The capture is the one the report describes, rule set by rule set."""

    payloads = _load_corpus()
    assert len(payloads) == 664, "the corpus is the 664-alert capture referenced by the report"

    scenarios = _scenarios()
    for preset, total in DOCUMENTED_TOTALS.items():
        assert len(scenarios[preset]) == total, f"{preset}: report says {total} alerts"

    present = {_short_rule(p.get("rule_name")) for p in payloads}
    for preset, rule_names in RULES_WITHOUT_ALERTS.items():
        assert not (rule_names & present), f"{preset}: {rule_names} must have no alert here"


def test_scenarios_do_not_share_alerts():
    """Each preset is a disjoint scenario; otherwise no group comparison means anything."""

    scenarios = _scenarios()
    ids = list(scenarios.items())
    for index, (left_id, left) in enumerate(ids):
        for right_id, right in ids[index + 1 :]:
            assert not (left & right), f"{left_id} and {right_id} share {len(left & right)} alerts"


def test_time_quality_splits_the_scenarios():
    """Half of case 1 and most of case 2 arrive with an alert-time fallback.

    That is the single most consequential property of this corpus: ``score_pair``
    awards no L2/L3 to such an alert (doc §3.3), so their pairs can only reach
    the host/user weight of 2 — below θ=3 — no matter how related they are.
    """

    payloads = _load_corpus()
    by_id = {p["alert_id"]: p for p in payloads}
    scenarios = _scenarios()
    expected = {
        "case-1-Comprehensive-attack-chain": (171, 85),
        "case-2-dc-kerberos-replication": (13, 5),
        "case-3-dc-certificate-theft-sliver": (0, 254),
        "case-4-webshell-ransomware-precursor": (0, 17),
    }
    for preset, (fallback, confirmed) in expected.items():
        counts = Counter(by_id[alert_id].get("event_time_source") for alert_id in scenarios[preset])
        assert counts["alert_time_fallback"] == fallback, preset
        assert counts["first_event"] == confirmed, preset


def test_tenant_ambient_values_explain_the_weak_bridges():
    """``administrator`` and the DC FQDN are ambient in this window, not evidence."""

    common = _pipeline()["common"]
    assert "administrator" in common
    assert "win-dc-mhaag-attack-range-84.attackrange.local" in common


# ── what the engine does reproduce ─────────────────────────────────────────


def test_case3_single_host_certificate_theft_is_one_campaign():
    """254 alerts: 240 on one DC form one component; the rest sit on other hosts.

    The scenario expects all 254 in one case, but 14 of them name a second DC, an
    attack box or ``dest=0``. The component is therefore the DC half of the
    scenario — and it is the strongest component in the corpus (score 12).
    """

    reached, total = _coverage("case-3-dc-certificate-theft-sliver")
    assert total == 254
    assert reached >= 240, "the certificate-theft alerts on the main DC must be reachable"

    members, score = _best_component("case-3-dc-certificate-theft-sliver")
    expected = _scenarios()["case-3-dc-certificate-theft-sliver"]
    precision = len(members & expected) / len(members)
    assert score == 12
    assert precision >= 0.95, "the component must not pull unrelated alerts in"


def test_case4_single_host_ransomware_precursor_is_one_campaign():
    """16 of 17 alerts on ``quadra.snapattack.labs``; one is on another host."""

    members, score = _best_component("case-4-webshell-ransomware-precursor")
    expected = _scenarios()["case-4-webshell-ransomware-precursor"]
    assert len(members & expected) >= 16
    assert len(members) == len(members & expected), "no alert outside the scenario"
    assert score == 5


def test_observation_keys_fit_the_case_contract():
    """The API rejects a bundle whose ``observation_id`` exceeds 512 characters."""

    keys = [observation.key for observation in _pipeline()["observations"]]
    assert keys
    assert max(len(key) for key in keys) <= KEY_LIMIT


def test_pair_scores_stay_within_their_documented_bounds():
    l1_cap_hit = 0
    for pair in _pipeline()["pairs"]:
        assert 0 <= pair.l1 <= L1_CAP
        assert pair.l2 in (0, 1) and pair.l3 in (0, 1)
        assert pair.total <= L1_CAP + 2
        if pair.total >= THETA and not pair.veto:
            l1_cap_hit += 1
    assert l1_cap_hit, "the corpus contains at least one passing pair"


def test_components_never_mix_an_ambient_only_pair():
    """A passing pair must have at least one non-ambient shared key, by contract."""

    for component in _pipeline()["components"]:
        for pair in component.pairs:
            assert not pair.veto
            assert pair.total >= THETA
            assert pair.l1 >= 2, "θ cannot be reached on an ambient-only overlap"


# ── where the engine and the plan disagree (documented, not silently ignored) ──


@pytest.mark.xfail(
    strict=True,
    reason=(
        "case 1 is a 5-day, multi-host scenario: 256 alerts span 64 destination hosts "
        "and 14 sources, the 161 C2 alerts share no destination at all, and 171 of the "
        "256 carry alert_time_fallback so L2/L3 are zero and no pair can exceed the "
        "host weight of 2. Its 256 alerts spread over 22 components (largest: 62) instead "
        "of one, and only 192 of them reach any component at all."
    ),
)
def test_case1_comprehensive_chain_is_one_campaign():
    members, _ = _best_component("case-1-Comprehensive-attack-chain")
    expected = _scenarios()["case-1-Comprehensive-attack-chain"]
    assert len(members & expected) >= 0.9 * len(expected)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "13 of case 2's 18 alerts are alert_time_fallback, so they cannot earn L2/L3; "
        "sharing the DC only gives L1=2. The 5 first-event alerts do merge — into a "
        "cluster that also holds LSASS alerts from case 1 (see the mixing test)."
    ),
)
def test_case2_dc_kerberos_replication_is_one_campaign():
    reached, total = _coverage("case-2-dc-kerberos-replication")
    assert reached >= 0.9 * total


@pytest.mark.xfail(
    strict=True,
    reason=(
        "host (2) + 'techniques differ' (L2=1) already reaches θ=3, so unrelated "
        "activity on one DC merges: a 35-alert component holds 13 case-1 alerts and 5 "
        "case-2 alerts, and a 21-alert component mixes case 1 and case 3."
    ),
)
def test_no_component_mixes_two_plan_scenarios():
    scenarios = _scenarios()
    mixed = []
    for component in _pipeline()["components"]:
        members = set(component.alert_ids)
        hit = [preset for preset, ids in scenarios.items() if members & ids]
        if len(hit) > 1:
            mixed.append((component.score, len(members), hit))
    assert mixed == []


# ── a scenario the corpus cannot exercise ─────────────────────────────────


def test_single_alert_control_has_no_alert_in_the_capture():
    """The negative control preset is declared but never occurs in the payloads.

    So "one alert alone must not open a case" is *not* covered by this corpus;
    it is covered by the unit tests for ``case_skip_reason`` and
    ``connected_components`` instead.
    """

    assert _scenarios()["control-single-alert"] == set()
    assert all(len(component.alert_ids) >= 2 for component in _pipeline()["components"])
