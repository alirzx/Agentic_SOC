"""Graph-based dedup: raw alerts → observations (doc §4.2)."""

from __future__ import annotations

from app.normalizer.extract_keys import extract_keys
from app.normalizer.roles import assign_role
from app.services.observations import (
    MAX_OBSERVATION_KEY_CHARS,
    bounded_key,
    build_observation,
    group_observations,
    observation_signature,
)

LSASS_RULE = "ESCU - Windows Possible Credential Dumping - Rule"
THREE_CX_APP = "ESCU - Hunting 3CXDesktopApp Software - Rule"
SMB_RULE = "ESCU - Executable File Written in Administrative SMB Share - Rule"
RISK_RULE = "Risk - 24 Hour Risk Threshold Exceeded - Rule"


def make(payload):
    keys = extract_keys(payload)
    role = assign_role(
        rule_name=payload.get("rule_name"),
        alert_fields=payload.get("alert_fields"),
        techniques=keys.techniques,
    )
    return build_observation(payload, keys, alert_id=payload["alert_id"], role=role)


def test_lsass_identity_is_the_process_pair(by_rule):
    payloads = by_rule[LSASS_RULE]
    observations = [make(p) for p in payloads]

    assert all(o.key.startswith("lsass|") for o in observations)
    # 72 notables collapse to far fewer distinct LSASS accesses.
    assert len(group_observations(observations)) < len(payloads)


def test_same_process_pair_groups_and_different_pair_does_not(by_rule):
    payloads = by_rule[LSASS_RULE]
    first = payloads[0]
    twin = dict(first)
    twin["alert_id"] = "11111111-2222-3333-4444-555555555555"

    assert observation_signature(twin, extract_keys(twin), alert_id=twin["alert_id"]) == observation_signature(
        first, extract_keys(first), alert_id=first["alert_id"]
    )

    changed = dict(first)
    changed["alert_id"] = "99999999-2222-3333-4444-555555555555"
    changed["alert_fields"] = dict(first["alert_fields"], TargetProcessGUID="{00000000-0000-0000-0000-00000000DEAD}")
    assert observation_signature(changed, extract_keys(changed), alert_id=changed["alert_id"]) != observation_signature(
        first, extract_keys(first), alert_id=first["alert_id"]
    )


def test_3cx_app_identity_is_the_file_hash(by_rule):
    payload = by_rule[THREE_CX_APP][0]
    observation = make(payload)

    assert observation.key.startswith("file|mswin-dc01|")
    assert observation.key.count("|") == 2
    assert observation.time_quality == "first_event"


def test_smb_identity_includes_minute_and_target(by_rule):
    payload = by_rule[SMB_RULE][0]
    observation = make(payload)

    assert observation.key.startswith("smb|ar-win-dc|")
    assert "20261108T1" in observation.key
    assert "test.exe" in observation.key.lower()


def test_risk_threshold_alerts_are_never_grouped(by_rule):
    payloads = by_rule[RISK_RULE]
    observations = [make(p) for p in payloads]

    assert all(o.key.startswith("alert|") or o.key.startswith("entity|") for o in observations)
    assert all(not o.time_quality_ok for o in observations)


def _hash_blob(lines: int = 3) -> str:
    """A ``process_hash`` the way Splunk sometimes carries it: every hash of the
    file, one line per digest. Long enough to blow the 512-char API contract."""
    return "\n".join(
        f"sha1={i:040x},md5={i:032x},sha256={i:064x},imphash={i:032x}"
        for i in range(1, lines + 1)
    )


def test_long_file_identity_is_bounded_for_the_case_contract(by_rule):
    """Regression: a multi-line file digest blob 422'd the whole case bundle.

    ``POST /api/v1/cases/from-correlation`` caps ``observation_id`` at 512
    characters, so ``file|<host>|<blob>`` was rejected and no case was created
    for any alert in the bundle.
    """
    base = by_rule[THREE_CX_APP][0]
    blob = _hash_blob()
    payload = {
        **base,
        "alert_id": "12121212-3434-5656-7878-909090909090",
        "alert_fields": {**base["alert_fields"], "process_hash": blob},
    }

    first = make(payload)
    assert first.key.startswith("file|")
    assert len(first.key) <= MAX_OBSERVATION_KEY_CHARS
    assert "|#" in first.key  # readable prefix + stable digest suffix
    assert "\n" not in first.key  # printable on one timeline line

    # Same evidence → same bounded key, so graph dedup still collapses repeats.
    twin = make({**payload, "alert_id": "abababab-cdcd-efef-0101-232323232323"})
    assert twin.key == first.key

    # A different digest blob must not collide just because the prefixes match.
    other = make(
        {
            **payload,
            "alert_id": "45454545-6767-8989-abab-cdcdcdcdcdcd",
            "alert_fields": {**base["alert_fields"], "process_hash": blob + "\nextra=1"},
        }
    )
    assert other.key != first.key
    assert len(other.key) <= MAX_OBSERVATION_KEY_CHARS


def test_short_observations_are_not_rewritten(by_rule):
    """Bounding only applies to keys that actually exceed the cap."""
    payload = by_rule[THREE_CX_APP][0]
    key = observation_signature(payload, extract_keys(payload), alert_id=payload["alert_id"])

    assert "|#" not in key
    assert key.count("|") == 2


def test_bounded_key_keeps_short_keys_and_truncates_deterministically():
    short = "smb|ar-win-dc|user|20261108T1015|test.exe|share"
    assert bounded_key(short) == short

    long = "file|srv1|" + "a" * (MAX_OBSERVATION_KEY_CHARS * 2)
    bounded = bounded_key(long)
    assert len(bounded) <= MAX_OBSERVATION_KEY_CHARS
    assert bounded.startswith("file|srv1|aaa")
    assert bounded == bounded_key(long)  # stable across calls / restarts
    assert bounded != bounded_key(long + "b")  # suffix comes from the full key


def test_merge_preserves_union_of_alerts_and_evidence(by_rule):
    payload = by_rule[LSASS_RULE][0]
    a = make(payload)
    b = make({**payload, "alert_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"})
    b.key = a.key

    merged = group_observations([a, b])
    assert len(merged) == 1
    assert len(merged[0].alert_ids) == 2
    assert set(a.tokens) <= set(merged[0].tokens)
