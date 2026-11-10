"""Tests for the importable automation-rule packs.

Two things are worth pinning here:

1. **Data integrity** — the packs are hand-written data, so a typo in an
   operator, an unknown action slug, or the same detection appearing in two
   rules (which would fire twice) must fail the build rather than reach a
   tenant.
2. **Match semantics** — each rule must match the alert that its named Splunk
   detection produces, and must not match an unrelated alert. ``rule_name``
   carries the notable's ``search_name``; the comparison is case-insensitive.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.runbook import (
    RulePackImportRequest,
    import_rule_pack,
    list_rule_packs,
)
from app.services.runbook.action_catalog import ACTIONS
from app.services.runbook.condition_eval import evaluate_all, validate_conditions
from app.services.runbook.packs import (
    PACKS,
    covered_detection_names,
    get_pack,
    list_packs,
    pack_rule_payloads,
)

VALID_TRIGGERS = {"alert.created", "alert.updated", "case.created", "manual"}
VALID_LEVELS = {"L0", "L1", "L2", "L3", "L4"}

ALL_RULES = [rule for pack in list_packs() for rule in pack.rules]


# ── Data integrity ────────────────────────────────────────────────────────────


def test_every_pack_has_rules_and_a_source() -> None:
    assert PACKS, "no packs registered"
    for pack in list_packs():
        assert pack.id and " " not in pack.id
        assert pack.label and pack.description
        assert pack.source, f"{pack.id} does not name its upstream corpus"
        assert pack.rules, f"{pack.id} has no rules"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.name)
def test_rule_conditions_are_valid(rule) -> None:
    assert validate_conditions(rule.conditions) == []


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.name)
def test_rule_targets_governed_actions_and_valid_enums(rule) -> None:
    assert rule.action_slug in ACTIONS, f"unknown action {rule.action_slug!r}"
    assert rule.autonomy_level in VALID_LEVELS
    assert rule.trigger_type in VALID_TRIGGERS
    assert 1 <= rule.priority <= 9999
    assert len(rule.name) <= 256


DETECTION_RULES = [rule for pack in list_packs() for rule in pack.rules if rule.detections]
CORE_RULES = [rule for rule in ALL_RULES if not rule.detections]


@pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.name)
def test_detection_pack_rules_ship_as_dry_run(rule) -> None:
    """Detection-driven pack rules install decisions, not execution."""
    assert rule.dry_run is True


def test_core_default_pack_keeps_the_legacy_posture() -> None:
    """Moving a rule into a pack must not change what the rule does.

    The general rules used to be seeded with a mix of dry-run and executing
    posture, and importing them now must reproduce that exactly — silently
    flipping an executing rule to dry run (or the reverse) would be a behaviour
    change disguised as a plumbing change. The console shows this posture per
    rule before anything is added.
    """
    pack = get_pack("core-defaults")
    assert pack is not None
    executing = sorted(rule.name for rule in pack.rules if not rule.dry_run)
    assert executing == sorted(
        [
            "Add TI context to case on indicator match",
            "Auto-close EICAR test files",
            "Auto-enrich network alerts",
            "Tag noisy endpoint rules for tuning",
        ]
    )
    assert all(rule.dry_run for rule in pack.rules if rule.name not in executing)


def test_rule_names_are_unique_and_detections_are_not_double_booked() -> None:
    names = [rule.name for rule in ALL_RULES]
    assert len(names) == len(set(names)), "duplicate rule name across packs"

    # A detection claimed by two rules would fire two actions on one alert.
    owners: dict[str, str] = {}
    for pack in list_packs():
        for rule in pack.rules:
            for detection in rule.detections:
                key = detection.strip().casefold()
                assert key not in owners, (
                    f"detection {detection!r} is claimed by both "
                    f"{owners[key]!r} and {rule.name!r}"
                )
                owners[key] = rule.name


def test_covered_detections_count_matches_the_rules() -> None:
    pack = get_pack("windows-splunk")
    assert pack is not None
    assert len(covered_detection_names(pack)) == len(
        {d for rule in pack.rules for d in rule.detections}
    )


def test_every_pack_rule_payload_carries_its_docs_and_owner() -> None:
    for pack in list_packs():
        for payload in pack_rule_payloads(pack):
            # No pack points at a docs URL: the anchor the detection packs used
            # to reference never existed, and a dead link on a governed action
            # is worse than none.
            assert payload.get("docs_ref") is None, f"{payload['name']} has a docs_ref"

    # Detection-driven rules are owned by detection engineering so they group in
    # the console filters. The general rules carry over with no owner, exactly as
    # they were seeded.
    windows = get_pack("windows-splunk")
    assert windows is not None
    assert all(p["owner_team"] for p in pack_rule_payloads(windows))


# ── Match semantics ───────────────────────────────────────────────────────────


def _subject(rule_name: str, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "rule_name": rule_name,
        "severity": "high",
        "status": "new",
        "category": "endpoint",
        "source": "splunk",
        "confidence": 80,
        "title": rule_name,
        "tags": [],
        "mitre_techniques": [],
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.name)
def test_rule_matches_each_of_its_detections(rule) -> None:
    for detection in rule.detections:
        assert evaluate_all(rule.conditions, _subject(detection)), (
            f"{rule.name} does not match its own detection {detection!r}"
        )


@pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.name)
def test_rule_match_is_case_insensitive(rule) -> None:
    detection = rule.detections[0]
    assert evaluate_all(rule.conditions, _subject(detection.upper()))


@pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.name)
def test_rule_ignores_unrelated_alerts(rule) -> None:
    assert not evaluate_all(rule.conditions, _subject("Unrelated Linux detection"))
    assert not evaluate_all(rule.conditions, _subject(""))


@pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.name)
def test_rule_fails_closed_without_a_rule_name(rule) -> None:
    """A notable that carries no search_name must not trigger containment."""
    subject = _subject("")
    subject.pop("rule_name")
    assert not evaluate_all(rule.conditions, subject)


def test_windows_pack_covers_the_named_families() -> None:
    """Guard against a silent shrink: the families the pack advertises exist."""
    pack = get_pack("windows-splunk")
    assert pack is not None
    detections = " | ".join(covered_detection_names(pack))
    for marker in (
        "Access LSASS Memory for Dump Creation",
        "Kerberoasting spn request with RC4 encryption",
        "Ransomware Notes bulk creation",
        "Deleting Shadow Copies",
        "Windows Defender ASR Rule Disabled",
        "Detect Regsvr32 Application Control Bypass",
        "WMI Permanent Event Subscription",
        "Detect PsExec With accepteula Flag",
    ):
        assert marker in detections


# ── Endpoints ─────────────────────────────────────────────────────────────────


class _Result:
    """Minimal stand-in for a SQLAlchemy ``Result``."""

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


def _user() -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="soc_analyst",
        email="analyst@example.com",
    )


def _db(existing_names: list[str] | None = None) -> AsyncMock:
    """Session stub: one name lookup, then writes the endpoint ignores."""
    db = AsyncMock()
    calls: list[Any] = []

    async def execute(stmt, *args, **kwargs):  # noqa: ANN001, ANN002
        calls.append(stmt)
        if "SELECT name FROM automation_rules" in str(stmt):
            return _Result([(name,) for name in (existing_names or [])])
        return _Result([])

    db.execute = AsyncMock(side_effect=execute)
    db.commit = AsyncMock()
    db.calls = calls  # type: ignore[attr-defined]
    return db


@pytest.mark.asyncio
async def test_list_rule_packs_reports_counts() -> None:
    user = _user()
    packs = await list_rule_packs(db=_db(), current_user=user)

    assert packs, "no packs listed"
    windows = next(p for p in packs if p.id == "windows-splunk")
    pack = get_pack("windows-splunk")
    assert pack is not None
    assert windows.rule_count == len(pack.rules)
    assert windows.covered_detections == len(covered_detection_names(pack))
    assert windows.docs_ref is None

    # Every rule is listed individually so the console can offer per-rule
    # selection, and none is reported installed for a tenant with no rules.
    assert [r.name for r in windows.rules] == [r.name for r in pack.rules]
    assert not any(r.installed for r in windows.rules)

    core = next(p for p in packs if p.id == "core-defaults")
    core_pack = get_pack("core-defaults")
    assert core_pack is not None
    assert core.rule_count == len(core_pack.rules)
    assert core.covered_detections == 0


@pytest.mark.asyncio
async def test_list_rule_packs_marks_rules_the_tenant_already_has() -> None:
    pack = get_pack("core-defaults")
    assert pack is not None
    already = [rule.name for rule in pack.rules[:2]]

    packs = await list_rule_packs(db=_db(existing_names=already), current_user=_user())
    core = next(p for p in packs if p.id == "core-defaults")

    installed = {r.name for r in core.rules if r.installed}
    assert installed == set(already)


@pytest.mark.asyncio
async def test_import_creates_every_rule_when_none_exist() -> None:
    user = _user()
    db = _db()

    result = await import_rule_pack("windows-splunk", db=db, current_user=user)

    pack = get_pack("windows-splunk")
    assert pack is not None
    assert result.created == [rule.name for rule in pack.rules]
    assert result.skipped == []
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_import_is_idempotent_by_rule_name() -> None:
    pack = get_pack("windows-splunk")
    assert pack is not None
    already = [rule.name for rule in pack.rules[:3]]
    db = _db(existing_names=already)

    result = await import_rule_pack("windows-splunk", db=db, current_user=_user())

    assert result.skipped == already
    assert result.created == [rule.name for rule in pack.rules[3:]]


@pytest.mark.asyncio
async def test_import_can_take_a_subset_of_a_pack() -> None:
    pack = get_pack("core-defaults")
    assert pack is not None
    chosen = [pack.rules[0].name, pack.rules[2].name]

    result = await import_rule_pack(
        "core-defaults",
        body=RulePackImportRequest(rule_names=chosen),
        db=_db(),
        current_user=_user(),
    )

    assert result.created == chosen
    assert result.skipped == []
    assert result.unknown == []


@pytest.mark.asyncio
async def test_import_reports_names_that_are_not_in_the_pack() -> None:
    result = await import_rule_pack(
        "core-defaults",
        body=RulePackImportRequest(rule_names=["not-a-rule"]),
        db=_db(),
        current_user=_user(),
    )

    assert result.created == []
    assert result.unknown == ["not-a-rule"]


@pytest.mark.asyncio
async def test_import_rejects_unknown_pack() -> None:
    with pytest.raises(Exception) as excinfo:
        await import_rule_pack("does-not-exist", db=_db(), current_user=_user())
    assert getattr(excinfo.value, "status_code", None) == 404
