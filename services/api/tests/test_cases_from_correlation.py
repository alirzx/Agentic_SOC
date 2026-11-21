"""Contract tests for ``POST /api/v1/cases/from-correlation``.

These cover the parts of the endpoint that do not need a database session: the
request contract, the deduplicated-alert filter (doc §7.2), and the route +
scope wiring. The SQL paths are exercised end to end against the dev stack in
``docs/architecture/correlation-engine.md``.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.deps import CORRELATION_WRITE_SCOPES
from app.api.v1.endpoints.api_keys import VALID_SCOPES
from app.api.v1.endpoints.cases import (
    CreateCaseFromCorrelationRequest,
    candidate_observations,
    ensure_new_case_has_evidence,
    partition_claimable_alerts,
    partition_correlation_alerts,
    router as cases_router,
)
from fastapi import HTTPException
from pydantic import ValidationError


def _row(funnel_stage: str | None, case_id: uuid.UUID | None = None):
    return SimpleNamespace(
        id=uuid.uuid4(), funnel_stage=funnel_stage, severity="high", case_id=case_id
    )


def test_deduplicated_alerts_are_ignored_not_members():
    rows = [_row("deduplicated"), _row("triaged"), _row("deduplicated"), _row(None)]
    eligible, ignored = partition_correlation_alerts(rows)

    assert [r.funnel_stage for r in eligible] == ["triaged", None]
    assert ignored == 2


def test_all_deduplicated_rows_leave_nothing_eligible():
    eligible, ignored = partition_correlation_alerts([_row("deduplicated")])
    assert eligible == []
    assert ignored == 1


def test_alerts_owned_by_another_case_are_not_claimable():
    """A case must never list evidence it does not own.

    Regression: ``alert_ids`` used to be written before the guarded claim update,
    so an alert already owned by another case stayed on the new case — the
    workspace showed 4 linked alerts, the investigation brief showed 0.
    """
    own_case = uuid.uuid4()
    other_case = uuid.uuid4()
    rows = [_row(None), _row("triaged", case_id=own_case), _row("triaged", case_id=other_case)]

    claimable, cased_elsewhere = partition_claimable_alerts(rows, target_case_id=own_case)

    assert [r.case_id for r in claimable] == [None, own_case]
    assert cased_elsewhere == 1


def test_new_case_claims_only_unowned_alerts():
    other_case = uuid.uuid4()
    rows = [_row(None), _row(None, case_id=other_case)]

    claimable, cased_elsewhere = partition_claimable_alerts(rows, target_case_id=None)

    assert len(claimable) == 1
    assert claimable[0].case_id is None
    assert cased_elsewhere == 1


def test_every_alert_cased_elsewhere_leaves_nothing_to_claim():
    other_case = uuid.uuid4()
    rows = [_row("triaged", case_id=other_case), _row("triaged", case_id=other_case)]

    claimable, cased_elsewhere = partition_claimable_alerts(rows, target_case_id=None)

    assert claimable == []
    assert cased_elsewhere == 2


def test_a_new_case_with_one_claimable_alert_is_refused():
    """One alert plus its duplicates is a detection, not a campaign.

    The engine's canonicaliser can leave a single alert behind (the rest were
    duplicates or already owned by a stronger cluster); opening a case for it is
    what filled the case list with single-alert "campaigns".
    """
    with pytest.raises(HTTPException) as exc:
        ensure_new_case_has_evidence(existing_case_id=None, claimable=[_row(None)])

    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "single_alert_campaign"
    assert exc.value.detail["claimable_alerts"] == 1


def test_two_claimable_alerts_open_a_case():
    ensure_new_case_has_evidence(existing_case_id=None, claimable=[_row(None), _row("triaged")])


def test_an_existing_campaign_may_be_extended_by_one_alert():
    # The case already holds evidence; a single new alert grows it.
    ensure_new_case_has_evidence(existing_case_id=uuid.uuid4(), claimable=[_row(None)])


def test_candidate_observations_carry_the_evidence_count():
    """Promotion must ship observations, or the case reads ``observations: 0``."""
    alert_a, alert_b = uuid.uuid4(), uuid.uuid4()
    candidate = {
        "observations": [
            {
                "observation_key": "lsass|srv1|a|b|T1003.001",
                "role": "credential_access:lsass",
                "techniques": ["T1003.001"],
                "alert_ids": [str(alert_a), str(alert_b)],
                "first_seen": None,
                "last_seen": None,
                "time_quality": "first_event",
            },
            {"observation_key": ""},  # no key → dropped
            {"observation_key": "bad", "alert_ids": ["not-a-uuid"]},  # dropped
            "not-a-dict",  # dropped
        ]
    }

    observations = candidate_observations(candidate)

    assert len(observations) == 1
    assert observations[0].observation_id == "lsass|srv1|a|b|T1003.001"
    assert observations[0].role == "credential_access:lsass"
    assert observations[0].alert_ids == [alert_a, alert_b]
    assert observations[0].time_quality == "first_event"


def test_candidate_without_observations_still_promotes():
    assert candidate_observations({}) == []


def test_request_requires_at_least_one_alert():
    with pytest.raises(ValidationError):
        CreateCaseFromCorrelationRequest(
            campaign_key="credential-access|host:srv1",
            score=5,
            normalizer_version="2.0.0",
            related_alert_ids=[],
        )


def test_request_rejects_short_campaign_key():
    with pytest.raises(ValidationError):
        CreateCaseFromCorrelationRequest(
            campaign_key="x",
            score=5,
            normalizer_version="2.0.0",
            related_alert_ids=[uuid.uuid4()],
        )


def test_request_accepts_observation_bundle():
    body = CreateCaseFromCorrelationRequest(
        campaign_key="credential-access|host:srv1",
        campaign_theme="credential-access",
        score=7,
        normalizer_version="2.0.0",
        related_alert_ids=[uuid.uuid4()],
        severity="high",
        entity_matches=[{"kind": "host", "value": "srv1.example.com"}],
        observations=[
            {
                "observation_id": "lsass|srv1|a|b|T1003.001",
                "role": "credential_access:lsass",
                "alert_ids": [uuid.uuid4()],
                "time_quality": "first_event",
            }
        ],
    )

    assert body.campaign_key == "credential-access|host:srv1"
    assert body.observations[0].role == "credential_access:lsass"


def test_request_rejects_unknown_entity_kind():
    with pytest.raises(ValidationError):
        CreateCaseFromCorrelationRequest(
            campaign_key="credential-access|host:srv1",
            score=3,
            normalizer_version="2.0.0",
            related_alert_ids=[uuid.uuid4()],
            entity_matches=[{"kind": "passport", "value": "srv1"}],
        )


def test_route_is_registered_before_the_case_id_catch_all():
    """/cases/{case_id} would shadow /cases/from-correlation if declared first."""
    paths = [route.path for route in cases_router.routes]
    assert "/cases/from-correlation" in paths
    # Declared before the catch-all so it is matchable.
    assert paths.index("/cases/from-correlation") < paths.index("/cases/{case_id}")


def test_dedicated_scope_is_valid_and_accepted():
    assert "cases:write:correlation" in VALID_SCOPES
    assert "cases:write:correlation" in CORRELATION_WRITE_SCOPES
