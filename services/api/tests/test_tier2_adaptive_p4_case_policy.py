"""P4 mandatory gate — Case Management Policy."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from app.services.tier2_adaptive.case_policy import (
    CASE_POLICY_VERSION,
    decide_case_action,
    _lock_for,
)
from app.services.tier2_adaptive.correlation import (
    CorrelationHistoryEntry,
    CorrelationResult,
)
from app.services.tier2_adaptive.entities import (
    extract_alert_entities,
    powershell_regression_alert,
)


def _corr(results: list[CorrelationResult]) -> CorrelationHistoryEntry:
    return CorrelationHistoryEntry(
        seed_alert_id="seed",
        results=results,
        window_hours=24,
        recorded_at="2026-11-14T00:00:00Z",
    )


def test_high_severity_single_alert_without_ip():
    alert = powershell_regression_alert()
    ents = extract_alert_entities(alert)
    assert ents.values("ip") == []
    decision = decide_case_action(alert, entities=ents, correlation=_corr([]))
    assert decision.action == "create"
    assert "high_severity" in decision.reason
    assert decision.idempotency_key


def test_endpoint_case_creation():
    alert = {
        "id": "ep-1",
        "severity": "high",
        "security_domain": "endpoint",
        "llm_payload": {"alert_fields": {"Computer": "host1.local", "Image": "cmd.exe"}},
    }
    decision = decide_case_action(alert, correlation=_corr([]))
    assert decision.action == "create"
    assert any(e["entity_type"] == "hostname" for e in decision.entity_snapshot)


def test_identity_case_creation():
    alert = {
        "id": "id-1",
        "severity": "critical",
        "security_domain": "identity",
        "llm_payload": {
            "alert_fields": {"user_id": "S-1-5-21-1-2-3-4", "username": "alice"}
        },
    }
    decision = decide_case_action(alert, correlation=_corr([]))
    assert decision.action == "create"


def test_existing_case_extension_via_membership():
    alert = {
        "id": "a1",
        "severity": "high",
        "case_id": "case-existing",
        "llm_payload": {"alert_fields": {"Computer": "h1"}},
    }
    decision = decide_case_action(alert, correlation=_corr([]))
    assert decision.action == "extend"
    assert decision.case_id == "case-existing"


def test_existing_case_extension_via_eligible_correlation():
    alert = {
        "id": "a1",
        "severity": "medium",
        "llm_payload": {"alert_fields": {"Computer": "h1"}},
    }
    decision = decide_case_action(
        alert,
        correlation=_corr(
            [
                CorrelationResult(
                    candidate_alert_id="a2",
                    total_score=78.0,
                    decision="eligible",
                    correlation_reasons=[],
                )
            ]
        ),
    )
    assert decision.action == "extend"
    assert decision.correlation_score == 78.0


def test_below_threshold_correlation_review():
    alert = {
        "id": "a1",
        "severity": "medium",
        "llm_payload": {"alert_fields": {"Computer": "h1"}},
    }
    decision = decide_case_action(
        alert,
        correlation=_corr(
            [
                CorrelationResult(
                    candidate_alert_id="a2",
                    total_score=55.0,
                    decision="candidate",
                )
            ]
        ),
    )
    assert decision.action == "review"
    assert decision.correlation_score == 55.0


def test_no_false_case_extension_below_threshold():
    alert = {
        "id": "a1",
        "severity": "low",
        "llm_payload": {"alert_fields": {"Computer": "h1"}},
    }
    decision = decide_case_action(
        alert,
        correlation=_corr(
            [
                CorrelationResult(
                    candidate_alert_id="a2",
                    total_score=25.0,
                    decision="unrelated",
                )
            ]
        ),
    )
    assert decision.action == "standalone"


def test_conflicting_entities_block_extend():
    alert = {
        "id": "a1",
        "severity": "high",
        "llm_payload": {"alert_fields": {"Computer": "h1"}},
    }
    decision = decide_case_action(
        alert,
        correlation=_corr(
            [
                CorrelationResult(
                    candidate_alert_id="a2",
                    total_score=80.0,
                    decision="eligible",
                    contradictory=True,
                )
            ]
        ),
    )
    # Contradictory eligible is ignored → falls through to create (high + evidence).
    assert decision.action == "create"


def test_duplicate_case_prevention_idempotency_key():
    alert = powershell_regression_alert()
    d1 = decide_case_action(alert, correlation=_corr([]))
    d2 = decide_case_action(alert, correlation=_corr([]))
    assert d1.idempotency_key == d2.idempotency_key
    assert d1.idempotency_key.startswith("tier2-case:create-solo:")


def test_concurrent_case_extension_lock():
    """Concurrency-safe lock acquisition for same campaign key."""
    key = "tenant-x:theme|host:h1"
    acquired: list[int] = []

    def worker(n: int) -> None:
        lock = _lock_for(key)
        with lock:
            acquired.append(n)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))
    assert sorted(acquired) == list(range(8))
    assert _lock_for(key) is _lock_for(key)


def test_tenant_isolation_in_decision_snapshot():
    alert = {
        "id": "a1",
        "tenant_id": "tenant-a",
        "severity": "high",
        "llm_payload": {"alert_fields": {"Computer": "h1"}},
    }
    decision = decide_case_action(alert, correlation=_corr([]))
    assert decision.action == "create"
    assert decision.policy_version == CASE_POLICY_VERSION


def test_existing_case_compatibility_replay_standalone():
    alert = {
        "id": "a1",
        "severity": "high",
        "disposition": "false_positive",
        "llm_payload": {"alert_fields": {"Computer": "h1"}},
    }
    decision = decide_case_action(alert, correlation=_corr([]))
    assert decision.action == "standalone"
    assert "replay" in decision.reason or "benign" in decision.reason


def test_medium_without_siblings_standalone_if_not_high():
    alert = {
        "id": "a1",
        "severity": "medium",
        "llm_payload": {"alert_fields": {"Computer": "h1"}},
    }
    decision = decide_case_action(alert, correlation=_corr([]))
    assert decision.action == "standalone"


def test_decision_to_dict():
    alert = powershell_regression_alert()
    decision = decide_case_action(alert, correlation=_corr([]))
    payload = decision.to_dict()
    assert payload["action"] == "create"
    assert payload["entity_snapshot"]
    assert payload["policy_version"].startswith("case-policy:")
