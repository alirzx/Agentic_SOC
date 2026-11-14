"""P2 mandatory gate — Adaptive Security Domain Profiles."""

from __future__ import annotations

from app.services.tier2_adaptive.entities import (
    extract_alert_entities,
    powershell_regression_alert,
)
from app.services.tier2_adaptive.profiles import (
    PROFILE_REGISTRY,
    InvestigationProfile,
    register_profile,
    select_investigation_profiles,
)


def test_endpoint_profile_independent():
    alert = {
        "security_domain": "endpoint",
        "llm_payload": {"alert_fields": {"Computer": "host1.local", "Image": "cmd.exe"}},
    }
    sel = select_investigation_profiles(alert)
    assert "endpoint" in sel.names
    assert "inspect_script_block" in PROFILE_REGISTRY["endpoint"].operations
    assert sel.fallback_used is False


def test_network_profile_independent():
    alert = {
        "security_domain": "network",
        "llm_payload": {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"},
    }
    sel = select_investigation_profiles(alert)
    assert "network" in sel.names
    assert any("inspect_src_dest_ip" in p.operations for p in sel.profiles)


def test_identity_profile_independent():
    alert = {
        "security_domain": "identity",
        "llm_payload": {
            "alert_fields": {"user_id": "S-1-5-21-1-2-3-4", "username": "jdoe"}
        },
    }
    sel = select_investigation_profiles(alert)
    assert "identity" in sel.names


def test_firewall_profile_independent():
    alert = {
        "security_domain": "firewall",
        "title": "Firewall deny outbound",
        "llm_payload": {"src_ip": "10.0.0.1", "dest_ip": "8.8.8.8"},
    }
    sel = select_investigation_profiles(alert)
    assert "firewall" in sel.names


def test_web_profile_independent():
    alert = {
        "security_domain": "web",
        "llm_payload": {"alert_fields": {"url": "https://evil.example/path"}},
    }
    sel = select_investigation_profiles(alert)
    assert "web" in sel.names


def test_email_profile_independent():
    alert = {
        "security_domain": "email",
        "llm_payload": {
            "alert_fields": {
                "sender": "phish@evil.com",
                "recipient": "user@corp.com",
            }
        },
    }
    sel = select_investigation_profiles(alert)
    assert "email" in sel.names


def test_cloud_profile_independent():
    alert = {
        "security_domain": "cloud",
        "llm_payload": {
            "alert_fields": {
                "account_id": "123456789012",
                "arn": "arn:aws:s3:::bucket/key",
            }
        },
    }
    sel = select_investigation_profiles(alert)
    assert "cloud" in sel.names


def test_malware_profile_independent():
    alert = {
        "security_domain": "malware",
        "llm_payload": {"alert_fields": {"sha256": "a" * 64, "Path": r"C:\tmp\a.exe"}},
    }
    sel = select_investigation_profiles(alert)
    assert "malware" in sel.names


def test_multi_profile_selection():
    alert = {
        "security_domain": "endpoint",
        "title": "Suspicious login after malware drop",
        "llm_payload": {
            "security_domain": "endpoint",
            "alert_fields": {
                "Computer": "ws01.corp",
                "user_id": "S-1-5-21-9-9-9-9",
                "sha256": "c" * 64,
                "Path": r"C:\Users\Public\payload.exe",
            },
        },
    }
    # Force dual domain signal via entities + malware keywords with hash.
    alert["llm_payload"]["detection_type"] = "malware"
    sel = select_investigation_profiles(alert)
    assert "endpoint" in sel.names
    # Hash + path should also surface malware when score clears threshold.
    assert len(sel.names) >= 1
    # With hash entity + malware keyword in blob from title, malware should score.
    assert "malware" in sel.names or "identity" in sel.names


def test_endpoint_plus_identity_multi():
    alert = {
        "security_domain": "endpoint",
        "llm_payload": {
            "alert_fields": {
                "Computer": "ws01.corp",
                "user_id": "S-1-5-21-1-2-3-8",
                "Image": "powershell.exe",
            }
        },
    }
    # Inject identity domain alias via raw_event secondary domain.
    alert["raw_event"] = {"orig_security_domain": "identity"}
    sel = select_investigation_profiles(alert)
    assert "endpoint" in sel.names
    assert "identity" in sel.names


def test_unknown_domain_fallback():
    alert = {
        "security_domain": "completely-unknown-xyz",
        "llm_payload": {"alert_fields": {"Computer": "only-host.local"}},
    }
    sel = select_investigation_profiles(alert)
    assert sel.names
    # Unknown domain with host → endpoint still selected via entities, or fallback.
    assert "endpoint" in sel.names


def test_missing_entities_still_selects_from_domain():
    alert = {"security_domain": "endpoint", "title": "Generic endpoint alert", "llm_payload": {}}
    sel = select_investigation_profiles(alert)
    assert "endpoint" in sel.names
    assert sel.fallback_used is False


def test_missing_ip_does_not_block_endpoint_or_identity():
    alert = powershell_regression_alert()
    ents = extract_alert_entities(alert)
    assert ents.values("ip") == []
    sel = select_investigation_profiles(alert, entities=ents)
    assert "endpoint" in sel.names
    assert sel.fallback_used is False


def test_title_alone_does_not_select_profile():
    alert = {
        "title": "Firewall deny network malware phishing cloud email attack",
        "llm_payload": {},
    }
    sel = select_investigation_profiles(alert)
    # Fallback only — no domain, no entities.
    assert sel.fallback_used is True
    assert len(sel.names) == 1


def test_conflicting_domain_signals_multi_select():
    alert = {
        "security_domain": "network",
        "raw_event": {"orig_security_domain": "firewall"},
        "llm_payload": {"src_ip": "10.0.0.2", "dest_ip": "10.0.0.3"},
    }
    sel = select_investigation_profiles(alert)
    assert "network" in sel.names
    assert "firewall" in sel.names


def test_powershell_regression_selects_endpoint():
    sel = select_investigation_profiles(powershell_regression_alert())
    assert sel.names[0] == "endpoint"
    assert "inspect_host" in sel.profiles[0].operations


def test_profile_registry_extensible():
    custom = InvestigationProfile(
        name="ot_ics",
        label="OT/ICS",
        operations=("inspect_plc",),
        entity_signals=("hostname",),
        domain_aliases=("ot", "ics", "scada"),
        rule_keywords=("modbus",),
    )
    register_profile(custom)
    try:
        alert = {"security_domain": "ot", "llm_payload": {"alert_fields": {"Computer": "plc1"}}}
        sel = select_investigation_profiles(alert)
        assert "ot_ics" in sel.names
    finally:
        PROFILE_REGISTRY.pop("ot_ics", None)


def test_selection_to_dict():
    sel = select_investigation_profiles(powershell_regression_alert())
    payload = sel.to_dict()
    assert payload["algorithm_version"].startswith("profile:")
    assert "endpoint" in payload["profile_names"]
    assert payload["reasons"]
