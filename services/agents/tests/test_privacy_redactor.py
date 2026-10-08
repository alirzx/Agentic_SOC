"""Offline invariants for stable tenant-scoped SOC pseudonymization."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from app.privacy.redactor import Pseudonymizer, RedactionConfig

KEY = "0123456789abcdef0123456789abcdef"


def codec(tenant: str = "tenant-a", **kwargs) -> Pseudonymizer:
    return Pseudonymizer(tenant_id=tenant, token_key=KEY, **kwargs)


def token_for(field: str, value: str, *, tenant: str = "tenant-a") -> str:
    return codec(tenant).redact_value({field: value})[field]


def test_stable_aliases_across_instances_and_discovery_order() -> None:
    first = codec()
    second = codec()
    a_ip = first.redact_value({"src_ip": "10.20.3.7"})["src_ip"]
    first.redact_value({"user": "EXAMPLE\\alice", "hostname": "dc01.example.local"})
    second.redact_value({"hostname": "other.example.local", "user": "other"})
    b_ip = second.redact_value({"src_ip": "10.20.3.7"})["src_ip"]
    assert a_ip == b_ip
    assert token_for("hostname", "DC01.EXAMPLE.LOCAL.") == token_for("hostname", "dc01.example.local")
    assert token_for("user", "EXAMPLE\\Alice") == token_for("user", "example\\alice")
    assert token_for("user", "alice@example.local") == token_for("user", "ALICE@EXAMPLE.LOCAL")


def test_tenants_and_entity_types_have_distinct_namespaces() -> None:
    assert token_for("user", "server01", tenant="tenant-a") != token_for("user", "server01", tenant="tenant-b")
    assert token_for("user", "server01") != token_for("asset", "server01")
    assert token_for("hostname", "server01") != token_for("asset", "server01")


def test_ip_canonicalization_and_safe_network_semantics() -> None:
    v4 = token_for("src_ip", "010.020.003.007")
    # Invalid IP syntax in an IP-semantic field must never fall through.
    assert v4.startswith("IP_OPAQUE_")
    assert token_for("src_ip", "10.20.3.7").startswith("IP_V4_PRIVATE_")
    assert token_for("src_ip", " 10.20.3.7 ") == token_for("src_ip", "10.20.3.7")
    assert token_for("src_ip", "2001:0db8:0:0:0:0:0:1") == token_for("src_ip", "2001:db8::1")
    assert token_for("src_ip", "8.8.8.8").startswith("IP_V4_PUBLIC_")

    parts = (b"aisoc-privacy-v1", b"tenant-a", b"IP", b"10.20.3.7")
    payload = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
    digest = hmac.new(KEY.encode(), payload, hashlib.sha256).hexdigest()[:24].upper()
    assert token_for("src_ip", "10.20.3.7") == f"IP_V4_PRIVATE_{digest}"


def test_nested_projection_removes_identities_and_masks_secrets() -> None:
    original = {
        "src_ip": "10.20.3.7",
        "hostname": "dc01.example.local",
        "asset": "workstation-22",
        "user": "EXAMPLE\\alice",
        "email": "alice@example.local",
        "details": ["EXAMPLE\\alice used dc01.example.local from 10.20.3.7"],
        "password": "SyntheticSecretValue",
    }
    p = codec()
    safe = p.redact_value(original)
    rendered = str(safe)
    for private in ("10.20.3.7", "dc01.example.local", "workstation-22", "EXAMPLE\\alice", "alice@example.local", "SyntheticSecretValue"):
        assert private not in rendered
    assert safe["password"] == "[REDACTED_SECRET]"
    restored = p.rehydrate(safe)
    for field in ("src_ip", "hostname", "asset", "user", "email"):
        assert restored[field] == original[field]
    assert restored["password"] == "[REDACTED_SECRET]"
    assert "SyntheticSecretValue" not in p.mapping.values()


def test_camel_case_and_list_field_hints_win_over_free_text_rules() -> None:
    p = codec()
    safe = p.redact_value({"ClientIP": ["8.8.8.8"], "UserId": "Alice", "host.name": "DC01.EXAMPLE.COM"})
    assert safe["ClientIP"][0].startswith("IP_V4_PUBLIC_")
    assert safe["UserId"].startswith("USER_")
    assert safe["host.name"].startswith("HOST_")
    assert "Alice" not in p.redact("actor=Alice connected")


def test_exact_rehydration_only_leaves_unknown_alias_unchanged() -> None:
    p = codec()
    safe = p.redact_value({"hostname": "dc01.example.local"})
    assert p.rehydrate(safe)["hostname"] == "dc01.example.local"
    assert p.rehydrate("HOST_DEADBEEF") == "HOST_DEADBEEF"
    known = safe["hostname"]
    assert p.rehydrate(known + "FFFF") == known + "FFFF"


def test_public_iocs_preserved_in_text_but_structured_org_ip_protected() -> None:
    p = codec()
    text = p.redact("internal 10.20.3.7 contacted known IOC 8.8.8.8 and evil.example")
    assert "10.20.3.7" not in text
    assert "8.8.8.8" in text
    assert "evil.example" in text
    assert p.redact_value({"source_ip": "8.8.8.8"})["source_ip"] != "8.8.8.8"


def test_secret_shapes_are_irreversibly_masked_and_key_never_appears() -> None:
    p = codec()
    safe = p.redact(f"password=ExampleSecret api_key=sk-abcdefghijklmnopqrstuvwxyz123456 key={KEY}")
    assert "ExampleSecret" not in safe
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in safe
    assert KEY not in safe
    assert "[REDACTED_SECRET]" in safe
    assert not any(value.startswith("sk-") for value in p.mapping.values())


def test_config_can_disable_non_secret_category() -> None:
    p = codec(config=RedactionConfig(redact_emails=False, redact_internal_hostnames=False))
    out = p.redact("mail alice@example.corp from 10.0.0.5")
    assert "alice@example.corp" in out
    assert "10.0.0.5" not in out


def test_active_reverse_maps_are_instance_local() -> None:
    first, second = codec(), codec()
    first.redact("10.0.0.5")
    assert first.mapping
    assert not second.mapping


def test_path_aware_nested_ocsf_fields_and_alias_families() -> None:
    p = codec()
    original = {
        "device": {"name": "endpoint01.corp.synthetic.test", "ip": "8.8.8.8"},
        "src_endpoint": {"hostname": "src01.corp.synthetic.test", "ip": "B_309"},
        "destination_endpoint": {"name": "dst01.corp.synthetic.test", "ip": "2001:db8::8"},
        "actor": {"user": {"name": "alice"}},
        "account": {"name": "alice"},
        "principal": {"name": "alice"},
    }
    safe = p.redact_value(original)
    assert safe["device"]["name"].startswith("HOST_")
    assert safe["device"]["ip"].startswith("IP_V4_PUBLIC_")
    assert safe["src_endpoint"]["ip"].startswith("IP_OPAQUE_")
    assert safe["destination_endpoint"]["ip"].startswith("IP_V6_")
    assert safe["actor"]["user"]["name"].startswith("USER_")
    assert safe["account"]["name"] == safe["principal"]["name"] == safe["actor"]["user"]["name"]
    assert p.rehydrate(safe) == original


def test_src_dest_aliases_use_value_semantics_and_authoritative_mappings() -> None:
    p = codec()
    safe = p.redact_value(
        {
            "src": "B_309",
            "src_ip": "B_309",
            "dst": "8.8.8.8",
            "dest": "endpoint01.corp.synthetic.test",
        }
    )
    assert safe["src"] == safe["src_ip"]
    assert safe["src"].startswith("IP_OPAQUE_")
    assert safe["dst"].startswith("IP_V4_PUBLIC_")
    assert safe["dest"].startswith("HOST_")


def test_entity_and_risk_object_use_sibling_type_without_masking_placeholders() -> None:
    p = codec()
    host = "endpoint01.corp.synthetic.test"
    safe_host = p.redact_value(
        {
            "entity_type": "system",
            "entity": host,
            "risk_object": host,
            "normalized_risk_object": host,
        }
    )
    assert safe_host["entity"].startswith("HOST_")
    assert safe_host["entity"] == safe_host["risk_object"] == safe_host["normalized_risk_object"]

    safe_user = p.redact_value(
        {
            "entity_type": "user",
            "entity": "unknown",
            "risk_object": "unknown",
            "normalized_risk_object": "unknown",
        }
    )
    assert safe_user["entity"] == safe_user["risk_object"] == safe_user["normalized_risk_object"] == "unknown"


def test_contextual_text_and_final_sweep_protect_earlier_repeats() -> None:
    p = codec()
    host = "endpoint01.corp.synthetic.test"
    text = (
        f"Registry modification on {host}. Later hostname={host}; "
        f"| search dest=\"{host}\" user=\"alice\" src_ip=\"B_309\". "
        "Public IOC evil.example and 8.8.8.8 remain useful."
    )
    safe = p.redact(text)
    assert host not in safe and "alice" not in safe and "B_309" not in safe
    assert safe.count("HOST_") >= 3
    assert "USER_" in safe and "IP_OPAQUE_" in safe
    assert "evil.example" in safe and "8.8.8.8" in safe
    assert p.rehydrate(safe) == text


def test_common_placeholders_and_explicit_non_identity_ids_are_preserved() -> None:
    values = ["unknown", "n/a", "NA", "none", "null", "not available", "-"]
    p = codec()
    for value in values:
        assert p.redact_value({"user": value, "src_ip": value, "hostname": value}) == {
            "user": value,
            "src_ip": value,
            "hostname": value,
        }
    ids = {
        "event_id": "evt-synthetic",
        "notable_id": "notable-synthetic",
        "source_event_id": "source-event-synthetic",
        "connector_id": "connector-synthetic",
        "source_connector_id": "source-connector-synthetic",
        "finding": {"uid": "finding-synthetic"},
    }
    assert p.redact_value(ids) == ids


def test_synthetic_splunk_schema_families() -> None:
    samples = json.loads((Path(__file__).parent / "fixtures" / "privacy_splunk_samples.json").read_text())

    spray = codec()
    spray_safe = spray.redact_value(samples["password_spray"])
    assert "B_309" not in json.dumps(spray_safe)
    assert spray_safe["src"].startswith("IP_OPAQUE_")
    assert spray_safe["src"] == spray_safe["src_ip"] == spray_safe["src_endpoint"]["ip"]
    assert "T1110.003" in json.dumps(spray_safe)
    assert spray.rehydrate(spray_safe) == samples["password_spray"]

    registry = codec()
    registry_safe = registry.redact_value(samples["registry_host"])
    original_host = samples["registry_host"]["dest"]
    assert original_host not in json.dumps(registry_safe)
    host_alias = registry_safe["dest"]
    assert host_alias.startswith("HOST_")
    assert registry_safe["hostname"] == registry_safe["device"]["name"] == host_alias
    assert registry_safe["splunk_notable"]["entity"] == host_alias
    assert registry_safe["splunk_notable"]["risk_object"] == host_alias
    assert registry_safe["splunk_notable"]["normalized_risk_object"] == host_alias
    assert registry_safe["session_token"] == "[REDACTED_SECRET]"
    restored_registry = registry.rehydrate(registry_safe)
    assert restored_registry["dest"] == original_host
    assert restored_registry["session_token"] == "[REDACTED_SECRET]"

    firewall = codec()
    firewall_safe = firewall.redact_value(samples["firewall_placeholder"])
    assert samples["firewall_placeholder"]["dest"] not in json.dumps(firewall_safe)
    for field in ("user",):
        assert firewall_safe[field] == "unknown"
    for field in ("entity", "risk_object", "normalized_risk_object"):
        assert firewall_safe["splunk_notable"][field] == "unknown"
    assert "USER_" not in json.dumps(firewall_safe)
