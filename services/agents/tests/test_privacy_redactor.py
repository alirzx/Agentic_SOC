"""Offline invariants for stable tenant-scoped SOC pseudonymization."""

from __future__ import annotations

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
    # Leading-zero IPv4 is deliberately rejected by ipaddress, not conflated.
    assert v4 == "010.020.003.007"
    assert token_for("src_ip", "10.20.3.7").startswith("IP_V4_PRIVATE_")
    assert token_for("src_ip", " 10.20.3.7 ") == token_for("src_ip", "10.20.3.7")
    assert token_for("src_ip", "2001:0db8:0:0:0:0:0:1") == token_for("src_ip", "2001:db8::1")
    assert token_for("src_ip", "8.8.8.8").startswith("IP_V4_PUBLIC_")


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
