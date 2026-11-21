"""extract_keys() against the real 2026-11-08 corpus."""

from __future__ import annotations

from app.normalizer.extract_keys import (
    NORMALIZER_VERSION,
    SYSTEM_PROCESSES,
    extract_keys,
)

LSASS_RULE = "ESCU - Windows Possible Credential Dumping - Rule"
THREE_CX_DNS = "ESCU - 3CX Supply Chain Attack Network Indicators - Rule"
THREE_CX_APP = "ESCU - Hunting 3CXDesktopApp Software - Rule"
SPRAY_SOURCE = "ESCU - Detect Password Spray Attack Behavior From Source - Rule"
SPRAY_ATTEMPTS = "ESCU - Detect Password Spray Attempts - Rule"


def test_lsass_alert_yields_host_and_scoped_process_guids(by_rule):
    payload = by_rule[LSASS_RULE][0]
    keys = extract_keys(payload)

    assert "win-dc-8537412.attackrange.local" in keys.hosts
    assert "T1003.001" in keys.techniques
    assert keys.time_quality == "first_event"

    # Process GUIDs are host-scoped so the same synthetic GUID on two DCs cannot
    # bridge them (see Key.scope).
    guid_tokens = [k.token for k in keys.keys if k.kind == "process_guid"]
    assert guid_tokens
    assert all(token.startswith("process_guid:win-dc-8537412") for token in guid_tokens)


def _domain_alert(domain: str, host: str = "ar-win-dc") -> dict:
    return {
        "rule_name": "ESCU - Kerberoasting spn request with RC4 encryption - Rule",
        "severity": "medium",
        "event_time_source": "first_event",
        "event_time": "2026-11-11T13:41:02+0330",
        "alert_fields": {"dest": host, "src_domain": domain, "user": "svc-backup"},
    }


def test_tenant_wide_domain_from_the_frequency_service_is_weak():
    """The ambient set the frequency service computes must actually be applied.

    ``_weight`` accepted ``common_values`` but only consulted the static
    ``COMMON_DOMAINS`` list for domains (and ignored it entirely for hosts and
    users), so a tenant-wide zone the service had already flagged still scored
    as a medium key.
    """

    keys = extract_keys(_domain_alert("attackrange.local"), common_values={"attackrange.local"})
    domain = next(k for k in keys.keys if k.kind == "domain" and k.value == "attackrange.local")

    assert domain.weight == 1


def test_unknown_domain_keeps_its_medium_weight():
    keys = extract_keys(_domain_alert("rare-vendor.example"))
    domain = next(k for k in keys.keys if k.kind == "domain" and k.value == "rare-vendor.example")

    assert domain.weight == 2


def test_tenant_wide_host_from_the_frequency_service_is_weak():
    keys = extract_keys(_domain_alert("rare-vendor.example"), common_values={"ar-win-dc"})
    host = next(k for k in keys.keys if k.kind == "host" and k.value == "ar-win-dc")

    assert host.weight == 1


def test_upn_and_bare_account_are_one_principal():
    """Kerberos rules say ``administrator@corp.local``; SAM rules say ``administrator``."""
    payload = {
        "rule_name": "ESCU - Kerberoasting spn request with RC4 encryption - Rule",
        "severity": "medium",
        "event_time_source": "first_event",
        "event_time": "2026-11-11T13:41:02+0330",
        "alert_fields": {
            "dest": "ar-win-dc.attackrange.local",
            "user": "Administrator@ATTACKRANGE.LOCAL",
        },
    }
    keys = extract_keys(payload)
    users = {(k.kind, k.value) for k in keys.keys if k.kind == "user"}

    assert ("user", "administrator@attackrange.local") in users
    # The twin is what lets a UPN-only alert meet a SAM/Security alert that only
    # carries the bare account name.
    assert ("user", "administrator") in users
    twin = next(k for k in keys.keys if k.kind == "user" and k.value == "administrator")
    assert twin.alias is True


def test_system_sid_never_becomes_a_user(by_rule):
    payload = by_rule[LSASS_RULE][0]
    keys = extract_keys(payload)

    assert "s-1-5-18" not in keys.users
    assert all(key.value != "s-1-5-18" for key in keys.keys)
    assert any(f["reason"] == "system_sid" for f in keys.filtered)


def test_system_process_is_not_a_key(by_rule):
    payload = by_rule[LSASS_RULE][0]
    keys = extract_keys(payload)

    assert "svchost.exe" in keys.process_names  # observed …
    assert "svchost.exe" not in keys.hosts  # … but never an entity
    assert "svchost.exe" not in keys.users


def test_cdn_answer_ip_is_zero_weight(by_rule):
    payload = by_rule[THREE_CX_DNS][0]
    keys = extract_keys(payload)

    # ``::ffff:104.18.15.54`` is Cloudflare — shared infrastructure, no signal.
    assert keys.ips == []
    assert any(f["reason"] == "zero_weight" for f in keys.filtered)
    # The commercial C2 domain survives, but only as weak evidence.
    assert ("domain", "www.3cx.com") in {(k.kind, k.value) for k in keys.keys}
    domain_key = next(k for k in keys.keys if k.value == "www.3cx.com")
    assert domain_key.weight == 1


def test_placeholder_source_is_filtered():
    # From the documented sample in docs/ahmadi/docs/NotableEvents_SPL_and_result.txt:
    # the spray rule reports the source literally as ``ATTACKER`` (attack-range
    # placeholder) while the entity is a real account.
    payload = {
        "alert_id": "207d7911-d0e6-4ec4-a71d-8933e9332a71",
        "event_time_source": "first_event",
        "event_time": "2026-10-21T20:05:38+0330",
        "alert_time": "2026-10-23T22:08:02+0330",
        "rule_name": SPRAY_SOURCE,
        "severity": "medium",
        "entity": "ADMINISTRATOR",
        "entity_type": "user",
        "annotations": {"mitre_attack": "T1110.003"},
        "alert_fields": {"src": "ATTACKER", "user": "ADMINISTRATOR", "failure": 96},
    }
    keys = extract_keys(payload)

    assert all("attacker" not in value.lower() for _, value in _pairs(keys))
    assert any(f["reason"] == "placeholder" for f in keys.filtered)
    assert "administrator" in keys.users


def test_ip_normalisation_uses_shape_not_field_name():
    payload = {
        "alert_id": "0671d3d7-98cb-47b1-bd82-9b542a4e7a30",
        "event_time_source": "alert_time_fallback",
        "event_time": "2026-10-23T22:07:56+0330",
        "alert_time": "2026-10-23T22:07:56+0330",
        "rule_name": SPRAY_ATTEMPTS,
        "severity": "medium",
        "entity": "KZSUBJQQ",
        "entity_type": "user",
        "annotations": {"mitre_attack": "T1110.003"},
        "alert_fields": {
            "src": "10.0.1.15",
            "counter": "::ffff:10.0.1.15__XmlWinEventLog__4768",
            "unique_accounts": 50,
        },
    }
    keys = extract_keys(payload)

    # ``src`` arrives as ``10.0.1.15``; ``counter`` carries a decorated
    # ``::ffff:10.0.1.15__…`` value that must not become a second IP.
    assert keys.ips == ["10.0.1.15"]
    ip_key = next(k for k in keys.keys if k.kind == "ip")
    assert ip_key.weight == 2  # RFC1918 → medium


def test_fqdn_host_also_emits_short_name(by_rule):
    payload = by_rule[THREE_CX_APP][0]
    keys = extract_keys(payload)

    assert "mswin-dc01.attackrange.local" in keys.hosts
    assert "mswin-dc01" in keys.hosts
    alias = next(k for k in keys.keys if k.value == "mswin-dc01")
    assert alias.alias is True


def test_process_command_line_does_not_pollute_process_names(by_rule):
    payload = by_rule[THREE_CX_APP][0]
    keys = extract_keys(payload)

    assert "3cxdesktopapp.exe" in keys.process_names
    assert all(" " not in name for name in keys.process_names)


def test_whole_corpus_produces_no_system_process_keys(corpus):
    system = {p.removesuffix(".exe") for p in SYSTEM_PROCESSES}
    for payload in corpus:
        keys = extract_keys(payload)
        for key in keys.keys:
            assert key.value not in system, f"{key.kind}={key.value} leaked as an entity"
            assert key.value not in {"attacker", "null", "unknown", "-"}


def test_empty_payload_is_safe():
    keys = extract_keys(None)
    assert keys.keys == []
    assert keys.time_quality == "alert_time_fallback"
    assert keys.normalizer_version == NORMALIZER_VERSION


def test_normalizer_version_is_stamped(corpus):
    keys = extract_keys(corpus[0], "9.9.9")
    assert keys.normalizer_version == "9.9.9"


# ── Indexer host vs event host (doc §1, §3.2 rule 2) ────────────────────────


_SPLUNK_MARKERS = {
    "alert_time": "2026-11-08T21:16:30+0330",
    "date_context": {"wday": "Sunday", "hour": 19},
    "time_window": {"earliest": None, "latest": None},
    "alert_fields": {},
    "rule_name": "ESCU - Test Rule",
    "event_time": "2026-11-08T19:53:51+0330",
    "event_time_source": "first_event",
}


def test_splunk_indexer_host_is_never_an_entity():
    """``host`` on a notable is the index/search head — not the victim."""
    payload = {
        **_SPLUNK_MARKERS,
        "entity": "IDX-SH-01",
        "entity_type": "system",
        "alert_fields": {"host": "IDX-SH-01", "dest": "win-dc-01.corp.local"},
    }
    keys = extract_keys(payload)

    assert "idx-sh-01" not in keys.hosts
    assert "win-dc-01.corp.local" in keys.hosts
    assert keys.primary_host == "win-dc-01"
    reasons = {f["reason"] for f in keys.filtered}
    assert "splunk_indexer_host" in reasons


def test_non_splunk_payload_keeps_host_as_the_event_host():
    """A non-Splunk source may legitimately report the victim in ``host``."""
    payload = {
        "rule_name": "Custom EDR rule",
        "alert_fields": {"host": "web-01", "user": "alice"},
    }
    keys = extract_keys(payload)

    assert "web-01" in keys.hosts
    assert keys.primary_host == "web-01"


def test_entity_equal_to_indexer_host_is_dropped():
    """The connector's ``entity`` fallback can leak the indexer host."""
    payload = {
        **_SPLUNK_MARKERS,
        "entity": "splunk-idx-9",
        "entity_type": "host",
        "alert_fields": {"host": "splunk-idx-9"},
    }
    keys = extract_keys(payload)

    assert keys.hosts == []
    assert any(f["reason"] == "splunk_indexer_host" for f in keys.filtered)


def test_meta_indexer_host_is_dropped_even_without_alert_fields_host():
    """The connector records the indexer in ``_meta``; trust it."""
    payload = {
        **_SPLUNK_MARKERS,
        "entity": "Splunk-SH-2",
        "entity_type": "system",
        "alert_fields": {"dest": "win-dc-02.corp.local"},
        "_meta": {"indexer_host": "Splunk-SH-2"},
    }
    keys = extract_keys(payload)

    assert "splunk-sh-2" not in keys.hosts
    assert keys.primary_host == "win-dc-02"


def test_primary_host_prefers_event_field_over_generic_hosts():
    payload = {
        **_SPLUNK_MARKERS,
        "alert_fields": {"sourcetype": "WinEventLog", "workstation": "WS-77", "dest": "DC-01.corp.local"},
    }
    keys = extract_keys(payload)

    assert keys.primary_host == "dc-01"
    assert "ws-77" in keys.hosts


def test_src_is_shape_decided_not_name_decided():
    """``src`` is an IP in one analytic and a host in another."""
    ip_payload = {**_SPLUNK_MARKERS, "alert_fields": {"src": "10.0.1.15"}}
    host_payload = {**_SPLUNK_MARKERS, "alert_fields": {"src": "win-dc-8537412.attackrange.local"}}

    ip_keys = extract_keys(ip_payload)
    host_keys = extract_keys(host_payload)

    assert ip_keys.ips == ["10.0.1.15"]
    assert ip_keys.hosts == []
    assert "win-dc-8537412.attackrange.local" in host_keys.hosts
    assert host_keys.ips == []


def _pairs(keys):
    for key in keys.keys:
        yield key.kind, key.value
