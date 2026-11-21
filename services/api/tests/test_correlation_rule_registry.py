import uuid
from pathlib import Path

from app.models.correlation_rule_identity import CorrelationRuleIdentityMap
from app.services.correlation_rule_registry import (
    normalize_field_kind_overrides,
    normalize_field_names,
    resolve_rule_identity_map,
)


def _map(*, tenant_id, rule_name, pattern=None):
    return CorrelationRuleIdentityMap(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        rule_name=rule_name,
        rule_name_pattern=pattern,
        is_active=True,
        host_fields=["dest"],
        source="test",
    )


def test_exact_tenant_precedes_every_global_or_pattern_row():
    tenant_id = uuid.uuid4()
    tenant_exact = _map(tenant_id=tenant_id, rule_name="Splunk: Failed Logon")
    global_exact = _map(tenant_id=None, rule_name="Splunk: Failed Logon")
    tenant_pattern = _map(tenant_id=tenant_id, rule_name="Splunk:*", pattern="Splunk:*")

    source, mapped = resolve_rule_identity_map(
        tenant_id,
        "Splunk: Failed Logon",
        [tenant_pattern, global_exact, tenant_exact],
    )

    assert source == "exact"
    assert mapped is tenant_exact


def test_exact_global_precedes_patterns():
    tenant_id = uuid.uuid4()
    global_exact = _map(tenant_id=None, rule_name="Splunk: Failed Logon")
    tenant_pattern = _map(tenant_id=tenant_id, rule_name="Splunk:*", pattern="Splunk:*")

    source, mapped = resolve_rule_identity_map(
        tenant_id,
        "Splunk: Failed Logon",
        [tenant_pattern, global_exact],
    )

    assert source == "exact"
    assert mapped is global_exact


def test_tenant_pattern_precedes_global_pattern():
    tenant_id = uuid.uuid4()
    tenant_pattern = _map(tenant_id=tenant_id, rule_name="Splunk:*", pattern="Splunk:*")
    global_pattern = _map(tenant_id=None, rule_name="ESCU -*", pattern="ESCU -*")

    source, mapped = resolve_rule_identity_map(
        tenant_id,
        "Splunk: Failed Logon",
        [global_pattern, tenant_pattern],
    )

    assert source == "tenant_pattern"
    assert mapped is tenant_pattern


def test_other_tenant_exact_row_never_resolves():
    tenant_id = uuid.uuid4()
    other_tenant_id = uuid.uuid4()
    other = _map(tenant_id=other_tenant_id, rule_name="Splunk: Failed Logon")

    source, mapped = resolve_rule_identity_map(
        tenant_id,
        "Splunk: Failed Logon",
        [other],
    )

    assert source == "generic_fallback"
    assert mapped is None


def test_missing_and_unknown_rule_sources():
    tenant_id = uuid.uuid4()

    assert resolve_rule_identity_map(tenant_id, "", []) == ("missing", None)
    assert resolve_rule_identity_map(tenant_id, "Unknown Rule", []) == ("generic_fallback", None)


def test_field_normalization_deduplicates_and_filters_invalid_kinds():
    assert normalize_field_names([" dest ", "Computer", "dest", ""]) == ["dest", "Computer"]
    assert normalize_field_kind_overrides({
        "dest": "host",
        "src_ip": "IP",
        "bad": "password",
        " ": "user",
    }) == {
        "dest": "host",
        "src_ip": "ip",
    }


def test_migrations_define_registry_audit_rls_and_seed_maps():
    api_root = Path(__file__).resolve().parents[1]
    map_sql = (api_root / "migrations" / "090_correlation_rule_identity_maps.sql").read_text(encoding="utf-8")
    audit_sql = (api_root / "migrations" / "091_correlation_rule_resolution_audits.sql").read_text(encoding="utf-8")

    assert "CREATE TABLE IF NOT EXISTS correlation_rule_identity_maps" in map_sql
    assert "CREATE TABLE IF NOT EXISTS correlation_rule_resolution_audits" in audit_sql
    assert "ALTER TABLE correlation_rule_identity_maps FORCE ROW LEVEL SECURITY" in map_sql
    assert "ALTER TABLE correlation_rule_resolution_audits FORCE ROW LEVEL SECURITY" in audit_sql
    assert "ESCU - Windows Mimikatz Crypto Export File Extensions - Rule" in map_sql
    assert "ESCU - HTTP C2 Framework User Agent - Rule" in map_sql
    assert "ESCU - *" in map_sql
