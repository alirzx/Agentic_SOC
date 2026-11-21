from app.services.rule_registry import RuleIdentityMap, resolve_rule_identity_map


def test_exact_tenant_wins_over_exact_global_and_patterns():
    tenant_exact = RuleIdentityMap(rule_name="Splunk: Failed Logon", tenant_id="tenant-a", host_fields=["dest"])
    global_exact = RuleIdentityMap(rule_name="Splunk: Failed Logon", tenant_id=None, host_fields=["Computer"])
    tenant_pattern = RuleIdentityMap(rule_name="Splunk:*", tenant_id="tenant-a", rule_name_pattern="Splunk:*", host_fields=["dvc"])
    result = resolve_rule_identity_map(
        "tenant-a",
        "Splunk: Failed Logon",
        [tenant_exact, global_exact, tenant_pattern],
    )
    assert result.matched_source == "exact"
    assert result.map is tenant_exact


def test_exact_global_precedes_patterns():
    global_exact = RuleIdentityMap(rule_name="Splunk: Failed Logon", tenant_id=None, host_fields=["dest"])
    tenant_pattern = RuleIdentityMap(rule_name="Splunk:*", tenant_id="tenant-a", rule_name_pattern="Splunk:*", host_fields=["dvc"])
    result = resolve_rule_identity_map(
        "tenant-a",
        "Splunk: Failed Logon",
        [tenant_pattern, global_exact],
    )
    assert result.matched_source == "exact"
    assert result.map is global_exact


def test_tenant_pattern_precedes_global_pattern():
    tenant_pattern = RuleIdentityMap(rule_name="Splunk:*", tenant_id="tenant-a", rule_name_pattern="Splunk:*", host_fields=["dest"])
    global_pattern = RuleIdentityMap(rule_name="Splunk:*", tenant_id=None, rule_name_pattern="Splunk:*", host_fields=["Computer"])
    result = resolve_rule_identity_map(
        "tenant-a",
        "Splunk: Failed Logon",
        [global_pattern, tenant_pattern],
    )
    assert result.matched_source == "tenant_pattern"
    assert result.map is tenant_pattern


def test_missing_rule_name_returns_missing():
    result = resolve_rule_identity_map("tenant-a", "", [])
    assert result.matched_source == "missing"
    assert result.map is None


def test_unmatched_rule_uses_generic_fallback_marker():
    result = resolve_rule_identity_map("tenant-a", "Some Unknown Rule", [])
    assert result.matched_source == "generic_fallback"
    assert result.map is None
