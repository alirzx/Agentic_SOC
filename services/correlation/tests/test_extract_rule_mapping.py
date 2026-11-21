from app.normalizer.extract_keys import extract_keys


def test_registry_map_limits_fields_and_excludes_indexer():
    payload = {
        "rule_name": "Splunk: Failed Logon",
        "severity": "high",
        "alert_time": "2026-11-21T10:00:00Z",
        "_meta": {"indexer_host": "splunk-indexer"},
        "alert_fields": {
            "dest": "WKSTN-100",
            "src_ip": "198.51.100.25",
            "src_user": "alice",
            "host": "splunk-indexer",
        },
    }

    keys = extract_keys(
        payload,
        identity_map={
            "host_fields": ["dest"],
            "user_fields": ["src_user"],
            "ip_fields": ["src_ip"],
            "excluded_fields": ["host"],
        },
    )

    assert "wkstn-100" in keys.hosts
    assert "198.51.100.25" in keys.ips
    assert "alice" in keys.users
    assert "splunk-indexer" not in keys.hosts


def test_registry_map_marks_missing_fields():
    payload = {
        "rule_name": "Splunk: Privileged Process",
        "alert_fields": {"Computer": "DC-01"},
    }

    keys = extract_keys(
        payload,
        identity_map={
            "host_fields": ["dest", "Computer"],
            "user_fields": ["Caller_User_Name"],
        },
    )

    assert "dc-01" in keys.hosts
    assert "dest" in keys.missing_fields
    assert "caller_user_name" in keys.missing_fields
