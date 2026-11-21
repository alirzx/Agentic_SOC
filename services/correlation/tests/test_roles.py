"""Role assignment and the C2 merge veto (doc §5.2)."""

from __future__ import annotations

import pytest
from app.normalizer.roles import assign_role, roles_conflict


@pytest.mark.parametrize(
    ("rule_name", "expected"),
    [
        ("ESCU - Windows Possible Credential Dumping - Rule", "credential_access:lsass"),
        ("ESCU - Access LSASS Memory for Dump Creation - Rule", "credential_access:lsass"),
        ("ESCU - Ntdsutil Export NTDS - Rule", "credential_access:ntds"),
        ("ESCU - Detect Password Spray Attempts - Rule", "credential_access:spray"),
        ("ESCU - 3CX Supply Chain Attack Network Indicators - Rule", "supply_chain:3cx_dns"),
        ("ESCU - Hunting 3CXDesktopApp Software - Rule", "supply_chain:3cx_app"),
        ("ESCU - Executable File Written in Administrative SMB Share - Rule", "lateral_movement:smb_share"),
        ("ESCU - DNS Query Length With High Standard Deviation - Rule", "exfiltration:dns"),
        ("ESCU - Windows Privilege Escalation Attempt Via MSI Rollback - Rule", "privilege_escalation:msi"),
        ("ESCU - PowerShell 4104 Hunting - Rule", "execution:powershell"),
        ("Risk - 24 Hour Risk Threshold Exceeded - Rule", "aggregation:risk"),
    ],
)
def test_builtin_rule_roles(rule_name, expected):
    assert assign_role(rule_name=rule_name) == expected


def test_c2_tool_decides_the_role():
    role = assign_role(
        rule_name="ESCU - HTTP C2 Framework User Agent - Rule",
        alert_fields={"tool": "Havoc C2"},
    )
    assert role == "c2:havoc c2"


def test_unmatched_rule_falls_back_to_technique():
    assert assign_role(rule_name="Custom rule", techniques=["T1021.002"]) == "lateral_movement:smb_share"


def test_operator_override_wins():
    role = assign_role(
        rule_name="ESCU - Windows Possible Credential Dumping - Rule",
        rule_overrides={"ESCU - Windows Possible Credential Dumping - Rule": "impact:ransomware"},
    )
    assert role == "impact:ransomware"


def test_distinct_c2_frameworks_conflict():
    assert roles_conflict("c2:sliver", "c2:cobalt strike") is True


def test_same_framework_does_not_conflict():
    assert roles_conflict("c2:sliver", "c2:sliver") is False


def test_unrelated_roles_never_conflict():
    assert roles_conflict("credential_access:lsass", "lateral_movement:smb_share") is False
    assert roles_conflict(None, "c2:sliver") is False
