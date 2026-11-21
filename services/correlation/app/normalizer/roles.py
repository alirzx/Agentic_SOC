"""Role assignment for correlation (doc §5.2).

A *role* answers "what job is this alert doing in the intrusion?" — credential
access, lateral movement, C2, exfiltration. Roles are used for exactly two
things, and deliberately nothing else:

1. **Titles / narrative** for a case (``credential-access + lateral-movement``).
2. **A merge veto.** Two alerts that belong to *different* C2 frameworks must
   never merge, even when they share entities and would otherwise score above
   θ. Mixing Sliver and Cobalt Strike beacons on one host into a single case is
   the classic false-positive this guard exists to prevent.

Role assignment is data-driven: a small built-in map covers the ~50 rules that
dominate real splash pages, and operators can override or extend it per tenant
through the ``correlation_rule_roles`` table (loaded by the engine and passed in
here as ``overrides``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

#: ``(regex on rule name, role)`` — first match wins. Ordered: the most
#: specific rules first so "3CX Supply Chain … Network Indicators" never falls
#: through to the generic ``supply_chain`` bucket.
_BUILTIN_RULES: tuple[tuple[str, str], ...] = (
    (r"lsass|credential dump", "credential_access:lsass"),
    (r"ntdsutil|ntds", "credential_access:ntds"),
    (r"password spray", "credential_access:spray"),
    (r"kerberoast|as-rep|dcsync", "credential_access:kerberos"),
    (r"3cx.*network indicators|3cx supply chain", "supply_chain:3cx_dns"),
    (r"3cxdesktopapp|hunting 3cx", "supply_chain:3cx_app"),
    (r"smb share", "lateral_movement:smb_share"),
    (r"psexec|remote service", "lateral_movement:remote_service"),
    (r"c2 framework|user agent", "command_and_control:http"),
    (r"dns query length", "exfiltration:dns"),
    (r"msi rollback", "privilege_escalation:msi"),
    (r"powershell 4104|script block", "execution:powershell"),
    (r"risk threshold|risk - ", "aggregation:risk"),
)

#: Techniques are a fallback when the rule name is unfamiliar (custom rules,
#: Sigma imports). More specific sub-techniques first.
_TECHNIQUE_ROLES: tuple[tuple[str, str], ...] = (
    ("T1003.001", "credential_access:lsass"),
    ("T1003.003", "credential_access:ntds"),
    ("T1110", "credential_access:spray"),
    ("T1021.002", "lateral_movement:smb_share"),
    ("T1071.001", "command_and_control:http"),
    ("T1048.003", "exfiltration:dns"),
    ("T1068", "privilege_escalation:msi"),
    ("T1059.001", "execution:powershell"),
    ("T1195.002", "supply_chain:software"),
)

_C2_TOOL_RE = re.compile(r"cobalt|sliver|meterpreter|beacon|empire|mythic|havoc|brute ?ratel|poshc2", re.IGNORECASE)


def assign_role(
    *,
    rule_name: str | None,
    alert_fields: Mapping[str, Any] | None = None,
    techniques: list[str] | None = None,
    role_overrides: Mapping[str, str] | None = None,
    rule_overrides: Mapping[str, str] | None = None,
) -> str:
    """Return a stable ``family:detail`` role for one alert.

    Precedence: explicit rule override → built-in rule pattern → rule override
    is *not* consulted twice → C2 tool hint → technique → ``general``.
    """
    name = (rule_name or "").strip()
    lowered = name.lower()

    # 1. Operator override keyed by exact rule name (per-tenant table).
    if rule_overrides and name in rule_overrides:
        return rule_overrides[name]

    # 2. C2 frameworks are identified by the tool they name, not by the rule.
    #    This is what makes two different frameworks mutually exclusive.
    tool = str((alert_fields or {}).get("tool") or "")
    if tool and _C2_TOOL_RE.search(tool):
        return f"c2:{tool.strip().lower()}"
    if _C2_TOOL_RE.search(name):
        return f"c2:{_C2_TOOL_RE.search(name).group(0).lower()}"  # type: ignore[union-attr]

    # 3. Built-in rule-name patterns.
    for pattern, role in _BUILTIN_RULES:
        if re.search(pattern, lowered):
            return role

    # 4. MITRE technique fallback.
    for technique in techniques or []:
        for prefix, role in _TECHNIQUE_ROLES:
            if str(technique).upper().startswith(prefix):
                return role

    # 5. Legacy generic ``role_overrides`` keyed by role family.
    family = lowered.split(" - ")[0] if " - " in lowered else ""
    if role_overrides and family in role_overrides:
        return role_overrides[family]

    return "general:intrusion"


def roles_conflict(role_a: str | None, role_b: str | None) -> bool:
    """True when two roles must never share a case.

    Only distinct C2 frameworks are mutually exclusive today. The function is
    intentionally narrow: an over-eager veto silently stops cases from forming.
    """
    if not role_a or not role_b:
        return False
    if role_a.startswith("c2:") and role_b.startswith("c2:"):
        return role_a != role_b
    return False


__all__ = ["assign_role", "roles_conflict"]
