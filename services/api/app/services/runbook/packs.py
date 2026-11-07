"""Importable automation-rule packs.

A pack is a checked-in, reviewable bundle of automation rules for one detection
source. Rules in a pack target detections *by name*: the field
``rule_name`` carries a Splunk notable's ``search_name``, which for
Splunk Security Content (ESCU) is the detection's own ``name:`` value. That
makes ``{"field": "rule_name", "op": "in", "value": [...]}`` an exact,
case-insensitive match against the correlation search that produced the alert —
no per-tenant mapping table and no free-text guessing.

Why packs instead of seeding
---------------------------
Nothing is written to a tenant's rules until an operator asks for it. That is
true for both packs shipped here:

* ``windows-splunk`` — keyed to named detection sources. A tenant without that
telemetry would only gain rules that can never match, which reads as
  "configured" while doing nothing.
* ``core-defaults`` — the vendor-neutral rules that used to be inserted for every
  tenant the moment the rules page was opened (see
  :mod:`app.services.runbook.default_rules`). Same idea: a rule an operator did
  not choose has no owner, and there was no way to tell an intended automation
  from an inherited one.

Import is explicit (``POST /runbook/automation-rules/packs/{pack_id}/import``),
can take a subset of the pack, and is idempotent by rule name, so re-importing
after a pack grows adds only the rules that are missing.

Posture
-------
Every ``windows-splunk`` rule ships ``dry_run=True``: importing installs
*decisions*, not execution. Each match writes a ledger line and, for
containment actions, an approval task. An operator raises autonomy deliberately
per rule after seeing what it matches (``POST /runbook/automation-rules/{id}/test``
previews it against real alerts first).

The ``core-defaults`` rules keep the autonomy and ``dry_run`` values they were
seeded with, because changing a rule's posture while moving it into a pack would
be a silent behaviour change. The import dialog shows each rule's autonomy and
dry-run state so the choice is informed.

Coverage claims
---------------
``source`` names the upstream corpus the detection names were taken from. The
counts here are detections this pack has an explicit rule for — not a claim that
the corpus is fully covered. Detection names that upstream renames will stop
matching: that is why every rule carries ``docs_ref`` and the pack reports its
covered names, so a drifting name is visible instead of silently inert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from app.services.runbook.default_rules import CORE_DEFAULT_RULES

__all__ = [
    "PACKS",
    "PackRule",
    "RawPackRule",
    "RulePack",
    "get_pack",
    "list_packs",
    "pack_rule_payloads",
    "covered_detection_names",
]

#: Upstream corpus the detection names come from.
ESCU_SOURCE = "Splunk Security Content (ESCU) — detections/endpoint"

#: Default owner for detection-driven rules; groups them in the UI filters.
_OWNER = "detection-engineering"


@dataclass(frozen=True)
class PackRule:
    """One rule inside a pack, in the shape the rules API stores.

    ``detections`` is the ESCU ``name:`` list the rule matches. It becomes a
    single ``rule_name in [...]`` condition — one condition rather than one
    condition per name, because conditions are ANDed and N separate ``eq``
    conditions could never match.
    """

    name: str
    summary: str
    detections: tuple[str, ...]
    action_slug: str
    action_params: dict[str, Any] = field(default_factory=dict)
    autonomy_level: str = "L2"
    dry_run: bool = True
    priority: int = 200
    trigger_type: str = "alert.created"
    owner_team: str = _OWNER

    @property
    def conditions(self) -> list[dict[str, Any]]:
        return [{"field": "rule_name", "op": "in", "value": list(self.detections)}]

    def payload(self) -> dict[str, Any]:
        """The row this rule would be inserted as."""
        return {
            "name": self.name,
            "description": self.summary,
            "trigger_type": self.trigger_type,
            "conditions": self.conditions,
            "action_slug": self.action_slug,
            "action_params": dict(self.action_params),
            "autonomy_level": self.autonomy_level,
            "dry_run": self.dry_run,
            "enabled": True,
            "priority": self.priority,
            "subject_type": "alert",
            # No docs link: the console page is one click away in the app, and
            # the URL printed here previously pointed at an anchor that does not
            # exist. A dead link on a governed action is worse than no link.
            "docs_ref": None,
            "owner_team": self.owner_team,
        }


@dataclass(frozen=True)
class RawPackRule:
    """A pack rule whose row is written out in full.

    The vendor-neutral defaults key on generic alert shape (severity, category,
    title), not on a named upstream detection, so they cannot be generated from
    a detection list the way :class:`PackRule` is. The row is carried verbatim
    (see :mod:`app.services.runbook.default_rules`) so a pack never quietly
    changes what an inherited rule does.
    """

    row: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.row["name"])

    @property
    def trigger_type(self) -> str:
        return str(self.row.get("trigger_type") or "alert.created")

    @property
    def conditions(self) -> list[dict[str, Any]]:
        """Carried verbatim, like the rest of the row."""
        return list(self.row.get("conditions") or [])

    @property
    def detections(self) -> tuple[str, ...]:
        """Empty: these rules key on alert shape, not a named detection."""
        return ()

    @property
    def action_slug(self) -> str:
        return str(self.row["action_slug"])

    @property
    def autonomy_level(self) -> str:
        return str(self.row.get("autonomy_level") or "L2")

    @property
    def dry_run(self) -> bool:
        return bool(self.row.get("dry_run", True))

    @property
    def priority(self) -> int:
        return int(self.row.get("priority") or 200)

    def payload(self) -> dict[str, Any]:
        """The row this rule would be inserted as."""
        return dict(self.row)


@dataclass(frozen=True)
class RulePack:
    id: str
    label: str
    description: str
    source: str
    rules: tuple[PackRule | RawPackRule, ...]

    @property
    def covered_detections(self) -> tuple[str, ...]:
        """Every upstream detection name this pack has a rule for, deduped.

        Zero for packs that are not keyed to an upstream corpus.
        """
        seen: dict[str, None] = {}
        for rule in self.rules:
            for detection in getattr(rule, "detections", ()):
                seen.setdefault(detection, None)
        return tuple(seen)

    def payloads(self) -> list[dict[str, Any]]:
        return [rule.payload() for rule in self.rules]

    @property
    def installed_names(self) -> tuple[str, ...]:
        """Every rule name in this pack, in order."""
        return tuple(rule.name for rule in self.rules)


def _windows_rule(
    name: str,
    summary: str,
    detections: tuple[str, ...],
    action_slug: str,
    *,
    priority: int,
    autonomy_level: str = "L2",
    action_params: dict[str, Any] | None = None,
) -> PackRule:
    return PackRule(
        name=name,
        summary=summary,
        detections=detections,
        action_slug=action_slug,
        action_params=action_params or {},
        autonomy_level=autonomy_level,
        priority=priority,
    )


_WINDOWS_RULES: tuple[PackRule, ...] = (
    # ── Credential access (T1003) ────────────────────────────────────────────
    _windows_rule(
        "Splunk Windows · ransomware spray → isolate host",
        "Fires when ESCU reports ransomware artefacts (note files, test files, "
        "encryption markers) on a Windows host. Containment is prepared, not "
        "executed, until the tenant raises autonomy for isolate_host.",
        (
            "Ransomware Notes bulk creation",
            "Ryuk Test Files Detected",
            "Samsam Test File Write",
            "Windows .Key File Creation in Root Directory",
        ),
        "isolate_host",
        priority=120,
        autonomy_level="L3",
        action_params={"target_type": "host", "reason": "windows-ransomware-artefacts"},
    ),
    _windows_rule(
        "Splunk Windows · LSASS memory dump → isolate host",
        "Fires on ESCU detections for LSASS memory access, dump creation or "
        "Mimikatz execution — active credential theft on the endpoint.",
        (
            "Access LSASS Memory for Dump Creation",
            "Dump LSASS via procdump",
            "Dump LSASS via comsvcs DLL",
            "Create Remote Thread into LSASS",
            "Windows Mimikatz Binary Execution",
            "Windows Credential Dumping LSASS Memory Createdump",
        ),
        "isolate_host",
        priority=130,
        autonomy_level="L3",
        action_params={"target_type": "host", "reason": "windows-lsass-credential-theft"},
    ),
    _windows_rule(
        "Splunk Windows · Mimikatz in script block → case",
        "Script-block detection of Mimikatz during a PowerShell session; opens a "
        "case because the host attribution needs analyst review.",
        ("Detect Mimikatz With PowerShell Script Block Logging",),
        "create_case",
        priority=140,
        action_params={"template": "windows-credential-theft"},
    ),
    _windows_rule(
        "Splunk Windows · NTDS / registry hive dump → case",
        "Domain or local credential database extraction (NTDS, SAM, SECURITY "
        "hive). High impact, but the responder needs host and account scope first.",
        (
            "Ntdsutil Export NTDS",
            "Windows Sensitive Registry Hive Dump Via CommandLine",
            "SAM Database File Access Attempt",
            "Esentutl SAM Copy",
        ),
        "create_case",
        priority=150,
        action_params={"template": "windows-credential-theft"},
    ),
    _windows_rule(
        "Splunk Windows · shadow-copy credential theft → case",
        "Credentials copied out of a volume shadow copy (a technique that "
        "bypasses file locks on the SAM/NTDS databases).",
        (
            "Credential Dumping via Copy Command from Shadow Copy",
            "Credential Dumping via Symlink to Shadow Copy",
        ),
        "create_case",
        priority=160,
        action_params={"template": "windows-credential-theft"},
    ),
    _windows_rule(
        "Splunk Windows · WDigest cleartext logon → case",
        "WDigest UseLogonCredential forced on, so Windows keeps plaintext "
        "credentials in LSASS memory for later theft.",
        ("Enable WDigest UseLogonCredential Registry",),
        "create_case",
        priority=170,
        action_params={"template": "windows-credential-theft"},
    ),
    # ── Kerberos (T1558) ─────────────────────────────────────────────────────
    _windows_rule(
        "Splunk Windows · Kerberoasting → case",
        "Service-ticket requests consistent with Kerberoasting or a bulk ticket "
        "harvest; needs an identity-focused investigation.",
        (
            "Kerberoasting spn request with RC4 encryption",
            "Unusual Number of Kerberos Service Tickets Requested",
            "Windows PowerView Kerberos Service Ticket Request",
        ),
        "create_case",
        priority=180,
        action_params={"template": "identity-attack"},
    ),
    _windows_rule(
        "Splunk Windows · Kerberos tooling → tag",
        "Named offensive tooling (Rubeus, NetExec, setspn enumeration) seen on a "
        "host. Tagged so the hunting queue can group them across the estate.",
        (
            "Rubeus Command Line Parameters",
            "Windows Process With NetExec Command Line Parameters",
            "ServicePrincipalNames Discovery with SetSPN",
        ),
        "add_alert_tag",
        priority=190,
        autonomy_level="L1",
        action_params={"tag": "kerberos-tooling"},
    ),
    _windows_rule(
        "Splunk Windows · Kerberos pre-auth disabled → case",
        "An account with Kerberos pre-authentication disabled is a standing "
        "AS-REP roasting target; change control has to confirm it is intentional.",
        (
            "Kerberos Pre-Authentication Flag Disabled in UserAccountControl",
            "Kerberos Pre-Authentication Flag Disabled with PowerShell",
        ),
        "create_case",
        priority=200,
        action_params={"template": "identity-attack"},
    ),
    # ── Impact and recovery inhibition (T1486, T1490, T1489) ─────────────────
    _windows_rule(
        "Splunk Windows · shadow-copy deletion → case",
        "Shadow copies removed, the usual precursor to ransomware encryption and "
        "the reason recovery options disappear.",
        (
            "Deleting Shadow Copies",
            "Delete ShadowCopy With PowerShell",
            "Windows WMIC Shadowcopy Delete",
        ),
        "create_case",
        priority=210,
        action_params={"template": "ransomware-precursor"},
    ),
    _windows_rule(
        "Splunk Windows · recovery inhibition → case",
        "Boot recovery, System Restore or backup catalog tampering — impact "
        "activity that removes the ability to restore a host.",
        (
            "BCDEdit Failure Recovery Modification",
            "Prevent Automatic Repair Mode using Bcdedit",
            "WBAdmin Delete System Backups",
            "Disabling SystemRestore In Registry",
        ),
        "create_case",
        priority=220,
        action_params={"template": "ransomware-precursor"},
    ),
    _windows_rule(
        "Splunk Windows · security services stopped → case",
        "Defender, SAM or other security services stopped on an endpoint.",
        (
            "Windows Security And Backup Services Stop",
            "Windows Security Account Manager Stopped",
        ),
        "create_case",
        priority=230,
        action_params={"template": "defense-evasion"},
    ),
    _windows_rule(
        "Splunk Windows · service-stop attempts → tag",
        "Repeated attempts to stop or disable services. Tagged rather than cased: "
        "the volume is high and most instances are patch or admin work.",
        (
            "Excessive Attempt To Disable Services",
            "Windows Excessive Service Stop Attempt",
            "Windows Service Stop Attempt",
        ),
        "add_alert_tag",
        priority=240,
        autonomy_level="L1",
        action_params={"tag": "service-tampering"},
    ),
    # ── Defense evasion (T1562, T1112, T1070) ────────────────────────────────
    _windows_rule(
        "Splunk Windows · Defender tampering → case",
        "ASR rules, tamper protection or Defender autostart changed through the "
        "registry — the host is being taken off the defence grid.",
        (
            "Windows Defender ASR Rule Disabled",
            "Windows Defender ASR Registry Modification",
            "Windows Impair Defenses Disable AV AutoStart via Registry",
            "Windows Modify Registry Tamper Protection",
        ),
        "create_case",
        priority=250,
        action_params={"template": "defense-evasion"},
    ),
    _windows_rule(
        "Splunk Windows · log tampering → case",
        "Security logging suppressed or evidence removed (log service registry, "
        "USN journal, shell history).",
        (
            "Disable Security Logs Using MiniNt Registry",
            "USN Journal Deletion",
            "Windows Powershell History File Deletion",
        ),
        "create_case",
        priority=260,
        action_params={"template": "defense-evasion"},
    ),
    _windows_rule(
        "Splunk Windows · AMSI bypass → case",
        "AMSI unloaded in-process through reflection, which blinds script "
        "inspection for every later PowerShell call on the host.",
        ("Unloading AMSI via Reflection",),
        "create_case",
        priority=270,
        action_params={"template": "defense-evasion"},
    ),
    # ── Signed-binary proxy execution (T1218) ────────────────────────────────
    _windows_rule(
        "Splunk Windows · mshta proxy execution → tag",
        "HTA execution through mshta, including renamed and URL-driven variants.",
        (
            "Detect mshta inline hta execution",
            "Detect MSHTA Url in Command Line",
            "Detect mshta renamed",
            "Suspicious mshta child process",
        ),
        "add_alert_tag",
        priority=280,
        autonomy_level="L1",
        action_params={"tag": "lolbin-proxy-execution"},
    ),
    _windows_rule(
        "Splunk Windows · regsvr32 app-control bypass → tag",
        "Regsvr32 used for scriptlet or remote DLL execution (app-control "
        "bypass), including renamed binaries.",
        (
            "Detect Regsvr32 Application Control Bypass",
            "Suspicious Regsvr32 Register Suspicious Path",
            "Windows Regsvr32 Renamed Binary",
        ),
        "add_alert_tag",
        priority=290,
        autonomy_level="L1",
        action_params={"tag": "lolbin-proxy-execution"},
    ),
    _windows_rule(
        "Splunk Windows · rundll32 abuse → tag",
        "Rundll32 exporting DllRegisterServer, running argument-free, or loading "
        "from a temp path or non-standard extension.",
        (
            "Suspicious Rundll32 dllregisterserver",
            "Suspicious Rundll32 no Command Line Arguments",
            "Windows Rundll32 Load DLL in Temp Dir",
            "Windows Rundll32 with Non-Standard File Extension",
        ),
        "add_alert_tag",
        priority=300,
        autonomy_level="L1",
        action_params={"tag": "lolbin-proxy-execution"},
    ),
    _windows_rule(
        "Splunk Windows · InstallUtil proxy execution → tag",
        "InstallUtil running outside its install path, reaching the network, or "
        "uninstalling — the classic .NET proxy-execution shape.",
        (
            "Windows InstallUtil in Non Standard Path",
            "Windows InstallUtil Remote Network Connection",
            "Windows InstallUtil Uninstall Option",
        ),
        "add_alert_tag",
        priority=310,
        autonomy_level="L1",
        action_params={"tag": "lolbin-proxy-execution"},
    ),
    _windows_rule(
        "Splunk Windows · renamed or relocated LOLBAS → tag",
        "A known trusted binary executed under a different name or from a path "
        "it never runs from legitimately.",
        (
            "Windows LOLBAS Executed As Renamed File",
            "Windows LOLBAS Executed Outside Expected Path",
        ),
        "add_alert_tag",
        priority=320,
        autonomy_level="L1",
        action_params={"tag": "lolbin-renamed"},
    ),
    # ── Persistence (T1053, T1543, T1546, T1547) ─────────────────────────────
    _windows_rule(
        "Splunk Windows · scheduled task spawning a shell → case",
        "A scheduled task created to launch a shell or containing a suspicious "
        "command, including XML-imported tasks.",
        (
            "WinEvent Scheduled Task Created to Spawn Shell",
            "Windows Scheduled Task Created Via XML",
            "Windows Scheduled Task with Suspicious Command",
        ),
        "create_case",
        priority=330,
        action_params={"template": "persistence"},
    ),
    _windows_rule(
        "Splunk Windows · short-lived scheduled task → tag",
        "A task that exists briefly or carries a generated name — a run-once "
        "execution pattern worth grouping with the rest of the estate.",
        (
            "Short Lived Scheduled Task",
            "Randomly Generated Scheduled Task Name",
        ),
        "add_alert_tag",
        priority=340,
        autonomy_level="L1",
        action_params={"tag": "scheduled-task-anomaly"},
    ),
    _windows_rule(
        "Splunk Windows · service created to run a payload → case",
        "New Windows service pointing at a suspicious path, a kernel-mode "
        "driver, or a known service-creation exploit (KrbRelayUp, Tscon).",
        (
            "Windows Service Created with Suspicious Service Path",
            "Windows Service Create Kernel Mode Driver",
            "Windows Service Create with Tscon",
            "Windows KrbRelayUp Service Creation",
        ),
        "create_case",
        priority=350,
        action_params={"template": "persistence"},
    ),
    _windows_rule(
        "Splunk Windows · WMI event subscription → case",
        "A permanent WMI event subscription (the fileless persistence primitive) "
        "created on a host.",
        (
            "WMI Permanent Event Subscription",
            "WMI Permanent Event Subscription - Sysmon",
            "Detect WMI Event Subscription Persistence",
            "Windows MOF Event Triggered Execution via WMI",
        ),
        "create_case",
        priority=360,
        action_params={"template": "persistence"},
    ),
    _windows_rule(
        "Splunk Windows · autostart registry persistence → tag",
        "Run-key, Startup-folder or Active Setup autostart entries.",
        (
            "Registry Keys Used For Persistence",
            "Windows Boot or Logon Autostart Execution In Startup Folder",
            "Active Setup Registry Autostart",
        ),
        "add_alert_tag",
        priority=370,
        autonomy_level="L1",
        action_params={"tag": "autostart-persistence"},
    ),
    _windows_rule(
        "Splunk Windows · vulnerable driver loaded → case",
        "A known vulnerable or attacker-supplied driver loaded into the kernel, "
        "which defeats user-mode protections on the host.",
        (
            "Windows Vulnerable Driver Loaded",
            "Windows Vulnerable Driver Installed",
        ),
        "create_case",
        priority=380,
        action_params={"template": "persistence"},
    ),
    # ── Lateral movement (T1021, T1047, T1569) ───────────────────────────────
    _windows_rule(
        "Splunk Windows · PsExec → tag",
        "PsExec executed locally or renamed. Tagged as tooling so a cluster of "
        "hits across hosts can be pivoted on.",
        (
            "Detect PsExec With accepteula Flag",
            "Detect Renamed PSExec",
        ),
        "add_alert_tag",
        priority=390,
        autonomy_level="L1",
        action_params={"tag": "lateral-movement-tooling"},
    ),
    _windows_rule(
        "Splunk Windows · Impacket / remote service → case",
        "Impacket command lines, remote service creation or remote WMI command "
        "execution — remote code execution across hosts.",
        (
            "Impacket Lateral Movement Commandline Parameters",
            "Windows Remote Create Service",
            "Windows Service Creation on Remote Endpoint",
            "Remote WMI Command Attempt",
        ),
        "create_case",
        priority=400,
        action_params={"template": "lateral-movement"},
    ),
    # ── Account manipulation and tool transfer ───────────────────────────────
    _windows_rule(
        "Splunk Windows · local admin account created → case",
        "A local administrator account created through net, PowerShell or the "
        "account-management API; change control has to confirm the owner.",
        (
            "Windows Create Local Administrator Account Via Net",
            "Detect New Local Admin account",
            "Windows Create Local Account",
        ),
        "create_case",
        priority=410,
        action_params={"template": "account-manipulation"},
    ),
    _windows_rule(
        "Splunk Windows · certutil / BITS download → tag",
        "LOLBAS download primitives (certutil, BITS, curl) fetching a remote "
        "payload onto a Windows host.",
        (
            "Windows File Download Via CertUtil",
            "BITSAdmin Download File",
            "PowerShell Start-BitsTransfer",
            "Windows Curl Download to Suspicious Path",
        ),
        "add_alert_tag",
        priority=420,
        autonomy_level="L1",
        action_params={"tag": "ingress-tool-transfer"},
    ),
)


_WINDOWS_SPLUNK_PACK = RulePack(
    id="windows-splunk",
    label="Windows · Splunk correlation rules",
    description=(
        "Governed responses for high-signal Windows detections from Splunk "
        "Security Content: credential access, Kerberos abuse, ransomware "
        "precursors, defence evasion, signed-binary proxy execution, "
        "persistence, lateral movement and tool transfer. Rules match the "
        "correlation search name in the alert's rule_name field."
    ),
    source=ESCU_SOURCE,
    rules=_WINDOWS_RULES,
)


#: The vendor-neutral rules that used to be auto-seeded into every tenant.
_CORE_DEFAULTS_PACK = RulePack(
    id="core-defaults",
    label="Core triage · vendor-neutral",
    description=(
        "General-purpose rules keyed on alert shape rather than a named detection: "
        "severity/confidence tagging, a case for critical and credential alerts, "
        "containment recommendations, and noise-suppression. These rules used to be "
        "inserted automatically; add the ones you actually want. Each row shows the "
        "autonomy and dry-run state it will be installed with."
    ),
    source="AiSOC built-in (no upstream corpus)",
    rules=tuple(RawPackRule(row) for row in CORE_DEFAULT_RULES),
)


#: Read-only registry of packs available for import, in the order the UI lists
#: them: the general set first, then source-specific packs.
PACKS: MappingProxyType[str, RulePack] = MappingProxyType(
    {
        _CORE_DEFAULTS_PACK.id: _CORE_DEFAULTS_PACK,
        _WINDOWS_SPLUNK_PACK.id: _WINDOWS_SPLUNK_PACK,
    }
)


def list_packs() -> list[RulePack]:
    """All packs, in registration order."""
    return list(PACKS.values())


def get_pack(pack_id: str) -> RulePack | None:
    """Return the pack with ``pack_id``, or ``None`` when unknown."""
    return PACKS.get((pack_id or "").strip())


def pack_rule_payloads(pack: RulePack) -> list[dict[str, Any]]:
    """Rows to insert for ``pack`` — the single shape the import endpoint uses."""
    return pack.payloads()


def covered_detection_names(pack: RulePack) -> tuple[str, ...]:
    """Upstream detection names ``pack`` has a rule for (deduped, ordered)."""
    return pack.covered_detections
