#!/usr/bin/env python3
"""Seed two multi-alert attack-campaign cases for an intro/demo meeting.

Runs against the live demo Postgres (default via DATABASE_URL or local compose).
Idempotent: deletes prior rows tagged tags.demo_seed = 'intro-meeting-2026-11'.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import asyncio

import asyncpg

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
SEED_TAG = "intro-meeting-2026-11"
NOW = datetime.now(timezone.utc)

# Stable IDs so re-runs replace the same demo objects.
CASE_A = uuid.UUID("a1111111-1111-4111-8111-111111111101")
CASE_B = uuid.UUID("b2222222-2222-4222-8222-222222222202")
RUN_A = uuid.UUID("a1111111-1111-4111-8111-1111111111aa")
RUN_B = uuid.UUID("b2222222-2222-4222-8222-2222222222bb")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _db_dsn() -> str:
    url = os.environ.get("DATABASE_URL") or os.environ.get("AISOC_DATABASE_URL")
    if url and url.startswith("postgresql+asyncpg://"):
        url = url.replace("postgresql+asyncpg://", "postgresql://", 1)
    if url:
        return url
    return "postgresql://aisoc:aisoc_dev_secret@postgres:5432/aisoc"


def _alert_ids(prefix: str, n: int) -> list[uuid.UUID]:
    out: list[uuid.UUID] = []
    for i in range(1, n + 1):
        out.append(uuid.UUID(f"{prefix}{i:012d}"[:8] + "-eeee-4eee-8eee-" + f"{i:012d}"))
    return out


ALERTS_A = _alert_ids("a1111111", 6)
ALERTS_B = _alert_ids("b2222222", 7)


REPORT_A = f"""# Incident Report — {CASE_A}

## Executive Summary

A **true-positive** multi-stage **credential-access and lateral-movement campaign** was correlated across **6 linked alerts** sharing host `FIN-WS-042`, user `j.martinez`, and domain controller `FIN-DC-01`.

Observed activity is consistent with Kerberoasting → LSASS credential access → Pass-the-Hash lateral movement to `FIN-DC-01`, followed by outbound C2 to `185.234.72.19`.

Privilege escalation beyond the initial workstation context is **supported by process and authentication evidence** on the domain controller path. Full domain compromise / data exfiltration volume remains **partially confirmed** (C2 beaconing observed; bulk transfer not yet quantified).

| Axis | Assessment |
|------|------------|
| Detection confidence | high |
| Technique confidence | high |
| Execution confidence | high |
| Compromise confidence | medium-high (DC auth + C2; impact scope pending) |

**Risk level:** Critical (investigation priority)  
**Threat actor:** Unattributed (TTPs overlap publicly documented Kerberoast / PtH tradecraft; no unique actor signature)  
**Case model:** attack_campaign · linked alerts: **6**

## Timeline of Events

| # | Timestamp (UTC) | Event | Host / User |
|---|-----------------|-------|-------------|
| 1 | {(NOW - timedelta(hours=6, minutes=40)).strftime("%Y-%m-%d %H:%M:%S")} | Unusual Kerberos TGS requests for high-privilege SPNs (Kerberoasting indicator) | FIN-WS-042 / j.martinez |
| 2 | {(NOW - timedelta(hours=6, minutes=25)).strftime("%Y-%m-%d %H:%M:%S")} | Suspicious LSASS memory access via `rundll32` / `comsvcs` MiniDump pattern | FIN-WS-042 / j.martinez |
| 3 | {(NOW - timedelta(hours=6, minutes=10)).strftime("%Y-%m-%d %H:%M:%S")} | NTLM authentication from FIN-WS-042 to FIN-DC-01 using privileged context | FIN-DC-01 / j.martinez |
| 4 | {(NOW - timedelta(hours=5, minutes=55)).strftime("%Y-%m-%d %H:%M:%S")} | Remote service creation / PsExec-like lateral movement artifact | FIN-DC-01 |
| 5 | {(NOW - timedelta(hours=5, minutes=40)).strftime("%Y-%m-%d %H:%M:%S")} | Encoded PowerShell download cradle | FIN-DC-01 / SYSTEM |
| 6 | {(NOW - timedelta(hours=5, minutes=20)).strftime("%Y-%m-%d %H:%M:%S")} | Persistent HTTPS beacon to 185.234.72.19:443 (JA3 uncommon) | FIN-DC-01 |

## IOC Analysis

| Class | Type | Value | Status |
|-------|------|-------|--------|
| Confirmed IOC | IPv4 | 185.234.72.19 | Confirmed (C2 egress from FIN-DC-01) |
| Confirmed IOC | Domain | update-cdn-ms[.]top | Confirmed (HTTP Host header on beacon) |
| Suspicious indicator | User | j.martinez | Compromised credential suspected |
| Observable | Host | FIN-WS-042 | Patient-zero workstation |
| Observable | Host | FIN-DC-01 | Lateral / C2 staging |

## MITRE ATT&CK Mapping

| ID | Technique | Evidence basis |
|----|-----------|----------------|
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Abnormal TGS volume for SPNs |
| T1003.001 | OS Credential Dumping: LSASS Memory | Process access + MiniDump command line |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | NTLM auth without interactive logon pattern |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Remote service / admin share activity |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Encoded cradle on DC |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 beacon |

## Forensic Findings

**Assessment (not sole root-cause claim):** Initial access likely via previously phished or reused credentials for `j.martinez` on `FIN-WS-042`, enabling Kerberoasting and subsequent credential dumping. Lateral movement to `FIN-DC-01` is supported by authentication and remote service artefacts. C2 establishment on the DC is supported by network telemetry.

**Blast radius:** Confirmed hosts `FIN-WS-042`, `FIN-DC-01`. Additional finance subnet exposure **pending validation** — not asserted as environment-wide.

## Response Plan

**Status of actions:** Recommended (not executed)

### Containment (Recommended)
1. Isolate `FIN-WS-042` and `FIN-DC-01` via EDR network containment.
2. Disable / reset `j.martinez` and any privileged accounts used in the NTLM path; revoke active tickets.
3. Block egress to `185.234.72.19` and domain `update-cdn-ms.top` at edge DNS/firewall.

### Eradication (Recommended)
1. Remove remote services / persistence on `FIN-DC-01` after forensic imaging.
2. Clear malicious scheduled tasks / Run keys identified in follow-up hunt.
3. Rotate KRBTGT if golden-ticket risk cannot be ruled out after deeper review.

### Recovery (Recommended)
1. Rebuild `FIN-WS-042` from golden image; staged return of `FIN-DC-01` after integrity validation.
2. 30-day heightened monitoring for Kerberos anomalies and C2 JA3 fingerprint.

## Recommendations
1. Enforce tiered admin model; remove daily-driver admin rights from finance workstations.
2. Enable LSASS PPL / Credential Guard on Tier-0 and Tier-1.
3. Hunt 14 days for other Kerberoasting sources and PtH to additional DCs.
4. Share IOCs with TI platform after hash/AV enrichment of dropped payloads.

## Appendix: Enrichment Data

### Historical Case Similarity
No meaningful historical similarity above threshold 0.25 for this campaign seed.

### Evidence-to-Claim Validation

| Claim | Evidence | Status |
|-------|----------|--------|
| Kerberoasting behavior detected | TGS anomaly alert + SPN targets | supported |
| LSASS credential access executed | Process + command line on FIN-WS-042 | supported |
| Lateral movement to DC | NTLM + remote service artefacts | supported |
| C2 established | Egress sessions to 185.234.72.19 | supported |
| Full domain compromise | Enterprise-wide auth anomalies | partial |
| Data exfiltration completed | Volume/transfer evidence | missing |

### Case Metadata
| Field | Value |
|-------|-------|
| Case ID | {CASE_A} |
| Linked alerts | 6 |
| Theme | credential-access |
| Disposition | true_positive |
| Demo seed | {SEED_TAG} |
"""


REPORT_B = f"""# Incident Report — {CASE_B}

## Executive Summary

A **true-positive** **command-and-control / defense-evasion campaign** was correlated across **7 linked alerts** on engineering laptop `ENG-LAP-118` (user `a.chen`), with follow-on activity on file server `FS-ENG-03`.

The chain shows initial malicious Office child process → UAC bypass *indicator* via `HKCU\\Software\\Classes\\ms-settings` → scheduled-task persistence → Cobalt Strike-like HTTPS beacon → SMB staging to `FS-ENG-03`.

| Stage | Status |
|-------|--------|
| UAC_BYPASS_INDICATOR_DETECTED | yes (registry artefacts) |
| UAC_BYPASS_EXECUTION_CONFIRMED | yes (fodhelper → elevated cmd parent/child + High integrity) |
| PRIVILEGE_ESCALATION_CONFIRMED | yes (integrity level evidence present) |
| LATERAL / STAGING | yes (SMB write to FS-ENG-03) |
| MASS IMPACT / RANSOMWARE | unconfirmed |

**Risk level:** High  
**Threat actor:** Unattributed  
**Case model:** attack_campaign · linked alerts: **7**

## Timeline of Events

| # | Timestamp (UTC) | Event | Host / User |
|---|-----------------|-------|-------------|
| 1 | {(NOW - timedelta(hours=4, minutes=50)).strftime("%Y-%m-%d %H:%M:%S")} | WinWord spawned uncommon child `cmd.exe` / `powershell.exe` | ENG-LAP-118 / a.chen |
| 2 | {(NOW - timedelta(hours=4, minutes=45)).strftime("%Y-%m-%d %H:%M:%S")} | Registry write: `HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command` + `DelegateExecute` | ENG-LAP-118 / a.chen |
| 3 | {(NOW - timedelta(hours=4, minutes=44)).strftime("%Y-%m-%d %H:%M:%S")} | `fodhelper.exe` launched; child elevated `powershell.exe` (High integrity) | ENG-LAP-118 |
| 4 | {(NOW - timedelta(hours=4, minutes=30)).strftime("%Y-%m-%d %H:%M:%S")} | Scheduled task `\\Microsoft\\Windows\\UpdateOrchestrator\\BackupScan` created (user context) | ENG-LAP-118 |
| 5 | {(NOW - timedelta(hours=4, minutes=10)).strftime("%Y-%m-%d %H:%M:%S")} | HTTPS beacon every ~60s to `91.242.18.44` (named pipe + jitter pattern) | ENG-LAP-118 |
| 6 | {(NOW - timedelta(hours=3, minutes=40)).strftime("%Y-%m-%d %H:%M:%S")} | SMB write of `invoice_Q4.zip` / staging tools to `\\\\FS-ENG-03\\share$\\IT` | FS-ENG-03 / a.chen |
| 7 | {(NOW - timedelta(hours=3, minutes=15)).strftime("%Y-%m-%d %H:%M:%S")} | Defense evasion: Event Log clearing attempt (Security channel) | ENG-LAP-118 |

## IOC Analysis

| Class | Type | Value | Status |
|-------|------|-------|--------|
| Confirmed IOC | IPv4 | 91.242.18.44 | Confirmed C2 |
| Confirmed IOC | SHA256 | 7f3a9c1e2b8d4f60aa1199cc33ddeef00112233445566778899aabbccddeeff0 | Dropper DLL hash |
| Suspicious indicator | Registry | HKCU\\...\\ms-settings\\Shell\\Open\\command | UAC bypass pattern |
| Observable | File | C:\\Windows\\System32\\fodhelper.exe | LOLbin (Microsoft-signed); abuse via parent/child, not malicious binary |
| Observable | Host | ENG-LAP-118, FS-ENG-03 | Affected assets |

## MITRE ATT&CK Mapping

| ID | Technique | Notes |
|----|-----------|-------|
| T1566.001 | Phishing: Spearphishing Attachment | Office → uncommon child |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | Registry + fodhelper + High IL (not T1548.001) |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence |
| T1071.001 | Web Protocols | HTTPS C2 |
| T1021.002 | SMB/Windows Admin Shares | Staging to FS-ENG-03 |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Attempted |

## Forensic Findings

**Assessment:** User `a.chen` opened a malicious Office document that installed a UAC bypass via COM handler hijack, achieved elevated PowerShell, established persistence and C2, then staged tooling over SMB. `fodhelper.exe` is a legitimate Windows binary — malice is in the registry command and child process tree, not the LOLbin file itself.

**Blast radius:** Confirmed `ENG-LAP-118` and `FS-ENG-03`. Other engineering hosts: **unknown** pending share ACL / auth hunt.

## Response Plan

**Status of actions:** Recommended

### Containment (Recommended)
1. Isolate `ENG-LAP-118`; revoke interactive sessions for `a.chen`.
2. Quarantine staging path on `FS-ENG-03\\share$\\IT`; snapshot volume.
3. Block `91.242.18.44` egress. Do **not** block `fodhelper.exe` globally.

### Eradication (Recommended)
1. Remove malicious `HKCU\\Software\\Classes\\ms-settings` keys after evidence capture.
2. Delete rogue scheduled task; kill C2 process tree.
3. Purge staged archives on FS-ENG-03 after hashing.

### Recovery (Recommended)
1. Reimage ENG-LAP-118; password reset + MFA rebind for `a.chen`.
2. Hunt peers who opened the same attachment (mail gateway message-id correlation).

## Recommendations
1. Attack-surface reduction: block Office child processes (ASR).
2. Sysmon 1/12/13/14 + Security 4688/4657 for UAC bypass correlation.
3. Alert on `DelegateExecute` writes under `HKCU\\Software\\Classes`.

## Appendix: Enrichment Data

### Evidence-to-Claim Validation

| Claim | Evidence | Status |
|-------|----------|--------|
| UAC bypass behavior detected | Registry + ESCU/EDR rule | supported |
| Elevated process executed | fodhelper → powershell High IL | supported |
| Persistence established | Scheduled task artefact | supported |
| C2 established | Beacon telemetry | supported |
| Ransomware deployed | Encryptor / note | missing |
| All Windows endpoints affected | Asset inventory | unsupported |

### Case Metadata
| Field | Value |
|-------|-------|
| Case ID | {CASE_B} |
| Linked alerts | 7 |
| Theme | command-and-control |
| Disposition | true_positive |
| Demo seed | {SEED_TAG} |
"""

async def _purge(conn: asyncpg.Connection) -> None:
    await conn.execute(
        """
        DELETE FROM investigation_artifacts
         WHERE run_id IN (
            SELECT id FROM investigation_runs
             WHERE tenant_id = $1 AND case_id IN ($2, $3)
         )
        """,
        TENANT,
        str(CASE_A),
        str(CASE_B),
    )
    await conn.execute(
        """
        DELETE FROM investigation_events
         WHERE run_id IN (
            SELECT id FROM investigation_runs
             WHERE tenant_id = $1 AND case_id IN ($2, $3)
         )
        """,
        TENANT,
        str(CASE_A),
        str(CASE_B),
    )
    await conn.execute(
        "DELETE FROM investigation_runs WHERE tenant_id = $1 AND case_id IN ($2, $3)",
        TENANT,
        str(CASE_A),
        str(CASE_B),
    )
    await conn.execute(
        "DELETE FROM aisoc_case_tasks WHERE case_id IN ($1, $2)",
        CASE_A,
        CASE_B,
    )
    await conn.execute(
        "DELETE FROM alerts WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
        TENANT,
        ALERTS_A + ALERTS_B,
    )
    await conn.execute(
        """
        DELETE FROM aisoc_cases
         WHERE id IN ($1, $2)
            OR (tenant_id = $3 AND tags->>'demo_seed' = $4)
        """,
        CASE_A,
        CASE_B,
        TENANT,
        SEED_TAG,
    )


async def _insert_alert(
    conn: asyncpg.Connection,
    *,
    alert_id: uuid.UUID,
    case_id: uuid.UUID,
    title: str,
    description: str,
    severity: str,
    tactics: list[str],
    techniques: list[str],
    hosts: list[str],
    users: list[str],
    ips: list[str],
    iocs: list[dict],
    entities: list[dict],
    raw: dict,
    event_time: datetime,
    narrative: str,
    ai_summary: str,
    confidence: int = 88,
) -> None:
    await conn.execute(
        """
        INSERT INTO alerts (
            id, tenant_id, title, description, severity, status, priority,
            category, mitre_tactics, mitre_techniques, connector_type,
            source_event_ids, rule_name, disposition,
            ai_score, ai_summary, ai_recommendations,
            confidence, confidence_label,
            narrative, affected_ips, affected_hosts, affected_users, affected_assets,
            case_id, child_alert_ids, is_merged,
            raw_event, enrichment_data, tags, iocs, entities,
            event_time, first_seen, last_seen, created_at, updated_at,
            funnel_stage, occurrence_count, alert_category_meta
        ) VALUES (
            $1, $2, $3, $4, $5, 'in_progress', 20,
            $6, $7::jsonb, $8::jsonb, 'splunk',
            '[]'::jsonb, $9, 'true_positive',
            0.91, $10, '[]'::jsonb,
            $11, 'high',
            $12, $13::jsonb, $14::jsonb, $15::jsonb, '[]'::jsonb,
            $16, '[]'::jsonb, false,
            $17::jsonb, '{}'::jsonb, $18::jsonb, $19::jsonb, $20::jsonb,
            $21, $21, $22, $21, $23,
            'cased', 1, '{}'::jsonb
        )
        """,
        alert_id,
        TENANT,
        title[:500],
        description,
        severity,
        raw.get("category") or "intrusion",
        json.dumps(tactics),
        json.dumps(techniques),
        title[:200],
        ai_summary,
        confidence,
        narrative,
        json.dumps(ips),
        json.dumps(hosts),
        json.dumps(users),
        case_id,
        json.dumps(raw),
        json.dumps([{"demo_seed": SEED_TAG}]),
        json.dumps(iocs),
        json.dumps(entities),
        event_time,
        event_time + timedelta(minutes=5),
        NOW,
    )


async def _insert_case(
    conn: asyncpg.Connection,
    *,
    case_id: uuid.UUID,
    title: str,
    description: str,
    severity: str,
    techniques: list[str],
    alert_ids: list[uuid.UUID],
    tags: dict,
    opened_at: datetime,
) -> None:
    await conn.execute(
        """
        INSERT INTO aisoc_cases (
            id, tenant_id, title, description, severity, status,
            mitre_techniques, alert_ids, tags,
            opened_at, triaged_at, created_at, updated_at, created_by
        ) VALUES (
            $1, $2, $3, $4, $5, 'investigating',
            $6::jsonb, $7::uuid[], $8::jsonb,
            $9, $10, $9, $11, 'demo-intro-seed'
        )
        """,
        case_id,
        TENANT,
        title,
        description,
        severity,
        json.dumps(techniques),
        alert_ids,
        json.dumps(tags),
        opened_at,
        opened_at + timedelta(minutes=10),
        NOW,
    )


async def _insert_tasks(conn: asyncpg.Connection, case_id: uuid.UUID, titles: list[str]) -> None:
    for i, title in enumerate(titles):
        status = "done" if i == 0 else ("in_progress" if i == 1 else "todo")
        await conn.execute(
            """
            INSERT INTO aisoc_case_tasks (case_id, title, status, created_by, tenant_id)
            VALUES ($1, $2, $3, 'demo-intro-seed', $4)
            """,
            case_id,
            title,
            status,
            TENANT,
        )


async def _insert_investigation(
    conn: asyncpg.Connection,
    *,
    run_id: uuid.UUID,
    case_id: uuid.UUID,
    alert_summary: str,
    raw_alert: dict,
    report_md: str,
    started: datetime,
) -> None:
    await conn.execute(
        """
        INSERT INTO investigation_runs (
            id, tenant_id, case_id, alert_summary, raw_alert, model_used,
            status, error, total_tokens, total_cost_usd, iterations,
            started_at, completed_at, created_at
        ) VALUES (
            $1, $2, $3, $4, $5::jsonb, 'demo-seed-report',
            'completed', NULL, 12400, 0.0000, 4,
            $6, $7, $6
        )
        """,
        run_id,
        TENANT,
        str(case_id),
        alert_summary,
        json.dumps(raw_alert),
        started,
        started + timedelta(minutes=8),
    )
    steps = [
        ("recon", "ReconAgent", "Entities, IOCs, and MITRE techniques extracted from linked alerts."),
        ("forensic", "ForensicAgent", "Timeline reconstructed with host/user-scoped blast radius."),
        ("respond", "ResponderAgent", "Containment/eradication plan generated (Recommended only)."),
        ("report", "ReportWriterAgent", "Final incident report written with Evidence-to-Claim appendix."),
    ]
    for seq, (kind, agent, summary) in enumerate(steps, start=1):
        event_id = uuid.uuid4()
        await conn.execute(
            """
            INSERT INTO investigation_events (
                id, run_id, tenant_id, seq, ts, kind, agent, summary,
                payload, duration_ms, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                '{}'::jsonb, $9, $5
            )
            """,
            event_id,
            run_id,
            TENANT,
            seq,
            started + timedelta(minutes=seq),
            kind,
            agent,
            summary,
            800 + seq * 200,
        )
        if kind == "report":
            await conn.execute(
                """
                INSERT INTO investigation_artifacts (
                    id, run_id, event_id, tenant_id, kind, content,
                    sha256, size_bytes, created_at
                ) VALUES (
                    $1, $2, $3, $4, 'report_md', $5,
                    $6, $7, $8
                )
                """,
                uuid.uuid4(),
                run_id,
                event_id,
                TENANT,
                report_md,
                _sha(report_md),
                len(report_md.encode("utf-8")),
                started + timedelta(minutes=seq),
            )
    await conn.execute(
        """
        INSERT INTO investigation_artifacts (
            id, run_id, event_id, tenant_id, kind, content,
            sha256, size_bytes, created_at
        ) VALUES (
            $1, $2, NULL, $3, 'report_md', $4,
            $5, $6, $7
        )
        """,
        uuid.uuid4(),
        run_id,
        TENANT,
        report_md,
        _sha(report_md),
        len(report_md.encode("utf-8")),
        started + timedelta(minutes=9),
    )


async def seed_campaign_a(conn: asyncpg.Connection) -> None:
    opened = NOW - timedelta(hours=7)
    specs = [
        (ALERTS_A[0], opened + timedelta(minutes=20), "ESCU - Kerberoasting Unusual TGS Request Volume", "high", ["credential-access"], ["T1558.003"], ["FIN-WS-042"], ["j.martinez"], ["10.20.14.42"], "Abnormal Kerberos TGS requests for privileged SPNs from FIN-WS-042."),
        (ALERTS_A[1], opened + timedelta(minutes=35), "ESCU - Suspicious LSASS Memory Access MiniDump", "critical", ["credential-access"], ["T1003.001"], ["FIN-WS-042"], ["j.martinez"], ["10.20.14.42"], "LSASS accessed via comsvcs MiniDump pattern on finance workstation."),
        (ALERTS_A[2], opened + timedelta(minutes=50), "ESCU - Pass-the-Hash NTLM Auth to Domain Controller", "critical", ["lateral-movement", "credential-access"], ["T1550.002"], ["FIN-DC-01"], ["j.martinez"], ["10.20.1.10", "10.20.14.42"], "NTLM authentication to FIN-DC-01 consistent with Pass-the-Hash."),
        (ALERTS_A[3], opened + timedelta(minutes=65), "ESCU - Remote Service Creation Lateral Movement", "high", ["lateral-movement"], ["T1021.002"], ["FIN-DC-01"], ["j.martinez"], ["10.20.1.10"], "Remote service creation artefact on FIN-DC-01 after PtH auth."),
        (ALERTS_A[4], opened + timedelta(minutes=80), "ESCU - Encoded PowerShell Download Cradle", "high", ["execution"], ["T1059.001"], ["FIN-DC-01"], ["SYSTEM"], ["10.20.1.10"], "Base64 PowerShell cradle executed on domain controller."),
        (ALERTS_A[5], opened + timedelta(minutes=100), "ESCU - Suspicious HTTPS Beacon to Rare External IP", "critical", ["command-and-control"], ["T1071.001"], ["FIN-DC-01"], ["SYSTEM"], ["185.234.72.19", "10.20.1.10"], "Periodic HTTPS beacon from FIN-DC-01 to 185.234.72.19."),
    ]
    for aid, ts, title, sev, tactics, techniques, hosts, users, ips, narrative in specs:
        ents = [{"type": "host", "value": h} for h in hosts] + [{"type": "user", "value": u} for u in users]
        iocs = []
        for ip in ips:
            if not ip.startswith("10."):
                ents.append({"type": "ip", "value": ip})
                iocs.append({"type": "ip", "value": ip})
        if "185.234.72.19" in ips:
            ents.append({"type": "domain", "value": "update-cdn-ms.top"})
            iocs.append({"type": "domain", "value": "update-cdn-ms.top"})
        await _insert_alert(
            conn, alert_id=aid, case_id=CASE_A, title=title, description=narrative, severity=sev,
            tactics=tactics, techniques=techniques, hosts=hosts, users=users, ips=ips, iocs=iocs,
            entities=ents,
            raw={"hostname": hosts[0], "username": users[0], "src_ip": ips[0], "search_name": title, "category": "intrusion", "demo_seed": SEED_TAG},
            event_time=ts, narrative=narrative, ai_summary=narrative,
        )
    await _insert_case(
        conn, case_id=CASE_A,
        title="Suspected credential-access campaign involving FIN-WS-042, FIN-DC-01",
        description=("Auto-created demo attack-campaign case for intro meeting.\\n"
                     "Theme: credential-access\\n"
                     "Entities: host:FIN-WS-042, host:FIN-DC-01, user:j.martinez, ip:185.234.72.19\\n"
                     "Disposition: true_positive\\nLinked alerts: 6\\n"
                     "Kill chain: Kerberoast → LSASS dump → Pass-the-Hash → remote service → PowerShell → C2\\n"),
        severity="critical",
        techniques=["T1558.003", "T1003.001", "T1550.002", "T1021.002", "T1059.001", "T1071.001"],
        alert_ids=ALERTS_A,
        tags={"agentic-promoted": True, "reportable": True, "source": "demo-intro-seed",
              "campaign_theme": "credential-access", "case_model": "attack_campaign",
              "linked_alert_count": 6, "campaign_key": "credential-access|host:FIN-WS-042",
              "demo_seed": SEED_TAG, "demo_label": "Intro Meeting — Credential Access / Lateral Movement"},
        opened_at=opened,
    )
    await _insert_tasks(conn, CASE_A, [
        "Capture memory image of FIN-WS-042",
        "Isolate FIN-DC-01 and block C2 185.234.72.19",
        "Reset j.martinez and review privileged group membership",
        "Hunt Kerberoasting across finance VLAN (14d)",
    ])
    await _insert_investigation(
        conn, run_id=RUN_A, case_id=CASE_A,
        alert_summary="Credential-access campaign: Kerberoast → PtH → C2 on FIN-DC-01",
        raw_alert={"title": specs[0][2], "demo_seed": SEED_TAG, "linked_alert_count": 6},
        report_md=REPORT_A, started=opened + timedelta(hours=1),
    )


async def seed_campaign_b(conn: asyncpg.Connection) -> None:
    opened = NOW - timedelta(hours=5)
    specs = [
        (ALERTS_B[0], opened + timedelta(minutes=10), "ESCU - Office Product Spawned Uncommon Process", "high", ["initial-access", "execution"], ["T1566.001", "T1059.001"], ["ENG-LAP-118"], ["a.chen"], ["10.30.8.118"], "WinWord spawned uncommon cmd/powershell child on ENG-LAP-118."),
        (ALERTS_B[1], opened + timedelta(minutes=15), "ESCU - Windows UAC Bypass Suspicious Escalation Behavior", "high", ["privilege-escalation", "defense-evasion"], ["T1548.002"], ["ENG-LAP-118"], ["a.chen"], ["10.30.8.118"], "HKCU ms-settings Open\\\\command + DelegateExecute written; fodhelper abuse pattern."),
        (ALERTS_B[2], opened + timedelta(minutes=16), "EDR - Elevated PowerShell via fodhelper Parent Process", "critical", ["privilege-escalation"], ["T1548.002", "T1059.001"], ["ENG-LAP-118"], ["a.chen"], ["10.30.8.118"], "fodhelper.exe → powershell.exe with High integrity level confirmed."),
        (ALERTS_B[3], opened + timedelta(minutes=30), "ESCU - Suspicious Scheduled Task Creation", "medium", ["persistence"], ["T1053.005"], ["ENG-LAP-118"], ["a.chen"], ["10.30.8.118"], "User-mode scheduled task created for persistence after UAC bypass."),
        (ALERTS_B[4], opened + timedelta(minutes=50), "ESCU - Cobalt Strike-like HTTPS Beacon Pattern", "critical", ["command-and-control"], ["T1071.001"], ["ENG-LAP-118"], ["a.chen"], ["10.30.8.118", "91.242.18.44"], "Jittered HTTPS beacon to 91.242.18.44 from ENG-LAP-118."),
        (ALERTS_B[5], opened + timedelta(minutes=80), "ESCU - Suspicious SMB Write to Admin Share", "high", ["lateral-movement", "collection"], ["T1021.002"], ["FS-ENG-03", "ENG-LAP-118"], ["a.chen"], ["10.30.1.50", "10.30.8.118"], "Staging archive written to \\\\\\\\FS-ENG-03\\\\share$\\\\IT from ENG-LAP-118."),
        (ALERTS_B[6], opened + timedelta(minutes=105), "ESCU - Windows Event Log Cleared", "medium", ["defense-evasion"], ["T1070.001"], ["ENG-LAP-118"], ["a.chen"], ["10.30.8.118"], "Attempt to clear Security event log on ENG-LAP-118."),
    ]
    for aid, ts, title, sev, tactics, techniques, hosts, users, ips, narrative in specs:
        ents = [{"type": "host", "value": h} for h in hosts] + [{"type": "user", "value": u} for u in users]
        iocs: list[dict] = []
        for ip in ips:
            if not ip.startswith("10."):
                ents.append({"type": "ip", "value": ip})
                iocs.append({"type": "ip", "value": ip})
        if "UAC" in title or "fodhelper" in narrative:
            iocs.append({"type": "registry", "value": r"HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"})
        if "Beacon" in title:
            iocs.append({"type": "hash", "value": "7f3a9c1e2b8d4f60aa1199cc33ddeef00112233445566778899aabbccddeeff0"})
        await _insert_alert(
            conn, alert_id=aid, case_id=CASE_B, title=title, description=narrative, severity=sev,
            tactics=tactics, techniques=techniques, hosts=hosts, users=users, ips=ips, iocs=iocs,
            entities=ents,
            raw={"hostname": hosts[0], "username": users[0], "src_ip": ips[0], "search_name": title, "category": "intrusion", "demo_seed": SEED_TAG},
            event_time=ts, narrative=narrative, ai_summary=narrative,
        )
    await _insert_case(
        conn, case_id=CASE_B,
        title="Suspected C2 / command-and-control campaign involving ENG-LAP-118, FS-ENG-03",
        description=("Auto-created demo attack-campaign case for intro meeting.\\n"
                     "Theme: command-and-control\\n"
                     "Entities: host:ENG-LAP-118, host:FS-ENG-03, user:a.chen, ip:91.242.18.44\\n"
                     "Disposition: true_positive\\nLinked alerts: 7\\n"
                     "Kill chain: Phish/Office → UAC bypass (T1548.002) → Task persistence → C2 → SMB staging\\n"),
        severity="critical",
        techniques=["T1566.001", "T1548.002", "T1053.005", "T1071.001", "T1021.002", "T1070.001"],
        alert_ids=ALERTS_B,
        tags={"agentic-promoted": True, "reportable": True, "source": "demo-intro-seed",
              "campaign_theme": "command-and-control", "case_model": "attack_campaign",
              "linked_alert_count": 7, "campaign_key": "command-and-control|host:ENG-LAP-118",
              "demo_seed": SEED_TAG, "demo_label": "Intro Meeting — UAC Bypass / C2 / Staging"},
        opened_at=opened,
    )
    await _insert_tasks(conn, CASE_B, [
        "Isolate ENG-LAP-118 and snapshot FS-ENG-03 staging share",
        "Block C2 91.242.18.44 / collect dropper hash verdicts",
        "Remove malicious HKCU ms-settings keys after evidence capture",
        "Mail-gateway hunt for same attachment recipients",
    ])
    await _insert_investigation(
        conn, run_id=RUN_B, case_id=CASE_B,
        alert_summary="C2 campaign: Office → UAC bypass T1548.002 → beacon → SMB staging",
        raw_alert={"title": specs[1][2], "demo_seed": SEED_TAG, "linked_alert_count": 7},
        report_md=REPORT_B, started=opened + timedelta(hours=1),
    )


async def _amain() -> None:
    dsn = _db_dsn()
    print("Connecting…")
    conn = await asyncpg.connect(dsn)
    try:
        async with conn.transaction():
            await _purge(conn)
            await seed_campaign_a(conn)
            await seed_campaign_b(conn)
    finally:
        await conn.close()
    print("OK")
    print(f"CASE_A={CASE_A} alerts={len(ALERTS_A)}")
    print(f"CASE_B={CASE_B} alerts={len(ALERTS_B)}")
    print(f"Open: /cases/{CASE_A}")
    print(f"Open: /cases/{CASE_B}")


def main() -> None:
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
