"""P4 — Case management policy for Tier-2 Adaptive Investigation.

Removes the mandatory IP dependency from Case creation and extension.
Decisions: create | extend | standalone | review.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.services.campaign_case import (
    campaign_case_title,
    campaign_tags,
    infer_attack_theme,
    primary_campaign_key,
)
from app.services.tier2_adaptive.correlation import (
    SCORE_CANDIDATE,
    SCORE_UNRELATED,
    CorrelationHistoryEntry,
    CorrelationResult,
)
from app.services.tier2_adaptive.entities import EntityExtractionResult, extract_alert_entities

CASE_POLICY_VERSION = "case-policy:v1"

# In-process idempotency / concurrency locks keyed by tenant+campaign.
_CASE_LOCKS: dict[str, threading.Lock] = {}
_CASE_LOCKS_GUARD = threading.Lock()


def _lock_for(key: str) -> threading.Lock:
    with _CASE_LOCKS_GUARD:
        if key not in _CASE_LOCKS:
            _CASE_LOCKS[key] = threading.Lock()
        return _CASE_LOCKS[key]


@dataclass
class CaseDecision:
    action: str  # create | extend | standalone | review
    reason: str
    case_id: str | None = None
    correlation_score: float | None = None
    candidate_case_ids: list[str] = field(default_factory=list)
    entity_snapshot: list[dict[str, Any]] = field(default_factory=list)
    policy_version: str = CASE_POLICY_VERSION
    idempotency_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaseMembershipRecord:
    case_id: str
    alert_id: str
    action: str
    reason: str
    recorded_at: str
    entity_snapshot: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _alert_dict(alert: Any) -> dict[str, Any]:
    if isinstance(alert, dict):
        return alert
    out: dict[str, Any] = {}
    for name in (
        "id",
        "title",
        "severity",
        "disposition",
        "case_id",
        "tenant_id",
        "rule_name",
        "mitre_techniques",
        "security_domain",
        "llm_payload",
        "raw_event",
    ):
        if hasattr(alert, name):
            out[name] = getattr(alert, name)
    return out


def _has_sufficient_evidence(entities: EntityExtractionResult) -> bool:
    meaningful = {
        "hostname",
        "endpoint",
        "ip",
        "username",
        "user_sid",
        "file_hash",
        "file_path",
        "process_name",
        "script_block",
        "url",
        "domain",
        "email",
        "email_sender",
        "cloud_resource",
        "account_id",
    }
    return any(entities.has_type(t) for t in meaningful)


def _entity_pairs(entities: EntityExtractionResult) -> list[tuple[str, str]]:
    priority = (
        "hostname",
        "endpoint",
        "user_sid",
        "username",
        "ip",
        "file_hash",
        "domain",
        "url",
    )
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for etype in priority:
        for value in entities.values(etype)[:3]:
            key = (etype if etype != "endpoint" else "host", value)
            # Map to campaign_entities kinds.
            kind = {
                "hostname": "host",
                "endpoint": "host",
                "user_sid": "user",
                "username": "user",
                "ip": "ip",
                "file_hash": "hash",
                "domain": "domain",
                "url": "url",
            }.get(etype, etype)
            item = (kind, value)
            if item in seen:
                continue
            seen.add(item)
            pairs.append(item)
    return pairs


def _is_replay(alert: dict[str, Any]) -> bool:
    disp = str(alert.get("disposition") or "").lower()
    if disp in {"false_positive", "benign", "benign_true_positive"}:
        return True
    tags = alert.get("tags") if isinstance(alert.get("tags"), dict) else {}
    if tags.get("event_replay") or tags.get("is_replay"):
        return True
    return False


def _high_severity(alert: dict[str, Any]) -> bool:
    return str(alert.get("severity") or "").lower() in {"high", "critical"}


def decide_case_action(
    alert: Any,
    *,
    entities: EntityExtractionResult | None = None,
    correlation: CorrelationHistoryEntry | None = None,
    existing_case_id: str | None = None,
) -> CaseDecision:
    """Pure policy decision — no DB writes.

    Policy:
    - Extend when best eligible correlation (>=70) without contradiction
    - Review when best score in candidate band (40–69)
    - Create solo case for high-severity with sufficient evidence and no siblings
    - Otherwise standalone
    """
    row = _alert_dict(alert)
    ents = entities or extract_alert_entities(row)
    snapshot = [e.to_dict() for e in ents.entities[:64]]
    alert_id = str(row.get("id") or row.get("alert_id") or "")
    case_id = existing_case_id or (
        str(row["case_id"]) if row.get("case_id") else None
    )

    if _is_replay(row):
        return CaseDecision(
            action="standalone",
            reason="event_replay_or_benign_disposition",
            case_id=case_id,
            entity_snapshot=snapshot,
            idempotency_key=f"tier2-case:skip-replay:{alert_id}",
        )

    if case_id:
        # Already associated — extension of membership handled by apply layer.
        return CaseDecision(
            action="extend",
            reason="alert_already_on_case",
            case_id=case_id,
            entity_snapshot=snapshot,
            idempotency_key=f"tier2-case:extend-existing:{case_id}:{alert_id}",
        )

    eligible: list[CorrelationResult] = []
    candidates: list[CorrelationResult] = []
    if correlation:
        for result in correlation.results:
            if result.contradictory:
                continue
            if result.decision == "eligible":
                eligible.append(result)
            elif result.decision == "candidate":
                candidates.append(result)

    if eligible:
        best = max(eligible, key=lambda r: r.total_score)
        return CaseDecision(
            action="extend",
            reason=f"correlation_eligible score={best.total_score}",
            correlation_score=best.total_score,
            candidate_case_ids=[],
            entity_snapshot=snapshot,
            idempotency_key=f"tier2-case:extend-corr:{alert_id}:{best.candidate_alert_id}",
        )

    if candidates:
        best = max(candidates, key=lambda r: r.total_score)
        return CaseDecision(
            action="review",
            reason=f"correlation_uncertain score={best.total_score} (band {SCORE_UNRELATED}-{SCORE_CANDIDATE})",
            correlation_score=best.total_score,
            entity_snapshot=snapshot,
            idempotency_key=f"tier2-case:review:{alert_id}:{best.candidate_alert_id}",
        )

    if _high_severity(row) and _has_sufficient_evidence(ents) and alert_id:
        return CaseDecision(
            action="create",
            reason="high_severity_standalone_sufficient_evidence",
            entity_snapshot=snapshot,
            idempotency_key=f"tier2-case:create-solo:{alert_id}",
        )

    return CaseDecision(
        action="standalone",
        reason="insufficient_evidence_or_below_threshold",
        entity_snapshot=snapshot,
        idempotency_key=f"tier2-case:standalone:{alert_id}",
    )


async def apply_case_decision(
    db: Any,
    *,
    tenant_id: uuid.UUID,
    alert: Any,
    decision: CaseDecision,
    related_alert_ids: list[uuid.UUID] | None = None,
    entities: EntityExtractionResult | None = None,
) -> tuple[CaseDecision, CaseMembershipRecord | None]:
    """Persist create/extend with idempotency and concurrency safety.

    Shadow/disabled callers should invoke ``decide_case_action`` only.
    """
    from sqlalchemy import text

    row = _alert_dict(alert)
    ents = entities or extract_alert_entities(row)
    alert_id = uuid.UUID(str(row.get("id") or row.get("alert_id")))
    pairs = _entity_pairs(ents)
    theme = infer_attack_theme(
        title=str(row.get("title") or row.get("rule_name") or ""),
        mitre_techniques=list(row.get("mitre_techniques") or []),
        raw_alert=row.get("raw_event") if isinstance(row.get("raw_event"), dict) else {},
    )
    camp_key = primary_campaign_key(theme, pairs) or f"tier2-adaptive|{alert_id}"
    lock = _lock_for(f"{tenant_id}:{camp_key}")

    if decision.action in {"standalone", "review"}:
        return decision, None

    with lock:
        now = datetime.now(UTC)
        since = now - timedelta(hours=24)
        member_ids = list(
            dict.fromkeys(
                [alert_id, *(related_alert_ids or [])]
            )
        )
        severity = str(row.get("severity") or "medium")
        if severity not in {"info", "low", "medium", "high", "critical"}:
            severity = "medium"
        case_title = campaign_case_title(theme, pairs)
        tags = campaign_tags(theme=theme, campaign_key=camp_key, source="tier2-adaptive")
        tags["tier2_adaptive"] = True
        tags["case_policy_version"] = CASE_POLICY_VERSION
        tags["entity_kinds"] = [k for k, _ in pairs[:8]]

        case_id: uuid.UUID | None = None
        created = False
        extended = False

        if decision.action == "extend" and decision.case_id:
            case_id = uuid.UUID(str(decision.case_id))
        else:
            # Idempotent lookup by campaign_key.
            existing = (
                await db.execute(
                    text(
                        """
                        SELECT id, alert_ids FROM aisoc_cases
                         WHERE tenant_id = :tid
                           AND status NOT IN ('resolved', 'closed')
                           AND opened_at >= :since
                           AND tags->>'campaign_key' = :ckey
                         ORDER BY opened_at ASC
                         LIMIT 1
                        """
                    ).bindparams(tid=tenant_id, since=since, ckey=camp_key)
                )
            ).fetchone()
            if existing:
                case_id = existing[0]
                prior = list(existing[1] or [])
                merged = list(dict.fromkeys([*prior, *[str(x) for x in member_ids]]))
                await db.execute(
                    text(
                        """
                        UPDATE aisoc_cases
                           SET alert_ids = CAST(:alert_ids AS UUID[]),
                               tags = COALESCE(tags, '{}'::jsonb) || CAST(:tags AS JSONB),
                               updated_at = :now
                         WHERE id = :id AND tenant_id = :tid
                        """
                    ).bindparams(
                        id=case_id,
                        tid=tenant_id,
                        alert_ids=merged,
                        tags=json.dumps(tags),
                        now=now,
                    )
                )
                extended = len(merged) > len(prior)
            elif decision.action == "create" or decision.action == "extend":
                case_id = uuid.uuid4()
                description = (
                    "Tier-2 Adaptive Investigation case.\n"
                    f"Theme: {theme}\n"
                    f"Entities: {', '.join(f'{k}:{v}' for k, v in pairs[:6]) or '(none)'}\n"
                    f"Policy: {decision.reason}\n"
                    f"Linked alerts: {len(member_ids)}\n"
                )
                await db.execute(
                    text(
                        """
                        INSERT INTO aisoc_cases (
                            id, tenant_id, title, description, severity, status,
                            alert_ids, tags, opened_at, created_at, updated_at, created_by
                        ) VALUES (
                            :id, :tid, :title, :description, :severity, 'investigating',
                            CAST(:alert_ids AS UUID[]), CAST(:tags AS JSONB),
                            :now, :now, :now, 'tier2-adaptive'
                        )
                        ON CONFLICT DO NOTHING
                        """
                    ).bindparams(
                        id=case_id,
                        tid=tenant_id,
                        title=case_title[:500],
                        description=description,
                        severity=severity,
                        alert_ids=[str(x) for x in member_ids],
                        tags=json.dumps(tags),
                        now=now,
                    )
                )
                created = True

        if case_id is None:
            return decision, None

        # Attach alerts to case (idempotent membership).
        await db.execute(
            text(
                """
                UPDATE alerts
                   SET case_id = :cid,
                       updated_at = :now
                 WHERE tenant_id = :tid
                   AND id = ANY(CAST(:ids AS UUID[]))
                   AND (case_id IS NULL OR case_id = :cid)
                """
            ).bindparams(
                cid=case_id,
                tid=tenant_id,
                ids=[str(x) for x in member_ids],
                now=now,
            )
        )

        out = CaseDecision(
            action="create" if created else "extend",
            reason=decision.reason,
            case_id=str(case_id),
            correlation_score=decision.correlation_score,
            entity_snapshot=decision.entity_snapshot,
            idempotency_key=decision.idempotency_key,
        )
        membership = CaseMembershipRecord(
            case_id=str(case_id),
            alert_id=str(alert_id),
            action=out.action,
            reason=out.reason,
            recorded_at=now.isoformat().replace("+00:00", "Z"),
            entity_snapshot=decision.entity_snapshot[:32],
        )
        # Silence unused in pure path
        _ = extended
        return out, membership
