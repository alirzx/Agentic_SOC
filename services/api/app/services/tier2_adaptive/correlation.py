"""P3 — Entity-aware correlation engine for Tier-2 Adaptive Investigation.

Replaces IP-only sibling search with multi-dimension scoring. Scores are
explainable and configurable. Same rule title or severity alone never correlates.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable

from app.services.tier2_adaptive.entities import (
    EntityExtractionResult,
    ExtractedEntity,
    extract_alert_entities,
)

CORRELATION_VERSION = "tier2-corr:v1"

# Initial weights (0–100 scale contribution before normalization). Configurable.
DEFAULT_WEIGHTS: dict[str, float] = {
    "exact_endpoint": 30.0,
    "exact_user_sid": 25.0,
    "exact_ip": 20.0,
    "exact_file_hash": 35.0,
    "process_relationship": 25.0,
    "behavioral_similarity": 20.0,
    "temporal_proximity": 10.0,
    "rule_relationship": 10.0,
    "exact_hostname": 30.0,
    "exact_domain": 15.0,
    "exact_url": 20.0,
    "exact_email": 20.0,
    "exact_cloud_account": 25.0,
    "exact_cloud_resource": 25.0,
}

# Score bands (policy consumes these in P4).
SCORE_UNRELATED = 40.0
SCORE_CANDIDATE = 70.0  # 40–69 candidate; >=70 eligible for case extension

# Common infrastructure IPs that must not create weak false correlations alone.
_COMMON_INFRA_IPS = frozenset(
    {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "208.67.222.222",
        "208.67.220.220",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    }
)


@dataclass
class CorrelationReason:
    type: str
    value: str
    weight: float
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationResult:
    candidate_alert_id: str
    total_score: float
    matched_entities: list[dict[str, str]] = field(default_factory=list)
    match_type: str = "none"
    time_relationship: str = "unknown"
    supporting_evidence: list[str] = field(default_factory=list)
    correlation_reasons: list[CorrelationReason] = field(default_factory=list)
    confidence: float = 0.0
    decision: str = "unrelated"  # unrelated | candidate | eligible
    algorithm_version: str = CORRELATION_VERSION
    contradictory: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_alert_id": self.candidate_alert_id,
            "total_score": self.total_score,
            "matched_entities": self.matched_entities,
            "match_type": self.match_type,
            "time_relationship": self.time_relationship,
            "supporting_evidence": self.supporting_evidence,
            "correlation_reasons": [r.to_dict() for r in self.correlation_reasons],
            "confidence": self.confidence,
            "decision": self.decision,
            "algorithm_version": self.algorithm_version,
            "contradictory": self.contradictory,
        }


@dataclass
class CorrelationHistoryEntry:
    seed_alert_id: str
    results: list[CorrelationResult]
    window_hours: int
    recorded_at: str
    algorithm_version: str = CORRELATION_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed_alert_id": self.seed_alert_id,
            "results": [r.to_dict() for r in self.results],
            "window_hours": self.window_hours,
            "recorded_at": self.recorded_at,
            "algorithm_version": self.algorithm_version,
        }


def _entity_values(ents: EntityExtractionResult, *types: str) -> set[str]:
    out: set[str] = set()
    for t in types:
        for v in ents.values(t):
            out.add(v.lower())
    return out


def _ts(alert: dict[str, Any]) -> float | None:
    for key in ("event_time", "alert_time", "created_at"):
        val = alert.get(key)
        if val is None:
            continue
        if hasattr(val, "timestamp"):
            return float(val.timestamp())
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00").replace("+0330", "+03:30")).timestamp()
            except ValueError:
                continue
    return None


def _rule_token(alert: dict[str, Any]) -> str:
    rule_id = str(alert.get("rule_id") or "").strip().lower()
    if rule_id:
        return f"id:{rule_id}"
    name = str(alert.get("rule_name") or alert.get("title") or "").strip().lower()
    return f"name:{name}" if name else ""


def _behavior_token(alert: dict[str, Any], ents: EntityExtractionResult) -> str:
    """Lightweight behavioral fingerprint: process + script/path family."""
    bits: list[str] = []
    procs = ents.values("process_name")[:2]
    paths = ents.values("file_path")[:1]
    scripts = ents.values("script_block")[:1]
    if procs:
        bits.append(f"proc:{procs[0].lower()}")
    if paths:
        # Use basename family
        base = paths[0].replace("\\", "/").split("/")[-1].lower()
        bits.append(f"file:{base}")
    if scripts:
        # First non-trivial token from script (not full body)
        head = scripts[0][:64].lower().split()
        if head:
            bits.append(f"script:{head[0]}")
    domain = str(alert.get("security_domain") or "").lower()
    if domain:
        bits.append(f"dom:{domain}")
    return "|".join(bits)


def _decision_for_score(score: float, *, contradictory: bool) -> str:
    if contradictory:
        return "unrelated"
    if score >= SCORE_CANDIDATE:
        return "eligible"
    if score >= SCORE_UNRELATED:
        return "candidate"
    return "unrelated"


def _normalize_score(raw: float) -> float:
    """Weights are already 0–100 contribution points; sum then cap."""
    return round(min(100.0, max(0.0, raw)), 2)


def score_alert_correlation(
    seed: dict[str, Any],
    candidate: dict[str, Any],
    *,
    seed_entities: EntityExtractionResult | None = None,
    candidate_entities: EntityExtractionResult | None = None,
    weights: dict[str, float] | None = None,
    temporal_window_seconds: int = 86400,
    require_non_rule_evidence: bool = True,
) -> CorrelationResult:
    """Explainable pairwise correlation score (0–100).

    Never correlates solely on shared rule title or severity.
    Common infrastructure IPs alone do not create eligible correlations.
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    seed_ents = seed_entities or extract_alert_entities(seed)
    cand_ents = candidate_entities or extract_alert_entities(candidate)
    seed_id = str(seed.get("id") or seed.get("alert_id") or "")
    cand_id = str(candidate.get("id") or candidate.get("alert_id") or "")

    # Tenant isolation — hard reject.
    seed_tenant = str(seed.get("tenant_id") or "").strip().lower()
    cand_tenant = str(candidate.get("tenant_id") or "").strip().lower()
    if seed_tenant and cand_tenant and seed_tenant != cand_tenant:
        return CorrelationResult(
            candidate_alert_id=cand_id,
            total_score=0.0,
            decision="unrelated",
            match_type="cross_tenant_blocked",
            supporting_evidence=["tenant_mismatch"],
            confidence=1.0,
        )

    reasons: list[CorrelationReason] = []
    matched: list[dict[str, str]] = []
    evidence: list[str] = []
    raw = 0.0
    contradictory = False

    def _overlap(types: tuple[str, ...], reason_type: str, weight_key: str) -> list[str]:
        left = _entity_values(seed_ents, *types)
        right = _entity_values(cand_ents, *types)
        return sorted(left & right)

    # Endpoint / hostname
    for shared in _overlap(("endpoint", "hostname"), "exact_endpoint", "exact_endpoint"):
        # Prefer endpoint weight; hostname uses same bucket.
        weight = w["exact_endpoint"] if shared in _entity_values(seed_ents, "endpoint") else w["exact_hostname"]
        raw += weight
        reasons.append(CorrelationReason(type="exact_endpoint" if weight == w["exact_endpoint"] else "exact_hostname", value=shared, weight=weight))
        matched.append({"entity_type": "hostname", "value": shared})
        evidence.append(f"shared_host:{shared}")

    # User / SID
    for shared in _overlap(("user_sid",), "exact_user_sid", "exact_user_sid"):
        raw += w["exact_user_sid"]
        reasons.append(CorrelationReason(type="exact_user_sid", value=shared, weight=w["exact_user_sid"]))
        matched.append({"entity_type": "user_sid", "value": shared})
        evidence.append(f"shared_sid:{shared}")
    for shared in _overlap(("username",), "exact_user_sid", "exact_user_sid"):
        # Username uses same weight family as user/SID per policy table.
        raw += w["exact_user_sid"]
        reasons.append(CorrelationReason(type="exact_user", value=shared, weight=w["exact_user_sid"]))
        matched.append({"entity_type": "username", "value": shared})
        evidence.append(f"shared_user:{shared}")

    # IP — with common-infra dampening
    shared_ips = _overlap(("ip",), "exact_ip", "exact_ip")
    meaningful_ips = [ip for ip in shared_ips if ip not in _COMMON_INFRA_IPS]
    common_only = shared_ips and not meaningful_ips
    for ip in meaningful_ips:
        raw += w["exact_ip"]
        reasons.append(CorrelationReason(type="exact_ip", value=ip, weight=w["exact_ip"]))
        matched.append({"entity_type": "ip", "value": ip})
        evidence.append(f"shared_ip:{ip}")
    if common_only:
        # Record but do not award full weight — prevents weak false correlations.
        damp = w["exact_ip"] * 0.15
        raw += damp
        reasons.append(
            CorrelationReason(
                type="common_infra_ip",
                value=shared_ips[0],
                weight=damp,
                detail="common_infrastructure_dampened",
            )
        )
        evidence.append(f"common_infra_ip:{shared_ips[0]}")

    # Hash
    for shared in _overlap(("file_hash",), "exact_file_hash", "exact_file_hash"):
        raw += w["exact_file_hash"]
        reasons.append(CorrelationReason(type="exact_file_hash", value=shared, weight=w["exact_file_hash"]))
        matched.append({"entity_type": "file_hash", "value": shared})
        evidence.append(f"shared_hash:{shared}")

    # Process relationship
    shared_procs = _overlap(("process_name", "parent_process"), "process_relationship", "process_relationship")
    if shared_procs:
        raw += w["process_relationship"]
        reasons.append(
            CorrelationReason(
                type="process_relationship",
                value=shared_procs[0],
                weight=w["process_relationship"],
            )
        )
        matched.append({"entity_type": "process_name", "value": shared_procs[0]})
        evidence.append(f"shared_process:{shared_procs[0]}")

    # Domain / URL / Email / Cloud
    for etype, wkey, rtype in (
        (("domain",), "exact_domain", "exact_domain"),
        (("url",), "exact_url", "exact_url"),
        (("email", "email_sender", "email_recipient"), "exact_email", "exact_email"),
        (("account_id",), "exact_cloud_account", "exact_cloud_account"),
        (("cloud_resource",), "exact_cloud_resource", "exact_cloud_resource"),
    ):
        for shared in _overlap(etype, rtype, wkey):
            raw += w[wkey]
            reasons.append(CorrelationReason(type=rtype, value=shared, weight=w[wkey]))
            matched.append({"entity_type": etype[0], "value": shared})
            evidence.append(f"shared_{rtype}:{shared}")

    # Behavioral similarity
    seed_beh = _behavior_token(seed, seed_ents)
    cand_beh = _behavior_token(candidate, cand_ents)
    if seed_beh and cand_beh and seed_beh == cand_beh:
        raw += w["behavioral_similarity"]
        reasons.append(
            CorrelationReason(
                type="behavioral_similarity",
                value=seed_beh[:120],
                weight=w["behavioral_similarity"],
            )
        )
        evidence.append("behavioral_similarity")

    # Temporal proximity
    ta, tb = _ts(seed), _ts(candidate)
    time_rel = "unknown"
    if ta is not None and tb is not None:
        delta = abs(ta - tb)
        if delta <= temporal_window_seconds:
            raw += w["temporal_proximity"]
            time_rel = f"within_{int(delta)}s"
            reasons.append(
                CorrelationReason(
                    type="temporal_proximity",
                    value=time_rel,
                    weight=w["temporal_proximity"],
                )
            )
            evidence.append(time_rel)
        else:
            time_rel = f"outside_window_{int(delta)}s"

    # Rule relationship — bonus only when other evidence exists.
    seed_rule = _rule_token(seed)
    cand_rule = _rule_token(candidate)
    same_rule = bool(seed_rule and seed_rule == cand_rule)
    non_rule_reasons = [r for r in reasons if r.type not in {"temporal_proximity", "rule_relationship"}]
    if same_rule and non_rule_reasons:
        raw += w["rule_relationship"]
        reasons.append(
            CorrelationReason(
                type="rule_relationship",
                value=seed_rule,
                weight=w["rule_relationship"],
            )
        )
        evidence.append(f"same_rule:{seed_rule}")
    elif same_rule and not non_rule_reasons:
        # Same rule alone → unrelated (explicit policy).
        evidence.append("same_rule_insufficient")

    # Contradictory evidence: both have hostnames and they don't overlap, AND
    # both have users that don't overlap, while only weak signals match.
    seed_hosts = _entity_values(seed_ents, "hostname", "endpoint")
    cand_hosts = _entity_values(cand_ents, "hostname", "endpoint")
    if seed_hosts and cand_hosts and not (seed_hosts & cand_hosts):
        seed_users = _entity_values(seed_ents, "username", "user_sid")
        cand_users = _entity_values(cand_ents, "username", "user_sid")
        if seed_users and cand_users and not (seed_users & cand_users):
            # Distinct host+user pairs — treat as contradictory unless hash matches.
            if not _overlap(("file_hash",), "exact_file_hash", "exact_file_hash"):
                contradictory = True
                evidence.append("contradictory_host_user")

    # Severity alone must never correlate — intentionally ignored.

    strong_types = {
        "exact_endpoint",
        "exact_hostname",
        "exact_user_sid",
        "exact_user",
        "exact_ip",
        "exact_file_hash",
        "process_relationship",
        "behavioral_similarity",
        "exact_domain",
        "exact_url",
        "exact_email",
        "exact_cloud_account",
        "exact_cloud_resource",
    }
    strong = [r for r in reasons if r.type in strong_types]
    only_common_infra = bool(common_only) and not strong
    if require_non_rule_evidence and not strong and same_rule and not only_common_infra:
        raw = 0.0
        reasons = [
            CorrelationReason(
                type="same_rule_without_evidence",
                value=seed_rule,
                weight=0.0,
                detail="insufficient",
            )
        ]
    elif only_common_infra:
        # Keep dampened common-infra reason for explainability; force unrelated.
        raw = min(raw, SCORE_UNRELATED - 1)

    total = _normalize_score(raw)
    if contradictory:
        total = min(total, SCORE_UNRELATED - 1)

    decision = _decision_for_score(total, contradictory=contradictory)
    match_type = reasons[0].type if reasons else "none"
    confidence = round(min(1.0, total / 100.0), 3)

    return CorrelationResult(
        candidate_alert_id=cand_id or seed_id,
        total_score=total,
        matched_entities=matched,
        match_type=match_type,
        time_relationship=time_rel,
        supporting_evidence=evidence,
        correlation_reasons=reasons,
        confidence=confidence,
        decision=decision,
        contradictory=contradictory,
    )


def correlate_candidates(
    seed: dict[str, Any],
    candidates: Iterable[dict[str, Any]],
    *,
    seed_entities: EntityExtractionResult | None = None,
    weights: dict[str, float] | None = None,
    temporal_window_seconds: int = 86400,
    min_decision: str = "candidate",
) -> CorrelationHistoryEntry:
    """Score all candidates; optionally filter to candidate/eligible decisions."""
    seed_ents = seed_entities or extract_alert_entities(seed)
    seed_id = str(seed.get("id") or seed.get("alert_id") or "")
    results: list[CorrelationResult] = []
    order = {"unrelated": 0, "candidate": 1, "eligible": 2}
    min_rank = order.get(min_decision, 1)
    for cand in candidates:
        cand_id = str(cand.get("id") or cand.get("alert_id") or "")
        if cand_id and cand_id == seed_id:
            continue
        result = score_alert_correlation(
            seed,
            cand,
            seed_entities=seed_ents,
            weights=weights,
            temporal_window_seconds=temporal_window_seconds,
        )
        if order.get(result.decision, 0) >= min_rank:
            results.append(result)
        elif min_decision == "unrelated":
            results.append(result)
    results.sort(key=lambda r: (-r.total_score, r.candidate_alert_id))
    return CorrelationHistoryEntry(
        seed_alert_id=seed_id,
        results=results,
        window_hours=max(1, temporal_window_seconds // 3600),
        recorded_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )


async def find_related_alerts_entity_aware(
    db: Any,
    *,
    tenant_id: uuid.UUID,
    seed: dict[str, Any],
    seed_entities: EntityExtractionResult | None = None,
    hours: int = 24,
    limit: int = 64,
) -> tuple[list[dict[str, Any]], CorrelationHistoryEntry]:
    """DB-backed sibling search using host/user/ip/hash entity filters.

    Reuses the agentic_funnel multi-entity OR pattern, then scores survivors.
    """
    from sqlalchemy import text

    ents = seed_entities or extract_alert_entities(seed)
    seed_id = uuid.UUID(str(seed.get("id") or seed.get("alert_id")))
    since = datetime.now(UTC) - timedelta(hours=max(1, hours))

    hosts = ents.values("hostname")[:5] + ents.values("endpoint")[:3]
    users = ents.values("username")[:5] + ents.values("user_sid")[:3]
    ips = ents.values("ip")[:8]
    hashes = ents.values("file_hash")[:3]

    # Always include seed; if no pivot entities, return seed-only history.
    if not (hosts or users or ips or hashes):
        history = CorrelationHistoryEntry(
            seed_alert_id=str(seed_id),
            results=[],
            window_hours=hours,
            recorded_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
        return [{"id": str(seed_id), **{k: v for k, v in seed.items() if k != "id"}}], history

    # Fetch a broad candidate pool via JSON/text containment (tenant scoped).
    rows = (
        await db.execute(
            text(
                """
                SELECT id, title, severity, disposition, status, tenant_id,
                       rule_name, rule_id, security_domain, detection_type,
                       affected_hosts, affected_ips, affected_users,
                       llm_payload, raw_event, enrichment_data, iocs,
                       event_time, created_at
                  FROM alerts
                 WHERE tenant_id = :tid
                   AND created_at >= :since
                   AND id <> :seed
                   AND COALESCE(disposition, '') NOT IN (
                         'false_positive', 'benign', 'benign_true_positive'
                   )
                 ORDER BY created_at DESC
                 LIMIT :lim
                """
            ).bindparams(
                tid=tenant_id,
                since=since,
                seed=seed_id,
                lim=max(limit * 4, 128),
            )
        )
    ).mappings().all()

    candidates = [dict(r) for r in rows]
    # Pre-filter cheaply by entity overlap before full scoring.
    filtered: list[dict[str, Any]] = []
    host_set = {h.lower() for h in hosts}
    user_set = {u.lower() for u in users}
    ip_set = {i.lower() for i in ips}
    hash_set = {h.lower() for h in hashes}
    for cand in candidates:
        c_ents = extract_alert_entities(cand)
        c_hosts = _entity_values(c_ents, "hostname", "endpoint")
        c_users = _entity_values(c_ents, "username", "user_sid")
        c_ips = _entity_values(c_ents, "ip")
        c_hashes = _entity_values(c_ents, "file_hash")
        if (
            (host_set and host_set & c_hosts)
            or (user_set and user_set & c_users)
            or (ip_set and ip_set & c_ips)
            or (hash_set and hash_set & c_hashes)
        ):
            cand["_entities"] = c_ents
            filtered.append(cand)

    history = correlate_candidates(
        {**seed, "tenant_id": str(tenant_id), "id": str(seed_id)},
        [{**c, "tenant_id": str(tenant_id)} for c in filtered],
        seed_entities=ents,
        temporal_window_seconds=hours * 3600,
        min_decision="unrelated",  # keep full history
    )
    # Cap returned related alerts to candidate+eligible.
    related_ids = {
        r.candidate_alert_id
        for r in history.results
        if r.decision in {"candidate", "eligible"}
    }
    related = [c for c in filtered if str(c.get("id")) in related_ids][:limit]
    seed_row = {"id": str(seed_id), **{k: v for k, v in seed.items() if k != "id"}}
    return [seed_row, *related], history
