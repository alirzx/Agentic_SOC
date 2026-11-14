"""Layer 3 — Explainable pairwise alert correlation scoring.

Correlation never changes alert identity and never soft-hides alerts.
Same-rule alone is insufficient; entity + temporal (+ optional tactic) required.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.services.dedup.alert_identity import extract_identity_entities

CORRELATION_VERSION = "corr:v1"

# Weights — documented for auditability; not measured production ML scores.
_W_HOST = 0.35
_W_USER = 0.30
_W_IP = 0.25
_W_HASH = 0.40
_W_DOMAIN = 0.20
_W_TEMPORAL = 0.20
_W_TACTIC = 0.15
_W_RULE_BONUS = 0.05  # small bonus only when another strong signal exists

DEFAULT_CORRELATE_THRESHOLD = 0.55


@dataclass
class CorrelationReason:
    type: str
    value: str
    weight: float


@dataclass
class CorrelationMatch:
    left_alert_id: str
    right_alert_id: str
    correlation_score: float
    correlation_reasons: list[CorrelationReason] = field(default_factory=list)
    relationship: str = "unrelated"
    algorithm_version: str = CORRELATION_VERSION
    correlation_timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_alert_id": self.left_alert_id,
            "right_alert_id": self.right_alert_id,
            "correlation_score": self.correlation_score,
            "correlation_reasons": [asdict(r) for r in self.correlation_reasons],
            "relationship": self.relationship,
            "algorithm_version": self.algorithm_version,
            "correlation_timestamp": self.correlation_timestamp,
        }


def _overlap(a: list[str], b: list[str]) -> list[str]:
    sb = {x.lower() for x in b}
    return [x for x in a if x.lower() in sb]


def _ts(row: dict[str, Any]) -> float | None:
    for key in ("event_time", "created_at"):
        val = row.get(key)
        if val is None:
            continue
        if hasattr(val, "timestamp"):
            return float(val.timestamp())
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
    return None


def score_alert_pair(
    left: dict[str, Any],
    right: dict[str, Any],
    *,
    temporal_window_seconds: int = 3600,
    threshold: float = DEFAULT_CORRELATE_THRESHOLD,
) -> CorrelationMatch:
    """Score two alerts; same rule alone does not yield related."""
    le = extract_identity_entities(left)
    re = extract_identity_entities(right)
    reasons: list[CorrelationReason] = []
    score = 0.0

    for kind, weight, key in (
        ("shared_host", _W_HOST, "hosts"),
        ("shared_user", _W_USER, "users"),
        ("shared_hash", _W_HASH, "hashes"),
        ("shared_domain", _W_DOMAIN, "domains"),
    ):
        shared = _overlap(le[key], re[key])
        if shared:
            score += weight
            reasons.append(CorrelationReason(type=kind, value=shared[0], weight=weight))

    shared_ips = _overlap(
        [*le["src_ips"], *le["dst_ips"]],
        [*re["src_ips"], *re["dst_ips"]],
    )
    if shared_ips:
        # IP alone is weak — apply only half weight unless another reason exists.
        w = _W_IP if reasons else _W_IP * 0.4
        score += w
        reasons.append(CorrelationReason(type="shared_ip", value=shared_ips[0], weight=w))

    ta, tb = _ts(left), _ts(right)
    if ta is not None and tb is not None and abs(ta - tb) <= temporal_window_seconds:
        score += _W_TEMPORAL
        reasons.append(
            CorrelationReason(
                type="temporal_proximity",
                value=f"delta_s={int(abs(ta - tb))}",
                weight=_W_TEMPORAL,
            )
        )

    left_tactics = {
        str(t).strip().lower()
        for t in (left.get("mitre_tactics") or [])
        if str(t).strip()
    }
    right_tactics = {
        str(t).strip().lower()
        for t in (right.get("mitre_tactics") or [])
        if str(t).strip()
    }
    shared_tactics = left_tactics & right_tactics
    if shared_tactics and reasons:
        score += _W_TACTIC
        reasons.append(
            CorrelationReason(
                type="shared_tactic",
                value=sorted(shared_tactics)[0],
                weight=_W_TACTIC,
            )
        )

    left_rule = str(left.get("rule_id") or left.get("rule_name") or "").strip().lower()
    right_rule = str(right.get("rule_id") or right.get("rule_name") or "").strip().lower()
    same_rule = bool(left_rule and left_rule == right_rule)
    if same_rule and reasons:
        score += _W_RULE_BONUS
        reasons.append(
            CorrelationReason(type="same_rule", value=left_rule[:120], weight=_W_RULE_BONUS)
        )

    # Cap and classify relationship.
    score = min(1.0, round(score, 4))
    # Shared IP + temporal only (no host/user/hash) stays below threshold by design
    # when IP weight was reduced — unrelated noise.
    if score >= threshold and any(
        r.type in {"shared_host", "shared_user", "shared_hash", "shared_tactic"}
        for r in reasons
    ):
        relationship = "potentially_related"
    elif score >= threshold:
        relationship = "weakly_related"
    else:
        relationship = "unrelated"

    return CorrelationMatch(
        left_alert_id=str(left.get("id") or ""),
        right_alert_id=str(right.get("id") or ""),
        correlation_score=score,
        correlation_reasons=reasons,
        relationship=relationship,
        correlation_timestamp=datetime.now(UTC).isoformat(),
    )
