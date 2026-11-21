"""L1/L2/L3 correlation scoring (doc §4.3) and θ gating.

::

    L1 = Σ weight(shared keys)                        # 0 … 18
    L2 = 1 if (shared story OR kill-chain progression) AND L1 ≥ 2
    L3 = 1 if a real 3-hop graph path exists            AND L1 ≥ 2
    score = L1 + L2 + L3
    θ = 3

Why L3 is *not* "they share a key": a direct shared key is already counted by
L1. If L3 fired on any overlap it would be a constant ``+1`` for every
candidate pair and effectively drop θ to 2 — which doc §9 records as "almost
always a false positive" on the 2026-11-08 corpus. L3 therefore requires a path
*through a third alert*: A–K1–C–K2–B with ``K1 ≠ K2``. That is genuine
graph evidence that the two observations sit in the same intrusion, not just on
the same host.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from app.normalizer.extract_keys import WEIGHT_WEAK
from app.normalizer.roles import roles_conflict
from app.services.observations import Observation

THETA = 3
L1_CAP = 18

#: Kinds whose value can be *ambient* — seen so often in a tenant that sharing
#: it says nothing about two actions being related. IPs, hashes and host-scoped
#: process GUIDs are never treated this way: a public IP, a file hash or a
#: process instance is specific even when it is common.
AMBIENT_KINDS: frozenset[str] = frozenset({"host", "user", "domain"})

#: Kill-chain phases normalised to the Splunk/Lockheed ladder. Unknown phases
#: are ignored rather than guessed at.
_PHASE_ORDER: dict[str, int] = {
    "reconnaissance": 0,
    "recon": 0,
    "delivery": 1,
    "exploitation": 2,
    "exploit": 2,
    "installation": 3,
    "execution": 4,
    "persistence": 5,
    "privilege-escalation": 6,
    "privilege escalation": 6,
    "defense-evasion": 7,
    "defense evasion": 7,
    "credential-access": 8,
    "credential access": 8,
    "discovery": 9,
    "lateral-movement": 10,
    "lateral movement": 10,
    "collection": 11,
    "command-and-control": 12,
    "command and control": 12,
    "exfiltration": 13,
    "impact": 14,
    "actions-on-objective": 14,
}


@dataclass(frozen=True)
class PairScore:
    left: str
    right: str
    l1: int
    l2: int
    l3: int
    shared: tuple[str, ...] = ()
    veto: str | None = None
    #: The shared ambient values that made ``veto`` fire (``kind:value`` per alias
    #: group). Kept structured — not parsed back out of the veto string — because
    #: the diagnostics report lists them to the operator.
    vetoed_by: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return 0 if self.veto else min(self.l1, L1_CAP) + self.l2 + self.l3

    @property
    def passes(self) -> bool:
        return self.total >= THETA

    def as_dict(self) -> dict:
        return {
            "left": self.left,
            "right": self.right,
            "l1": self.l1,
            "l2": self.l2,
            "l3": self.l3,
            "score": self.total,
            "shared": list(self.shared),
            "veto": self.veto,
            "vetoed_by": list(self.vetoed_by),
        }


class TenantGraph:
    """In-memory bipartite index of observation → keys → observations.

    This mirrors the Neo4j projection closely enough to answer the one question
    scoring needs (``is there a 3-hop path?``) without a network round-trip per
    pair, and it keeps the engine fully testable offline.
    """

    def __init__(self, observations: Iterable[Observation] = ()) -> None:
        self._tokens: dict[str, set[str]] = {}
        self._index: dict[str, set[str]] = defaultdict(set)
        for observation in observations:
            self.add(observation)

    def add(self, observation: Observation) -> None:
        tokens = observation.tokens
        self._tokens[observation.key] = tokens
        for token in tokens:
            self._index[token].add(observation.key)

    def tokens(self, node: str) -> set[str]:
        return self._tokens.get(node, set())

    def shares_token(self, a: str, b: str) -> set[str]:
        return self.tokens(a) & self.tokens(b)

    def has_three_hop_path(self, a: str, b: str) -> bool:
        """True when A and B are joined through a third observation.

        The path must use two *distinct* shared keys (K1 for A↔C, K2 for C↔B).
        A single key shared by all three would just be another direct overlap.
        """
        candidates: set[str] = set()
        for token in self.tokens(a):
            candidates |= self._index.get(token, set())
        for token in self.tokens(b):
            candidates |= self._index.get(token, set())
        candidates.discard(a)
        candidates.discard(b)
        for node in candidates:
            common_a = self.tokens(a) & self.tokens(node)
            common_b = self.tokens(b) & self.tokens(node)
            if not common_a or not common_b:
                continue
            if (common_a - common_b) or (common_b - common_a):
                return True
        return False


#: Kinds whose values carry a suffix that a *twin* key duplicates.
_SUFFIX_KINDS = frozenset({"host", "domain"})


def _alias_group(token: str) -> tuple[str, str]:
    """Collapse alias representations of ONE entity into a single L1 slot.

    ``extract_keys`` deliberately emits more than one key for the same real
    value so that evidence written by different rules can meet:
    ``dest=ar-win-dc.attackrange.local`` also yields the short host
    ``ar-win-dc`` and a ``domain`` twin of the FQDN, and a user's UPN also
    yields the bare account name. Those are bridging keys, not independent
    evidence.

    Summing them as if they were independent made one shared host worth 6
    instead of the documented 2 (``host`` 2 + short alias 2 + domain twin 2),
    so any two alerts on a busy server cleared θ=3 on the hostname alone and
    unrelated activity collapsed into one case. Grouping the aliases restores
    the documented arithmetic: one shared host is 2, one shared account is 2,
    and a pair needs genuine progression (L2) or graph proximity (L3) to pass.
    """
    kind, _, value = token.partition(":")
    lowered = value.strip().lower()
    if kind in _SUFFIX_KINDS:
        return ("host", lowered.split(".", 1)[0])
    if kind == "user":
        return ("user", lowered.split("@", 1)[0].rsplit("\\", 1)[-1])
    return (kind, lowered)


def _is_ambient_token(token: str, weight: int) -> bool:
    """True when the key is a bare ambient value (weak, and a name-space kind).

    Weakness is how ``extract_keys`` records ambience: a hub host, a
    high-frequency account and a well-known or tenant-wide domain are all
    downgraded to ``WEIGHT_WEAK``. Alias twins are capped at medium and therefore
    stay informative — they are the same fact as a real entity, not background.
    """
    if weight > WEIGHT_WEAK:
        return False
    kind, _, _ = token.partition(":")
    return kind in AMBIENT_KINDS


def _phase_rank(observation: Observation) -> int | None:
    ranks = [_PHASE_ORDER[p] for p in observation.kill_chain if p in _PHASE_ORDER]
    return min(ranks) if ranks else None


def _l2(a: Observation, b: Observation, l1: int) -> int:
    """Story overlap or kill-chain progression."""
    if l1 < 2:
        return 0
    if set(a.stories) & set(b.stories):
        return 1
    rank_a, rank_b = _phase_rank(a), _phase_rank(b)
    if rank_a is not None and rank_b is not None and rank_a != rank_b:
        return 1
    # Distinct techniques on a shared entity is the weakest form of progression:
    # only counts when MITRE data exists on both sides.
    if a.techniques and b.techniques and set(a.techniques) != set(b.techniques):
        return 1
    return 0


def score_pair(
    a: Observation,
    b: Observation,
    *,
    graph: TenantGraph | None = None,
    role_overrides: Mapping[str, str] | None = None,
) -> PairScore:
    """Score two observations. ``role_overrides`` is accepted for signature
    stability but roles are already resolved onto each observation."""
    del role_overrides
    shared_tokens = a.tokens & b.tokens
    weights = {k.token: k.weight for k in a.keys}
    weights.update({k.token: k.weight for k in b.keys})
    # One slot per real value: the strongest alias in the group counts, the
    # rest bridge rather than add (see ``_alias_group``). A group is ambient only
    # when *every* token in it is ambient, so an alias twin can never launder a
    # shared AD domain into evidence.
    groups: dict[tuple[str, str], int] = {}
    ambient: dict[tuple[str, str], bool] = {}
    for token in shared_tokens:
        weight = weights.get(token, 0)
        group = _alias_group(token)
        is_ambient = _is_ambient_token(token, weight)
        if group not in groups:
            groups[group] = weight
            ambient[group] = is_ambient
            continue
        groups[group] = max(groups[group], weight)
        ambient[group] = ambient[group] and is_ambient
    # Ambient values contribute nothing. Counting them as 1 each let a
    # tenant-wide domain lift a borderline pair (2) over θ=3, so it still widened
    # campaigns even when it could not form one: on the 166-notable corpus,
    # adding one tenant domain to every payload pulled 8 extra alerts into
    # existing cases. Suppressed entirely, that run is identical to the run
    # without the domain.
    l1 = min(sum(weight for group, weight in groups.items() if not ambient[group]), L1_CAP)

    veto: str | None = None
    vetoed_by: tuple[str, ...] = ()
    if roles_conflict(a.role, b.role):
        veto = f"distinct_c2_framework:{a.role}|{b.role}"
    elif groups and not any(not flag for flag in ambient.values()):
        # Every shared value is ambient (hub hosts, high-frequency accounts,
        # well-known or tenant-wide domains). Three of those used to reach θ=3
        # on their own, which is how unrelated activity on one tenant domain
        # correlated itself into a case. A pair needs at least one key that is
        # actually specific to the two actions.
        # Report the *values* an operator can act on (``domain:corp.local``), not
        # the alias-group label the grouping uses internally (``host:corp``).
        # When this veto fires every group is ambient, so every shared token is
        # ambient too — the two views list the same evidence.
        vetoed_by = tuple(
            sorted(
                token
                for token in shared_tokens
                if _is_ambient_token(token, weights.get(token, 0))
            )
        )
        veto = "ambient_keys_only:" + ",".join(vetoed_by)

    # Doc §3.3: an alert whose time came from the alert clock (not the rule's
    # event time) cannot earn context points — a 2-hour-late notable must not
    # manufacture a kill-chain progression.
    time_ok = a.time_quality_ok and b.time_quality_ok
    l2 = _l2(a, b, l1) if time_ok else 0
    l3 = 0
    if time_ok and l1 >= 2 and graph is not None and graph.has_three_hop_path(a.key, b.key):
        l3 = 1

    return PairScore(
        left=a.key,
        right=b.key,
        l1=l1,
        l2=l2,
        l3=l3,
        shared=tuple(sorted(shared_tokens)),
        veto=veto,
        vetoed_by=vetoed_by,
    )


def score_matrix(
    observations: Sequence[Observation],
    *,
    graph: TenantGraph | None = None,
) -> list[PairScore]:
    """Score every unordered pair. O(n²) — callers batch per tenant/window."""
    index = graph or TenantGraph(observations)
    out: list[PairScore] = []
    for i, a in enumerate(observations):
        for b in observations[i + 1 :]:
            out.append(score_pair(a, b, graph=index))
    return out


@dataclass
class Component:
    """A connected group of observations that passed θ."""

    observation_keys: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    score: int = 0
    pairs: list[PairScore] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.alert_ids)


def connected_components(
    observations: Sequence[Observation],
    pairs: Iterable[PairScore],
    *,
    theta: int = THETA,
) -> list[Component]:
    """Union-find over pairs that pass θ; returns components with ≥2 alerts."""
    by_key = {o.key: o for o in observations}
    parent: dict[str, str] = {o.key: o.key for o in observations}
    best: dict[tuple[str, str], PairScore] = {}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    for pair in pairs:
        best[(pair.left, pair.right)] = pair
        if pair.veto or pair.total < theta:
            continue
        union(pair.left, pair.right)

    groups: dict[str, list[str]] = defaultdict(list)
    for key in by_key:
        groups[find(key)].append(key)

    components: list[Component] = []
    for members in groups.values():
        alerts: list[str] = []
        for key in members:
            for alert_id in by_key[key].alert_ids:
                if alert_id not in alerts:
                    alerts.append(alert_id)
        if len(members) < 2 or len(alerts) < 2:
            continue
        internal = [
            p
            for p in best.values()
            if p.left in members and p.right in members and not p.veto and p.total >= theta
        ]
        components.append(
            Component(
                observation_keys=sorted(members),
                alert_ids=alerts,
                score=max((p.total for p in internal), default=0),
                pairs=sorted(internal, key=lambda p: p.total, reverse=True),
            )
        )
    components.sort(key=lambda c: (-c.score, -c.size, c.observation_keys[:1]))
    return components


__all__ = [
    "Component",
    "L1_CAP",
    "PairScore",
    "THETA",
    "TenantGraph",
    "connected_components",
    "score_matrix",
    "score_pair",
]
