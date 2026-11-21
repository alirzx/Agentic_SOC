"""
Correlation engine candidate discovery: find connected components of alerts
that should become cases.

A candidate is a maximal connected component of alerts where:
- Each observation_signature groups semantically similar alerts
- Pairs of observations score ≥ θ (default 3) via L1+L2+L3
- Component size ≥ min_alerts (default 1)
- No alert is already a case member (correlation_state != 'cased')

Algorithm:
  1. Load context: fetch all alerts in tenant within lookback window
  2. Extract observations: group by observation_signature
  3. Score pairs: L1 (weighted shared keys), L2 (shared story / kill-chain step), L3 (graph proximity)
  4. Union-find: merge observations that score ≥ θ
  5. Canonicalise: winner per component
  6. Build payload: create candidate with all member alerts + metadata
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

#: Entity buckets a candidate can be filtered on. ``techniques`` is not an
#: entity, but analysts think of "has a MITRE technique" and "has a host" the
#: same way in a filter bar, so it shares the vocabulary.
ENTITY_KINDS: tuple[str, ...] = ("hosts", "users", "ips", "domains", "techniques")

#: Triage buckets a candidate can be filtered on. Keys are the auto-triage
#: verdicts (`services/agents/app/agents/dispositions.py`) plus ``unreviewed``
#: for alerts triage has not classified yet. The engine already drops auto-closed
#: FP/benign alerts before correlation, so those never reach a candidate; what an
#: analyst needs from the queue is "contains a confirmed TP" versus "not reviewed".
TRIAGE_FILTERS: tuple[str, ...] = (
    "true_positive",
    "likely_tp",
    "needs_review",
    "escalate",
    "unreviewed",
)

#: Sort orders the list endpoint accepts.
CANDIDATE_SORTS: tuple[str, ...] = ("score", "recent", "alerts")


def payload_rule_title(payload: Any, alert_title: Any = None) -> str | None:
    """Human-readable analytic title from an alert's ``llm_payload``.

    ``alerts.title`` is populated from the Splunk notable's ``search_name``
    (``ESCU - Windows Possible Credential Dumping - Rule``), so it duplicates
    ``alerts.search_name`` rather than naming the analytic. The payload keeps
    both: ``rule_name`` (the search name) and ``rule.title`` /
    ``rule.title_template`` (``Windows Possible Credential Dumping``). Surface
    the latter so the candidate view can show what fired, not just its search.

    Returns ``None`` when the payload is absent, malformed, or only repeats the
    value the caller already has — callers must not render a duplicate line.
    """

    if not isinstance(payload, dict):
        return None
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    candidates = (rule.get("title"), rule.get("title_template"), payload.get("title"))
    existing = {str(v).strip().lower() for v in (alert_title, payload.get("rule_name")) if v}
    for value in candidates:
        if not isinstance(value, str):
            continue
        # Rendered titles can contain newlines and padding from Splunk macros;
        # collapse them so the column stays one line.
        title = " ".join(value.split())
        if title and title.lower() not in existing:
            return title
    return None


@dataclass
class Observation:
    """A set of alerts with the same observation_signature"""
    signature: str
    alert_ids: list[str]
    role: str | None
    techniques: list[str]
    hosts: list[str]
    users: list[str]
    ips: list[str]
    domains: list[str]
    score: int = 0
    #: Weighted `kind:value` keys persisted by the correlation engine. Empty for
    #: rows written before migration 079 — callers fall back to the entity
    #: buckets in that case.
    tokens: set[str] = field(default_factory=set)
    #: Per-token weight exactly as the engine scored it (migration 080). Empty on
    #: older rows; see ``_FALLBACK_TOKEN_WEIGHTS``.
    token_weights: dict[str, int] = field(default_factory=dict)
    stories: list[str] = field(default_factory=list)
    kill_chain: list[str] = field(default_factory=list)
    first_seen: Any | None = None
    last_seen: Any | None = None
    time_quality: str | None = None


def drop_cased_observations(
    observations: dict[str, Observation], cased_alert_ids: Iterable[str]
) -> dict[str, Observation]:
    """Remove alerts that already belong to a case from the candidate ledger.

    ``correlation_observations`` rows are never deleted — the engine only claims
    alerts that are not yet cased — so a campaign that was just promoted kept
    showing up in the queue, and pressing "Create case" on it failed with
    ``alerts_already_cased``. Observations that still have un-cased alerts are
    kept with the remainder; those with none are dropped.

    Pure so the trimming rule is testable without a database session.
    """

    cased = {str(value) for value in cased_alert_ids}
    if not cased:
        return observations

    kept: dict[str, Observation] = {}
    for key, observation in observations.items():
        remaining = [alert_id for alert_id in observation.alert_ids if str(alert_id) not in cased]
        if not remaining:
            continue
        observation.alert_ids = remaining
        kept[key] = observation
    return kept


def keep_alert_ids(
    observations: dict[str, Observation], keep: Iterable[str]
) -> dict[str, Observation]:
    """Restrict the ledger to a given alert set (a case's evidence).

    The mirror image of :func:`drop_cased_observations`: a case's alerts are by
    definition cased, so discovery's own trimming would return nothing. Rows
    that lose every alert are dropped — an observation with no evidence left
    must not keep contributing its keys to the graph.

    Pure, and mutates the freshly-loaded rows like its sibling.
    """

    wanted = {str(value) for value in keep}
    if not wanted:
        return {}

    kept: dict[str, Observation] = {}
    for key, observation in observations.items():
        remaining = [alert_id for alert_id in observation.alert_ids if str(alert_id) in wanted]
        if not remaining:
            continue
        observation.alert_ids = remaining
        kept[key] = observation
    return kept


def entity_tokens(observation: Observation) -> set[str]:
    """Fallback ``kind:value`` tokens from the entity buckets.

    Only used for ledger rows written before migration 079 (no persisted
    ``tokens``): it misses hash and host-scoped process-guid keys, so L3 built
    from it can under-count. Prefer :func:`observation_tokens`.
    """

    tokens: set[str] = set()
    for bucket, kind in (
        ("hosts", "host"),
        ("users", "user"),
        ("ips", "ip"),
        ("domains", "domain"),
    ):
        for value in getattr(observation, bucket) or []:
            text = str(value).strip().lower()
            if text:
                tokens.add(f"{kind}:{text}")
    return tokens


#: L1 is a *weighted* sum, capped — vendored from
#: ``services/correlation/app/services/scoring.py`` so the candidate list cannot
#: drift from the engine that actually formed the components.
L1_CAP = 18

#: Kill-chain ladder, normalised to the Splunk/Lockheed phases. Identical to the
#: engine's ``_PHASE_ORDER``; unknown phase names are ignored, not guessed at.
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

#: Weight class per key kind for ledger rows written before migration 080 (no
#: ``token_weights``). ``extract_keys()`` derives the real weight from 30-day
#: frequency and a private/public IP split; these are its values for a value
#: seen once. Only rows the engine has not re-upserted yet are affected.
_FALLBACK_TOKEN_WEIGHTS: dict[str, int] = {
    "process_guid": 3,
    "hash": 3,
    "ip": 3,
    "domain": 2,
    "host": 2,
    "user": 2,
}


def fallback_token_weight(kind: str) -> int:
    return _FALLBACK_TOKEN_WEIGHTS.get(kind, 1)


def phase_rank(observation: Observation) -> int | None:
    """Lowest kill-chain rank on an observation, or ``None`` when unknown."""

    ranks = [_PHASE_ORDER[p] for p in observation.kill_chain if p in _PHASE_ORDER]
    return min(ranks) if ranks else None


def roles_conflict(role_a: str | None, role_b: str | None) -> bool:
    """Engine merge veto: distinct C2 frameworks never share a case.

    Copied from ``services/correlation/app/normalizer/roles.py``; the candidate
    list has to drop the same pairs the engine drops, otherwise it offers a
    candidate the engine deliberately refused to form.
    """

    if not role_a or not role_b:
        return False
    if role_a.startswith("c2:") and role_b.startswith("c2:"):
        return role_a != role_b
    return False


#: Kinds whose value can be *ambient* — seen so often in a tenant that sharing
#: it says nothing about two actions being related. Keep in sync with
#: ``services/correlation/app/services/scoring.py``.
AMBIENT_KINDS: frozenset[str] = frozenset({"host", "user", "domain"})

#: Weakest weight class in ``extract_keys``; ambience is recorded as weakness.
AMBIENT_WEIGHT = 1


def is_ambient_token(token: str, weight: int) -> bool:
    """True when a shared key is a bare ambient value (hub host, common domain)."""

    if weight > AMBIENT_WEIGHT:
        return False
    kind, _, _ = token.partition(":")
    return kind in AMBIENT_KINDS


def only_ambient_keys(obs_a: Observation, obs_b: Observation) -> bool:
    """True when every shared key is ambient, so the pair carries no evidence.

    The engine refuses to merge such a pair (``scoring.py`` vetoes
    ``ambient_keys_only``): hub hosts, high-frequency accounts and well-known or
    tenant-wide domains are the tenant's wallpaper, and three of them used to
    reach θ on their own. Deriving it from the persisted per-token weights means
    the candidate list rejects exactly the pairs the engine rejected.

    Ambient is decided per alias group: an ambient value whose alias twin is
    informative (or vice versa) is not ambient, because the group is only
    wallpaper when every token in it is.
    """

    shared = observation_tokens(obs_a) & observation_tokens(obs_b)
    if not shared:
        return False
    weights = dict(obs_a.token_weights)
    for token, weight in obs_b.token_weights.items():
        if weight > weights.get(token, 0):
            weights[token] = weight
    ambient: dict[tuple[str, str], bool] = {}
    for token in shared:
        kind, _, _ = token.partition(":")
        weight = weights.get(token) or fallback_token_weight(kind)
        group = _alias_group(token)
        flag = is_ambient_token(token, weight)
        ambient[group] = (ambient[group] and flag) if group in ambient else flag
    return not any(not flag for flag in ambient.values())


def observation_tokens(observation: Observation) -> set[str]:
    """The engine's own token set when the ledger has it, else a rebuild.

    The engine stores exactly ``{key.token for key in keys if key.weight > 0}``
    (migration 079), so using it makes L3 identical to the engine's. Older rows
    carry no tokens and fall back to :func:`entity_tokens`.
    """

    if observation.tokens:
        return {str(token) for token in observation.tokens}
    return entity_tokens(observation)


def _short_key(value: str, limit: int = 22) -> str:
    """Graph label for a key value (hashes and GUIDS are long)."""

    text = str(value)
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def observation_token_payload(observation: Observation) -> list[dict[str, Any]]:
    """Every key this observation contributed to scoring, strongest first.

    These are the engine's own tokens (``kind:value``, or ``kind:scope|value``
    for host-scoped process GUIDs) with the weight each one added to L1. The
    inspect view shows them on the observation and on its graph node so an
    analyst can see *which* values put two actions on the same campaign.

    Rows written before migration 080 carry no weights; those entries are
    flagged ``estimated`` instead of passing the per-kind default off as the
    engine's number.
    """

    payload: list[dict[str, Any]] = []
    for token in observation_tokens(observation):
        kind, _, value = token.partition(":")
        weight = observation.token_weights.get(token)
        payload.append(
            {
                "token": token,
                "kind": kind,
                "value": value,
                "weight": weight if weight is not None else fallback_token_weight(kind),
                "estimated": weight is None,
            }
        )
    payload.sort(key=lambda item: (-int(item["weight"]), str(item["token"])))
    return payload


#: Token kind → (node kind, edge kind) for the observation graph. Entity kinds
#: get the familiar shapes; every other scored key becomes a `key` node so
#: nothing the engine scored on is invisible.
_OBSERVATION_TOKEN_NODES: dict[str, tuple[str, str]] = {
    "host": ("host", "OBSERVED_ON"),
    "user": ("user", "INVOLVES_USER"),
    "ip": ("ip", "USES_IP"),
    "domain": ("domain", "QUERIED_DOMAIN"),
    "hash": ("hash", "MATCHES_HASH"),
    "process_guid": ("process_guid", "INVOKES_PROCESS"),
}

#: An observation with more endpoints than this is projected as a spanning tree
#: rather than a complete graph: 20 endpoints would otherwise emit 190 edges.
MAX_OBSERVATION_EDGE_ENDPOINTS = 4


def observation_endpoint_id(token: Mapping[str, Any]) -> str | None:
    """Node id an observation token can be drawn between, if it has one.

    Only entity kinds are edges' endpoints; a `key:` pseudo token (an
    unroutable kind) has no node identity of its own and stays a key node.
    """

    mapped = _OBSERVATION_TOKEN_NODES.get(str(token.get("kind")))
    if mapped is None:
        return None
    return f"{mapped[0]}:{token.get('value')}"


def observation_endpoints(tokens: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The entities an observation can be drawn between, strongest first.

    ``observation_token_payload`` already sorts by the weight the token added to
    L1, so the first endpoint is the observation's strongest evidence.
    """

    endpoints: list[dict[str, Any]] = []
    seen: set[str] = set()
    for token in tokens:
        node_id = observation_endpoint_id(token)
        if node_id is None or node_id in seen:
            continue
        seen.add(node_id)
        endpoints.append({**dict(token), "node_id": node_id})
    return endpoints


def _spanning_tree_pairs(endpoints: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Prim over endpoint weights: connect the strongest evidence with k-1 edges.

    Deterministic: the highest combined weight wins, ties fall back to the
    endpoint order (already weight-sorted), so the same evidence always draws
    the same shape.
    """

    if len(endpoints) < 2:
        return []
    connected = [endpoints[0]]
    remaining = list(endpoints[1:])
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    while remaining:
        best_score = -1
        best_pair: tuple[dict[str, Any], dict[str, Any]] | None = None
        for node in remaining:
            for anchor in connected:
                score = int(anchor.get("weight") or 0) + int(node.get("weight") or 0)
                if score > best_score:
                    best_score = score
                    best_pair = (anchor, node)
        assert best_pair is not None  # remaining is non-empty and connected is not
        pairs.append(best_pair)
        connected.append(best_pair[1])
        remaining.remove(best_pair[1])
    return pairs


def observation_projection_pairs(
    endpoints: Sequence[dict[str, Any]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Which entity pairs one observation contributes an edge between.

    Up to :data:`MAX_OBSERVATION_EDGE_ENDPOINTS` endpoints → every pair (3 → 3
    edges, 4 → 6). Wider than that → a spanning tree, so a 20-endpoint
    observation cannot emit 190 edges nobody can read.
    """

    if len(endpoints) < 2:
        return []
    if len(endpoints) <= MAX_OBSERVATION_EDGE_ENDPOINTS:
        return [
            (endpoints[i], endpoints[j])
            for i in range(len(endpoints))
            for j in range(i + 1, len(endpoints))
        ]
    return _spanning_tree_pairs(list(endpoints))


def correlation_anchor(
    left: Sequence[Mapping[str, Any]], right: Sequence[Mapping[str, Any]]
) -> tuple[str, str] | None:
    """Re-anchor an observation↔observation pair onto two distinct entities.

    With observations projected as edges there is no observation node to hang a
    `CORRELATION` edge on, so the pair is drawn between the strongest entity of
    each side *that the other side does not also have* (the shared values are
    what produced the score, so they are already one node). `None` means the two
    actions touch exactly the same single entity and no pair can be drawn; the
    pair scores still list the link.
    """

    if not left or not right:
        return None
    right_ids = {str(endpoint.get("node_id")) for endpoint in right}
    left_ids = {str(endpoint.get("node_id")) for endpoint in left}
    left_only = [endpoint for endpoint in left if str(endpoint.get("node_id")) not in right_ids]
    right_only = [endpoint for endpoint in right if str(endpoint.get("node_id")) not in left_ids]
    source = str((left_only or list(left))[0].get("node_id"))
    target = str((right_only or list(right))[0].get("node_id"))
    if not source or not target or source == target:
        return None
    return source, target


def _alias_group(token: str) -> tuple[str, str]:
    """Collapse alias representations of ONE entity into a single L1 slot.

    ``extract_keys`` emits several keys for the same real value so evidence
    written by different rules can meet (an FQDN host, its short name, the
    domain twin of the FQDN, and a user's UPN vs bare account name). Summing
    them made one shared host worth 6 instead of the documented 2.

    Keep in sync with ``services/correlation/app/services/scoring.py``.
    """

    kind, _, value = token.partition(":")
    lowered = value.strip().lower()
    if kind in {"host", "domain"}:
        return ("host", lowered.split(".", 1)[0])
    if kind == "user":
        return ("user", lowered.split("@", 1)[0].rsplit("\\", 1)[-1])
    return (kind, lowered)


class TokenIndex:
    """Observation → shared token → observation index for L3.

    Same question as the engine's ``TenantGraph``: is there a 3-hop path
    A–K1–C–K2–B through a *third* observation using two distinct keys? A direct
    shared key is already L1, so counting it again would hand every overlapping
    pair a free point and effectively lower θ.
    """

    def __init__(self, observations: dict[str, Observation]) -> None:
        self._tokens: dict[str, set[str]] = {
            key: observation_tokens(observation) for key, observation in observations.items()
        }
        self._index: dict[str, set[str]] = {}
        for key, tokens in self._tokens.items():
            for token in tokens:
                self._index.setdefault(token, set()).add(key)

    def three_hop_path(self, left: str, right: str) -> dict[str, str] | None:
        """Explain the L3 path, or ``None`` when there is none.

        Returns the *middle* observation and the two distinct keys that make the
        path real, so the inspector can say "these two actions sit on the same
        intrusion because both touch C — through host:win-dc and user:bob"
        instead of showing a bare ``L3 = 1``.
        """

        tokens_left = self._tokens.get(left, set())
        tokens_right = self._tokens.get(right, set())
        if not tokens_left or not tokens_right:
            return None

        candidates: set[str] = set()
        for token in tokens_left | tokens_right:
            candidates |= self._index.get(token, set())
        candidates.discard(left)
        candidates.discard(right)

        for node in sorted(candidates):
            tokens_node = self._tokens.get(node, set())
            common_left = tokens_left & tokens_node
            common_right = tokens_right & tokens_node
            if not common_left or not common_right:
                continue
            only_left = common_left - common_right
            only_right = common_right - common_left
            if only_left or only_right:
                return {
                    "via": node,
                    # One key per side; fall back to the shared side when a key
                    # is common to all three (still a distinct-key path).
                    "left_token": sorted(only_left or common_left)[0],
                    "right_token": sorted(only_right or common_right)[0],
                }
        return None

    def has_three_hop_path(self, left: str, right: str) -> bool:
        return self.three_hop_path(left, right) is not None


class UnionFind:
    """Standard union-find with path compression and union by rank"""

    def __init__(self, items: list[str]) -> None:
        self.parent = {item: item for item in items}
        self.rank = dict.fromkeys(items, 0)

    def find(self, x: str) -> str:
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: str, y: str) -> None:
        px, py = self.find(x), self.find(y)
        if px == py:
            return
        if self.rank[px] < self.rank[py]:
            px, py = py, px
        self.parent[py] = px
        if self.rank[px] == self.rank[py]:
            self.rank[px] += 1

    def components(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        for item in self.parent:
            root = self.find(item)
            if root not in groups:
                groups[root] = []
            groups[root].append(item)
        return groups


class CandidateDiscovery:
    """Find candidates (connected components) for case creation"""

    def __init__(
        self,
        session: AsyncSession,
        *,
        theta: int = 3,
        lookback_hours: int = 72,
        min_alerts: int = 1,
    ) -> None:
        self.session = session
        self.theta = theta
        self.lookback_hours = lookback_hours
        self.min_alerts = min_alerts

        # Per-pair score breakdown for the last scored pair-set. Populated by
        # ``_score_pairs`` so the inspect payload can explain *why* two
        # observations were merged — the exact L1/L2/L3 split the engine used.
        self.pair_details: dict[tuple[str, str], dict[str, Any]] = {}

    async def run(
        self,
        tenant_id: str,
        *,
        include_graph: bool = False,
        observation_mode: str = "node",
    ) -> list[dict[str, Any]]:
        """
        Discover all candidates for a tenant.

        Returns list of candidates, each with:
        - candidate_key: unique identifier
        - campaign_theme: human-readable theme
        - score: aggregated L1+L2+L3
        - alert_ids: all members
        - entities: grouped by kind
        - techniques: MITRE ATT&CK techniques
        - time_first, time_last: timestamp span
        """

        # 1. Load observations from correlation_observations table
        observations = await self._load_observations(tenant_id)
        observations = await self._drop_cased_alerts(tenant_id, observations)
        if len(observations) < 2:
            return []

        # 2. Build score matrix: pair every observation with every other
        scores = self._score_pairs(observations)

        # 3. Union-find: merge observations that pass θ threshold
        uf = UnionFind(list(observations.keys()))
        for (obs_a, obs_b), score in scores.items():
            if score >= self.theta:
                uf.union(obs_a, obs_b)

        # 4. Build candidates from components
        candidates: list[dict[str, Any]] = []
        for _root, members in uf.components().items():
            if len(members) < 2:
                continue
            # A campaign needs two pieces of evidence, not two ledger rows about
            # the same alert (see the identical-alert-set skip in
            # ``_score_pairs``). The correlation engine refuses to promote a
            # single-alert component; discovery must not offer it either.
            seen_alerts = {str(a) for m in members for a in observations[m].alert_ids}
            if len(seen_alerts) < 2:
                continue
            candidate = await self._assemble_component(
                tenant_id,
                members,
                observations,
                scores,
                include_graph=include_graph,
                require_theta=True,
                observation_mode=observation_mode,
            )
            if candidate is not None:
                candidates.append(candidate)

        # Strongest link first, then the biggest campaign. Sorting on the
        # evidence total put a 100-alert loose component above a tight 6-alert
        # one, which is the opposite of what a triage queue should show.
        return sorted(
            candidates,
            key=lambda c: (c["score"], c["alert_count"]),
            reverse=True,
        )

    async def describe_alert_set(
        self, tenant_id: str, alert_ids: Iterable[str], *, observation_mode: str = "node"
    ) -> dict[str, Any] | None:
        """Re-inspect an arbitrary alert set as one campaign.

        Candidates are *discovered* (un-cased, θ-gated). A case's evidence is
        the opposite: already cased, and possibly scored below θ once noise has
        been excluded. This resolves the ledger rows that still cover the given
        alerts, re-scores the surviving pairs and returns the same inspect
        payload the candidate modal renders — so the case view and the
        candidate view are literally the same explanation, not two
        implementations that drift.

        Returns ``None`` when nothing is left to describe; callers show an empty
        graph rather than inventing one.
        """

        wanted = {str(value) for value in alert_ids if str(value).strip()}
        if not wanted:
            return None

        observations = await self._load_observations(tenant_id, lookback_hours=0)
        observations = keep_alert_ids(observations, wanted)
        if not observations:
            return None

        scores = self._score_pairs(observations)
        members = sorted(observations.keys())
        # An excluded alert must not linger in the output: alert ids are trimmed
        # to the requested set, not to whatever the ledger row still lists.
        for observation in observations.values():
            observation.alert_ids = [
                alert_id for alert_id in observation.alert_ids if str(alert_id) in wanted
            ]
        return await self._assemble_component(
            tenant_id,
            members,
            observations,
            scores,
            include_graph=True,
            require_theta=False,
            observation_mode=observation_mode,
        )

    async def _assemble_component(
        self,
        tenant_id: str,
        members: list[str],
        observations: dict[str, Observation],
        scores: dict[tuple[str, str], int],
        *,
        include_graph: bool,
        require_theta: bool,
        observation_mode: str = "node",
    ) -> dict[str, Any] | None:
        """Turn one set of observations into a candidate payload.

        Shared by discovery (θ-gated, un-cased alerts) and by
        :meth:`describe_alert_set` (a case's evidence, no gate) so both produce
        byte-identical structures.
        """

        all_alert_ids: set[str] = set()
        all_entities: dict[str, set[str]] = {}
        all_techniques: set[str] = set()

        for sig in members:
            obs = observations[sig]
            all_alert_ids.update(obs.alert_ids)
            all_techniques.update(obs.techniques or [])

            # Aggregate entities
            for kind in ["hosts", "users", "ips", "domains"]:
                if kind not in all_entities:
                    all_entities[kind] = set()
                all_entities[kind].update(getattr(obs, kind) or [])

        # Query alert table to get timestamps and severity
        alert_data = await self._load_alert_data(tenant_id, list(all_alert_ids))

        if not alert_data:
            return None

        # Two different numbers, and conflating them made the list filter
        # meaningless: ``peak_score`` is the strongest single pair link (the
        # number that is compared to θ), while ``evidence_score`` is the sum
        # over every scored pair and therefore grows with candidate size. A
        # 100-alert campaign reached 3000+ on the old "score" and every
        # score filter above θ let it through.
        pair_scores = [
            scores.get((members[i], members[j]), 0)
            for i in range(len(members))
            for j in range(i + 1, len(members))
        ]
        peak_score = max(pair_scores, default=0)
        evidence_score = sum(pair_scores)
        if require_theta and peak_score < self.theta:
            return None

        # The key must be stable across cycles *and* unique per component.
        # Truncating the union-find root was neither: observation keys share
        # long prefixes (`entity|…`), so two different components produced
        # "component-entity|T" and the UI (and the detail lookup) could not
        # tell them apart. A hash of the member set is deterministic and
        # collision-free in practice.
        fingerprint = hashlib.sha1("|".join(sorted(members)).encode("utf-8")).hexdigest()[:12]
        candidate: dict[str, Any] = {
            "candidate_key": f"component-{fingerprint}",
            "campaign_theme": self._theme_from_entities(all_entities, all_techniques),
            "score": peak_score,
            "evidence_score": evidence_score,
            "pair_count": sum(1 for value in pair_scores if value > 0),
            "alert_count": len(all_alert_ids),
            "alert_ids": sorted(str(alert_id) for alert_id in all_alert_ids),
            "entities": {k: sorted(str(v) for v in values) for k, values in all_entities.items()},
            "techniques": sorted(str(technique) for technique in all_techniques),
            # Span on *event* time, not ingestion time: backfilling a
            # campaign in one batch makes created_at identical for every
            # alert, which used to render every candidate as a "0m" blip.
            "time_first": min(a.get("event_time") or a["created_at"] for a in alert_data),
            "time_last": max(a.get("event_time") or a["created_at"] for a in alert_data),
            "severity": self._max_severity([a["severity"] for a in alert_data]),
            "triage": self._triage_summary(alert_data),
        }

        if include_graph:
            candidate.update(
                self._describe_component(
                    members,
                    observations,
                    alert_data,
                    evidence_score,
                    observation_mode=observation_mode,
                )
            )

        return candidate

    async def _drop_cased_alerts(
        self, tenant_id: str, observations: dict[str, Observation]
    ) -> dict[str, Observation]:
        """Drop alerts already attached to a case (see :func:`drop_cased_observations`).

    ``deduplicated_into_case`` counts as consumed as well. Those alerts are the
    soft-dedup losers of a campaign the engine already cased: they carry no
    ``case_id`` of their own, so leaving them in discovery made every run offer
    the same campaign again as a brand-new candidate (86 alerts at score 5 next
    to the 15-alert case they had just produced). They stay evidence *of that
    case*; they are not new evidence.

    ``funnel_stage='deduplicated'`` is consumed on its own, whatever the
    correlation columns say. Soft-dedup clears ``case_id`` and the correlation
    engine rewrites ``correlation_state`` when it retries a stale claim, so the
    stage is the one marker that always survives; keying the decision on it too
    is what stops the all-in-one ghost candidate (61 dedup losers re-offered at
    score 6 after a claim-TTL cycle).
    """

        alert_ids = sorted({str(a) for obs in observations.values() for a in obs.alert_ids})
        if not alert_ids:
            return observations

        result = await self.session.execute(
            text(
                """
                SELECT id
                  FROM alerts
                 WHERE tenant_id = :tenant_id
                   AND id::text = ANY(:ids)
                   AND (
                         case_id IS NOT NULL
                      OR funnel_stage = 'deduplicated'
                      OR correlation_state IN ('cased', 'deduplicated_into_case')
                   )
                """
            ),
            {"tenant_id": tenant_id, "ids": alert_ids},
        )
        cased = {str(row[0]) for row in result.all()}
        return drop_cased_observations(observations, cased)

    async def _load_observations(
        self, tenant_id: str, *, lookback_hours: int | None = None
    ) -> dict[str, Observation]:
        """Fetch observations from the correlation ledger.

        ``lookback_hours`` defaults to the instance window. Pass ``0`` for no
        time limit — a case can be days old while its observations are older
        than the candidate queue's lookback, and its graph must still resolve.
        """

        hours = self.lookback_hours if lookback_hours is None else lookback_hours
        window = "" if hours == 0 else "AND created_at >= now() - make_interval(hours => :hours)"
        result = await self.session.execute(
            text(
                f"""
                SELECT
                    observation_key,
                    alert_ids,
                    role,
                    techniques,
                    hosts,
                    users,
                    ips,
                    domains,
                    tokens,
                    token_weights,
                    stories,
                    kill_chain,
                    first_seen,
                    last_seen,
                    time_quality
                FROM correlation_observations
                WHERE tenant_id = :tenant_id
                  {window}
                ORDER BY observation_key
                """
            ),
            {
                "tenant_id": tenant_id,
                "hours": hours,
            },
        )

        observations: dict[str, Observation] = {}
        for row in result.mappings():
            obs = Observation(
                signature=row["observation_key"],
                alert_ids=list(row["alert_ids"]) if row["alert_ids"] else [],
                role=row["role"],
                techniques=list(row["techniques"]) if row["techniques"] else [],
                hosts=list(row["hosts"]) if row["hosts"] else [],
                users=list(row["users"]) if row["users"] else [],
                ips=list(row["ips"]) if row["ips"] else [],
                domains=list(row["domains"]) if row["domains"] else [],
                tokens={str(token) for token in (row["tokens"] or [])},
                token_weights={
                    str(token): int(weight)
                    for token, weight in (row["token_weights"] or {}).items()
                },
                stories=[str(story) for story in (row["stories"] or [])],
                kill_chain=[str(phase) for phase in (row["kill_chain"] or [])],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                time_quality=row["time_quality"],
            )
            observations[row["observation_key"]] = obs

        return observations

    def _score_pairs(
        self, observations: dict[str, Observation]
    ) -> dict[tuple[str, str], int]:
        """Score every pair of observations: L1 + L2 + L3.

        Pure in-memory now: the ledger stores every input the engine scored with
        (migrations 079/080), so no alert-table queries are needed and the list
        cannot disagree with the engine that formed the components.
        """

        scores: dict[tuple[str, str], int] = {}
        self.pair_details = {}
        obs_keys = list(observations.keys())
        index = TokenIndex(observations)

        for i, key_a in enumerate(obs_keys):
            for key_b in obs_keys[i + 1 :]:
                obs_a = observations[key_a]
                obs_b = observations[key_b]

                # Two ledger rows can list exactly the same alert when its
                # observation signature moved between cycles (the ambient set
                # changes the strong-key digest). That is one action recorded
                # twice, not two correlated actions: scoring it invented a
                # 1-alert candidate at peak 4 next to the singleton it came from.
                if set(obs_a.alert_ids) == set(obs_b.alert_ids):
                    continue

                # L1: weighted sum over shared correlation keys
                l1, matched = self._score_l1(obs_a, obs_b)

                # Merge veto, same rule as the engine: two different C2
                # frameworks never share a case, however many keys they share.
                if l1 and roles_conflict(obs_a.role, obs_b.role):
                    continue

                # Same rule as the engine's ``ambient_keys_only`` veto: a pair
                # that shares nothing but hub hosts / common domains does not
                # become a candidate. Skipping it here keeps the list honest —
                # those pairs were never merged into a case.
                if only_ambient_keys(obs_a, obs_b):
                    continue

                # L2: shared analytic story / kill-chain progression
                time_ok_pair = (
                    obs_a.time_quality == "first_event"
                    and obs_b.time_quality == "first_event"
                )
                l2 = self._score_l2(obs_a, obs_b, l1) if time_ok_pair else 0

                # L3: graph proximity — 3-hop path through a third observation,
                # over the tokens the engine persisted in the ledger (migration
                # 079), so this reproduces the engine's own L3 exactly. Same
                # guards as scoring.py: both sides need rule event time (an
                # alert-clock fallback must not earn context points) and L3 only
                # upgrades an existing link, so L1 has to be meaningful first.
                # Keep the explanation, not just the point: the UI has to be
                # able to show which third observation and keys produced L3.
                l3_via = (
                    index.three_hop_path(key_a, key_b)
                    if time_ok_pair and l1 >= 2
                    else None
                )
                l3 = 1 if l3_via else 0

                total = l1 + l2 + l3
                if total > 0:
                    scores[(key_a, key_b)] = total
                    self.pair_details[(key_a, key_b)] = {
                        "l1": l1,
                        "l2": l2,
                        "l3": l3,
                        "l3_via": l3_via,
                        "score": total,
                        "matched": matched,
                    }

        return scores

    def _score_l1(
        self, obs_a: Observation, obs_b: Observation
    ) -> tuple[int, list[dict[str, Any]]]:
        """L1: sum of shared-key weights, capped at 18 — the engine's own formula.

        It used to add a flat 3/3/2/1 per entity *kind* and +1 for a matching
        role, which is not what formed the components: the engine sums the
        per-key weights (3 strong / 2 medium / 1 weak) over every shared key —
        including hashes and host-scoped process GUIDs — caps the total at 18 and
        grants nothing for a shared role. Three shared hubs therefore scored 9
        here and 3 in the engine.

        Returns the score plus the shared keys that produced it, so the inspect
        view can say "these two observations are one campaign because they share
        ``host:win-dc-01`` (3)" instead of showing a bare number.
        """

        shared = observation_tokens(obs_a) & observation_tokens(obs_b)
        if not shared:
            return 0, []

        # The engine keeps the strongest weight when a token appears on both
        # sides (Observation.merge), so the same here.
        weights = dict(obs_a.token_weights)
        for token, weight in obs_b.token_weights.items():
            if weight > weights.get(token, 0):
                weights[token] = weight

        total = 0
        matched: list[dict[str, Any]] = []
        counted: dict[tuple[str, str], int] = {}
        for token in sorted(shared):
            kind, _, value = token.partition(":")
            weight = weights.get(token) or fallback_token_weight(kind)
            if is_ambient_token(token, weight):
                # Ambient value (hub host, common or tenant-wide domain,
                # high-frequency account): listed so the analyst sees the link,
                # but worth nothing. The engine suppresses these entirely, so a
                # tenant-wide domain cannot lift a borderline pair over θ either.
                matched.append({"kind": kind, "value": value, "weight": 0, "ambient": True})
                continue
            group = _alias_group(token)
            if counted.get(group, 0) >= weight:
                # An alias twin of a value already counted — it explains why the
                # pair is linked, but adding its weight again would double one
                # fact (see ``_alias_group``). Shown with weight 0 so the
                # displayed weights still sum to L1 exactly.
                matched.append(
                    {"kind": kind, "value": value, "weight": 0, "alias_of": group[1]}
                )
                continue
            counted[group] = weight
            total += weight
            matched.append({"kind": kind, "value": value, "weight": weight})

        return min(total, L1_CAP), matched

    def _score_l2(self, obs_a: Observation, obs_b: Observation, l1: int) -> int:
        """L2: shared analytic story or kill-chain progression (0 or 1).

        Not temporal proximity. The engine never awards a point for two alerts
        merely happening close in time, and the old "+2 under an hour, +1 under
        four" rule inflated almost every pair. Three ordered tests, first hit
        wins, identical to ``scoring.py::_l2``:

        1. both observations belong to the same analytic story;
        2. both carry a kill-chain phase and the phases differ (the intrusion
           moved a step forward);
        3. both carry MITRE techniques and the technique sets differ (the weakest
           form of progression: same entity, a different action).
        """

        if l1 < 2:
            return 0
        if set(obs_a.stories) & set(obs_b.stories):
            return 1
        rank_a, rank_b = phase_rank(obs_a), phase_rank(obs_b)
        if rank_a is not None and rank_b is not None and rank_a != rank_b:
            return 1
        if (
            obs_a.techniques
            and obs_b.techniques
            and set(obs_a.techniques) != set(obs_b.techniques)
        ):
            return 1
        return 0

    def _triage_summary(self, alert_data: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        """Aggregate the auto-triage verdicts of a candidate's alerts.

        The correlation engine only *excludes* auto-closed alerts; it never used
        the remaining verdicts to rank or explain a candidate, so the queue could
        not answer "does this campaign contain a confirmed true positive?". This
        summary carries the verdict distribution and confidence band of the
        member alerts to the UI without touching the score the engine computed.

        Reads ``alerts.disposition`` / ``alerts.confidence`` at *display* time
        only: neither participates in L1/L2/L3 or in component formation.
        """

        verdicts: dict[str, int] = {}
        confidences: list[int] = []
        for alert in alert_data:
            verdict = str(alert.get("disposition") or "").strip().lower()
            if verdict:
                verdicts[verdict] = verdicts.get(verdict, 0) + 1
            confidence = alert.get("confidence")
            if isinstance(confidence, (int, float)):
                confidences.append(int(confidence))

        reviewed = sum(verdicts.values())
        summary: dict[str, Any] = {group: verdicts.get(group, 0) for group in TRIAGE_FILTERS}
        summary.update(
            {
                "verdicts": dict(sorted(verdicts.items(), key=lambda item: -item[1])),
                "reviewed": reviewed,
                # ``unreviewed`` counts alerts triage has not classified yet; it is
                # also a filter bucket, so it must not be overwritten above.
                "unreviewed": max(0, len(alert_data) - reviewed),
                "max_confidence": max(confidences) if confidences else None,
                "avg_confidence": (
                    round(sum(confidences) / len(confidences)) if confidences else None
                ),
            }
        )
        return summary

    async def _load_alert_data(
        self, tenant_id: str, alert_ids: list[str]
    ) -> list[dict[str, Any]]:
        """Fetch the alert fields a candidate view needs.

        Callers read the optional keys defensively (`.get`) because tests and
        older queries may return only id/created_at/severity.
        """

        if not alert_ids:
            return []

        result = await self.session.execute(
            text(
                """
                SELECT id, created_at, event_time, severity, title,
                       mitre_techniques, llm_payload, disposition, confidence,
                       funnel_stage, correlation_state, occurrence_count
                FROM alerts
                WHERE tenant_id = :tenant_id AND id = ANY(:ids)
                ORDER BY created_at
                """
            ),
            {"tenant_id": tenant_id, "ids": alert_ids},
        )

        return [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "severity": row["severity"],
                "event_time": row["event_time"],
                "title": row["title"],
                "payload_title": payload_rule_title(row["llm_payload"], row["title"]),
                "mitre_techniques": row["mitre_techniques"],
                # Display-only: the auto-triage verdict/confidence the engine does
                # not score with (see ``_triage_summary``).
                "disposition": row["disposition"],
                "confidence": row["confidence"],
                # Soft-dedup evidence: these rows stay case witnesses but are
                # hidden from the alerts workbench, so the inspect view has to
                # label them explicitly or they read as ordinary alerts.
                "funnel_stage": row["funnel_stage"],
                "correlation_state": row["correlation_state"],
                "occurrence_count": row["occurrence_count"],
            }
            for row in result.mappings()
        ]

    # ── Inspect payload (graph + timeline + score explanations) ───────────

    def _describe_component(
        self,
        members: list[str],
        observations: dict[str, Observation],
        alert_data: list[dict[str, Any]],
        evidence_score: int,
        *,
        observation_mode: str = "node",
    ) -> dict[str, Any]:
        """Build everything the inspect view needs to *show* the correlation.

        Three artefacts, all derived from the same scored pair set that formed
        the component (no re-scoring, no extra queries):

        - ``observations``: the atomic actions (nodes of the campaign)
        - ``pair_scores``: why each pair was joined, with the shared values
        - ``graph``: ready-to-render nodes/edges (observations + entities)
        - ``timeline``: alerts in time order with their observation attached
        """

        member_set = set(members)

        observation_payload: list[dict[str, Any]] = []
        alert_to_observation: dict[str, str] = {}
        for key in members:
            obs = observations[key]
            alert_ids = [str(alert_id) for alert_id in obs.alert_ids]
            for alert_id in alert_ids:
                alert_to_observation[alert_id] = key
            observation_payload.append(
                {
                    "observation_key": key,
                    "role": obs.role,
                    "techniques": [str(t) for t in (obs.techniques or [])],
                    "hosts": [str(v) for v in (obs.hosts or [])],
                    "users": [str(v) for v in (obs.users or [])],
                    "ips": [str(v) for v in (obs.ips or [])],
                    "domains": [str(v) for v in (obs.domains or [])],
                    "alert_ids": alert_ids,
                    "alert_count": len(alert_ids),
                    "first_seen": obs.first_seen,
                    "last_seen": obs.last_seen,
                    "time_quality": obs.time_quality,
                    # The engine already scored with these (L2 reads both); the
                    # inspect view needs them to show the campaign's ATT&CK
                    # stories and kill-chain coverage instead of only counts.
                    "stories": [str(story) for story in (obs.stories or [])],
                    "kill_chain": [str(phase) for phase in (obs.kill_chain or [])],
                    "tokens": observation_token_payload(obs),
                }
            )

        pair_payload: list[dict[str, Any]] = [
            {
                "source": key_a,
                "target": key_b,
                "l1": detail["l1"],
                "l2": detail["l2"],
                "l3": detail["l3"],
                "score": detail["score"],
                "matched": list(detail.get("matched") or []),
                "l3_via": detail.get("l3_via"),
                "threshold_met": detail["score"] >= self.theta,
            }
            for (key_a, key_b), detail in self.pair_details.items()
            if key_a in member_set and key_b in member_set
        ]
        pair_payload.sort(key=lambda pair: pair["score"], reverse=True)

        timeline: list[dict[str, Any]] = []
        for alert in alert_data:
            alert_id = str(alert.get("id"))
            timeline.append(
                {
                    "alert_id": alert_id,
                    "observation_key": alert_to_observation.get(alert_id),
                    "title": alert.get("title"),
                    # Analytic name from llm_payload.rule.title — distinct from
                    # alerts.title, which mirrors the search_name.
                    "payload_title": alert.get("payload_title"),
                    "severity": alert.get("severity"),
                    "time": alert.get("event_time") or alert.get("created_at"),
                    "techniques": [
                        str(t) for t in (alert.get("mitre_techniques") or [])
                    ],
                    "funnel_stage": alert.get("funnel_stage"),
                    "deduplicated": alert.get("funnel_stage") == "deduplicated",
                    "occurrence_count": alert.get("occurrence_count"),
                }
            )
        # Deterministic order even when a row's time is NULL.
        timeline.sort(key=lambda event: str(event.get("time") or ""))

        return {
            "observations": observation_payload,
            "pair_scores": pair_payload,
            "timeline": timeline,
            "graph": self._build_graph(
                members, observations, pair_payload, observation_mode=observation_mode
            ),
            "score_breakdown": {
                "l1": sum(pair["l1"] for pair in pair_payload),
                "l2": sum(pair["l2"] for pair in pair_payload),
                "l3": sum(pair["l3"] for pair in pair_payload),
                "theta": self.theta,
                # Strongest link (the θ comparison) and the evidence total. The
                # inspect view shows both and never calls one of them "score".
                "peak_score": pair_payload[0]["score"] if pair_payload else 0,
                "component_score": evidence_score,
            },
        }

    def _build_graph(
        self,
        members: list[str],
        observations: dict[str, Observation],
        pairs: list[dict[str, Any]],
        *,
        observation_mode: str = "node",
    ) -> dict[str, Any]:
        """Turn the component into cytoscape-ready nodes and edges.

        Observations are the attacker actions; the keys they contributed
        (host/user/ip/domain, plus the hashes and host-scoped process GUIDs the
        entity buckets cannot express) are the substrate that makes them one
        campaign. Correlation edges carry the pair score so the UI can draw
        above-θ links solid and near-miss links dashed; key edges carry the
        weight that key added to L1 — the analyst can see exactly why the
        grouping happened.

        ``observation_mode`` selects the projection:

        * ``node`` — an observation is a hub node with its entities as leaves
          (the historical shape).
        * ``edge`` — an observation with two or more endpoints is drawn as the
          relation it actually is: a role-labelled edge between those entities.
          An observation with fewer than two endpoints keeps its node (there is
          no edge to draw), and every entity it touched is still a real node.
        """

        node_mode = observation_mode != "edge"
        token_edges = _OBSERVATION_TOKEN_NODES

        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        #: Observation key → entity endpoints, strongest first. Correlation
        #: pairs are re-anchored on these when there are no observation nodes.
        endpoints_by_observation: dict[str, list[dict[str, Any]]] = {}
        #: Unordered entity pair → the accumulated role edge between them.
        role_edges: dict[tuple[str, str], dict[str, Any]] = {}

        def ensure_entity_node(token: dict[str, Any], entity_id: str, entity_kind: str) -> None:
            entity_node = nodes.get(entity_id)
            if entity_node is None:
                nodes[entity_id] = {
                    "id": entity_id,
                    "kind": entity_kind,
                    "label": _short_key(str(token["value"])),
                    # Full key, so the inspector can show the hash or GUID
                    # the label had to truncate.
                    "token": str(token["token"]),
                    "alert_count": 0,
                }
            else:
                entity_node["alert_count"] = int(entity_node["alert_count"]) + 1

        for key in members:
            obs = observations[key]
            node_id = f"obs:{key}"
            label = obs.role or (obs.techniques[0] if obs.techniques else "observation")
            tokens = observation_token_payload(obs)
            endpoints = observation_endpoints(tokens)
            endpoints_by_observation[key] = endpoints
            keep_node = node_mode or len(endpoints) < 2

            if keep_node:
                nodes[node_id] = {
                    "id": node_id,
                    "kind": "observation",
                    "label": str(label),
                    "alert_count": len(obs.alert_ids or []),
                    "techniques": [str(t) for t in (obs.techniques or [])],
                    "kill_chain": [str(phase) for phase in (obs.kill_chain or [])],
                    "observation_key": key,
                }

            linked: set[str] = set()
            for token in tokens:
                kind = str(token["kind"])
                entity_kind, edge_kind = token_edges.get(kind, ("key", "CONTRIBUTES_KEY"))
                # Entity nodes are keyed by kind:value so the same host shared by
                # two observations is one node; other keys keep their full token
                # (a hash can appear under two host-scoped GUIDS).
                entity_id = observation_endpoint_id(token) or f"key:{token['token']}"
                if entity_id in linked:
                    continue
                linked.add(entity_id)
                ensure_entity_node(token, entity_id, entity_kind)

                if keep_node:
                    edges.append(
                        {
                            "id": f"{node_id}->{entity_id}",
                            "source": node_id,
                            "target": entity_id,
                            "kind": edge_kind,
                            # The weight this key added to L1 (3 strong / 2 medium /
                            # 1 weak) — not a flat 1.
                            "weight": int(token["weight"]),
                            "threshold_met": True,
                            "token": str(token["token"]),
                        }
                    )
                elif entity_kind == "key" and endpoints:
                    # A key-only token has no entity endpoint of its own; anchor
                    # it on the observation's strongest endpoint so evidence the
                    # engine scored on never disappears from the canvas.
                    edges.append(
                        {
                            "id": f"{endpoints[0]['node_id']}->{entity_id}",
                            "source": str(endpoints[0]["node_id"]),
                            "target": entity_id,
                            "kind": edge_kind,
                            "weight": int(token["weight"]),
                            "threshold_met": True,
                            "token": str(token["token"]),
                        }
                    )

            if keep_node:
                continue

            role = str(obs.role or "general")
            alert_count = len(obs.alert_ids or [])
            for left, right in observation_projection_pairs(endpoints):
                pair_key = tuple(sorted((str(left["node_id"]), str(right["node_id"]))))
                entry = role_edges.get(pair_key)
                if entry is None:
                    entry = {
                        "id": f"role:{pair_key[0]}~{pair_key[1]}",
                        "source": pair_key[0],
                        "target": pair_key[1],
                        "kind": "OBSERVATION",
                        "role": role,
                        "roles": [],
                        "role_alerts": {},
                        "observations": [],
                        "count": 0,
                        "alert_count": 0,
                        "weight": 0,
                        "endpoint_count": len(endpoints),
                    }
                    role_edges[pair_key] = entry
                if role not in entry["roles"]:
                    entry["roles"].append(role)
                entry["role_alerts"][role] = int(entry["role_alerts"].get(role, 0)) + alert_count
                entry["observations"].append(key)
                entry["count"] += 1
                entry["alert_count"] += alert_count
                entry["weight"] += alert_count
                entry["endpoint_count"] = max(int(entry["endpoint_count"]), len(endpoints))

        for entry in role_edges.values():
            role_alerts: dict[str, int] = entry.pop("role_alerts")
            entry["roles"] = sorted(entry["roles"])
            # Dominant role colours the edge; the inspector lists the rest.
            entry["role"] = max(role_alerts.items(), key=lambda item: (item[1], item[0]))[0]
            entry["observations"] = sorted(set(entry["observations"]))
            edges.append(entry)

        for pair in pairs:
            if node_mode:
                source = f"obs:{pair['source']}"
                target = f"obs:{pair['target']}"
            else:
                anchor = correlation_anchor(
                    endpoints_by_observation.get(str(pair["source"]), []),
                    endpoints_by_observation.get(str(pair["target"]), []),
                )
                if anchor is None:
                    # Two actions that only touch the same single entity have no
                    # entity pair to draw; the pair scores still list the link.
                    continue
                source, target = anchor
            if source not in nodes or target not in nodes or source == target:
                continue
            edges.append(
                {
                    "id": f"{source}~{target}",
                    "source": source,
                    "target": target,
                    "kind": "CORRELATION",
                    "weight": pair["score"],
                    "threshold_met": pair["threshold_met"],
                    "matched": pair["matched"],
                    # Present only when this pair earned L3.
                    "l3_via": pair.get("l3_via"),
                }
            )

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "theta": self.theta,
            "observation_mode": "node" if node_mode else "edge",
        }

    def _theme_from_entities(
        self, entities: dict[str, set[str]], techniques: set[str]
    ) -> str:
        """Generate human-readable campaign theme from entities and techniques"""

        # Simple heuristic: check if it's LSASS, SMB, PowerShell, etc.
        theme_clues = {
            "T1003": "CREDENTIAL_THEFT",
            "T1021": "LATERAL_MOVEMENT",
            "T1566": "PHISHING",
            "T1046": "RECONNAISSANCE",
        }

        for technique, theme_suffix in theme_clues.items():
            if technique in techniques:
                return f"APT_ACTIVITY_{theme_suffix}"

        if entities.get("hosts") and len(entities.get("hosts", [])) > 1:
            return "MULTI_HOST_CORRELATION"

        if entities.get("users") and len(entities.get("users", [])) > 1:
            return "MULTI_USER_ACTIVITY"

        return "CORRELATED_ALERTS"

    def _max_severity(self, severities: list[str]) -> str:
        """Return highest severity from list"""

        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return max(severities, key=lambda s: severity_order.get(s, 0))


# ────────────────────────────────────────────────────────────────────────────
# Candidate filtering (pure — the list endpoint applies this after discovery)
# ────────────────────────────────────────────────────────────────────────────


def _as_datetime(value: Any) -> datetime | None:
    """Best-effort datetime for a candidate timestamp (aware, UTC by default)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if value in (None, ""):
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _search_blob(candidate: dict[str, Any]) -> str:
    """Everything a free-text query is allowed to match.

    Deliberately includes the entity *values* (host/user/IP/domain) and the
    MITRE techniques — an analyst searching ``win-dc-8537412`` or ``T1003`` is
    looking for the evidence that formed the group, not for a human title.
    """
    parts: list[str] = [
        str(candidate.get("candidate_key") or ""),
        str(candidate.get("campaign_theme") or ""),
    ]
    for values in (candidate.get("entities") or {}).values():
        parts.extend(str(value) for value in values)
    parts.extend(str(value) for value in candidate.get("techniques") or [])
    parts.extend(str(value) for value in candidate.get("alert_ids") or [])
    return "\n".join(parts).lower()


def filter_candidates(
    candidates: Sequence[dict[str, Any]],
    *,
    q: str | None = None,
    min_score: int = 3,
    severity: str | None = None,
    entity_kinds: Iterable[str] = (),
    triage: Iterable[str] = (),
    min_alerts: int | None = None,
    max_alerts: int | None = None,
    since: Any | None = None,
    until: Any | None = None,
    sort: str = "score",
) -> list[dict[str, Any]]:
    """Filter + order candidate dicts produced by :meth:`CandidateDiscovery.run`.

    Kept as a pure function so every filter rule is unit-testable without a
    database session. Semantics:

    * ``min_score`` compares the candidate's **peak pair score** (the strongest
      single link, i.e. the number θ gates), not the evidence total.
    * ``entity_kinds`` requires *all* named buckets to be non-empty.
    * ``triage`` requires *any* named verdict bucket to be non-empty — selecting
      "true positive" and "needs review" means "either", which is how analysts
      read a verdict facet. Values outside :data:`TRIAGE_FILTERS` are ignored.
    * ``since``/``until`` keep candidates whose event-time span **overlaps** the
      window — asking for "last 24 h" must not hide a campaign that started
      yesterday and is still active.
    * ``q`` is a case-insensitive substring match over the theme, entity values,
      techniques and alert ids.
    """
    needed = [kind for kind in entity_kinds if kind in ENTITY_KINDS]
    triage_needed = [bucket for bucket in triage if bucket in TRIAGE_FILTERS]
    needle = (q or "").strip().lower()
    start = _as_datetime(since)
    end = _as_datetime(until)
    severity_value = (severity or "").strip().lower()

    filtered: list[dict[str, Any]] = []
    for candidate in candidates:
        if int(candidate.get("score") or 0) < min_score:
            continue
        if severity_value and str(candidate.get("severity") or "").lower() != severity_value:
            continue

        if needed:
            entities = candidate.get("entities") or {}
            techniques = candidate.get("techniques") or []
            if any(
                not (techniques if kind == "techniques" else entities.get(kind) or [])
                for kind in needed
            ):
                continue

        if triage_needed:
            summary = candidate.get("triage") or {}
            if not any(int(summary.get(bucket) or 0) > 0 for bucket in triage_needed):
                continue

        count = int(candidate.get("alert_count") or 0)
        if min_alerts is not None and count < min_alerts:
            continue
        if max_alerts is not None and count > max_alerts:
            continue

        if start or end:
            first = _as_datetime(candidate.get("time_first"))
            last = _as_datetime(candidate.get("time_last")) or first
            if first is None or last is None:
                continue
            if start is not None and last < start:
                continue
            if end is not None and first > end:
                continue

        if needle and needle not in _search_blob(candidate):
            continue

        filtered.append(candidate)

    if sort == "recent":
        filtered.sort(key=lambda c: _as_datetime(c.get("time_last")) or datetime.min.replace(tzinfo=UTC), reverse=True)
    elif sort == "alerts":
        filtered.sort(key=lambda c: (int(c.get("alert_count") or 0), int(c.get("score") or 0)), reverse=True)
    else:
        filtered.sort(key=lambda c: (int(c.get("score") or 0), int(c.get("alert_count") or 0)), reverse=True)
    return filtered
