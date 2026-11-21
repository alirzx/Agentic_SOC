"""Pure entity extraction from the immutable ``alerts.llm_payload``.

This module is deliberately dependency-free (stdlib only) and side-effect free so
it can be exercised against real alert fixtures — including the 166-notable
corpus captured on 2026-11-08 — without a database, a graph, or a running
service. Everything downstream of it (observations, scoring, case creation)
consumes :class:`ExtractedKeys` and nothing else.

Design contract (see ``docs/plans/case/2.0.md`` §3):

* **`llm_payload` is the single source of truth.** No column, table, or
  intermediate ``related`` structure is consulted.
* **Type detection is value-shaped, not field-named.** A value that *is* an IP
  address is treated as an IP even if it arrived in ``user``. Field names are
  only used as a tie-breaker hint for values that are ambiguous by shape
  (``DEFENDER-01`` is a host; ``ADMINISTRATOR`` is a user).
* **Everything is normalised.** Lowercase, ``::ffff:`` stripped, trailing DNS
  dot stripped, GUID braces stripped, FQDN hosts also emit their short name.
* **Noise is filtered before scoring.** System SIDs, placeholders, loopback,
  CDN ranges, ``isatap``/``teredo`` tunnel artifacts and the documented
  ``system_processes`` never become keys.

The output keeps *provenance* (which dotted payload path produced a value) so an
analyst can always answer "why did these two alerts correlate?".
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

NORMALIZER_VERSION = "2.0.0"

# ── Key classes (doc §4.1) ──────────────────────────────────────────────────
WEIGHT_STRONG = 3
WEIGHT_MEDIUM = 2
WEIGHT_WEAK = 1

#: Kinds emitted by this module. ``process_guid`` is scoped to a host by the
#: observation layer, matching the doc's "process_guid inside a host" rule.
KINDS: tuple[str, ...] = ("host", "user", "ip", "domain", "hash", "process_guid")

# ── Calibration (doc §9) ────────────────────────────────────────────────────
T_USER_COMMON = 50  # freq/30d above which a user is "high frequency"
T_COMMON_DOMAIN = 100  # freq/30d above which a domain is "well known"
H_HUB = 500  # freq/30d above which a host is a hub

#: Relative ubiquity for domains (see ``frequency.common_values``). The absolute
#: thresholds above are per 30 days, but the engine scores a capped *window*: a
#: tenant-wide zone (the AD domain in a lab, the corporate parent domain in
#: production) can be on every alert of the window and never reach 100. A domain
#: on this share of the window's alerts is ambient, and two observations that
#: share nothing but ambient values are not a campaign.
DOMAIN_UBIQUITY_RATIO = 0.25
#: A ratio over a handful of alerts is noise, not a baseline.
MIN_RATIO_SAMPLE = 8

#: Placeholder tokens vendors use for "no value". Compared case-insensitively
#: after quote stripping.
PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "",
        "-",
        "_",
        "--",
        "n/a",
        "na",
        "none",
        "null",
        "nil",
        "unknown",
        "unspecified",
        "attacker",
        "victim",
        "user",
        "system",
        "localhost",
        "::1",
        "0.0.0.0",
        "*",
        "(null)",
        "n.a.",
        "tbd",
    }
)

#: Windows accounts that identify the OS itself, not a human or service owner.
SYSTEM_SIDS: frozenset[str] = frozenset(
    {
        "s-1-0-0",  # nobody
        "s-1-5-7",  # anonymous logon
        "s-1-5-18",  # SYSTEM
        "s-1-5-19",  # LOCAL SERVICE
        "s-1-5-20",  # NETWORK SERVICE
    }
)

#: Processes that are filtered before any scoring (doc §4.1 list). These are the
#: OS plumbing processes that appear as ``SourceImage`` on almost every Sysmon
#: event; treating them as an entity collapses unrelated incidents.
SYSTEM_PROCESSES: frozenset[str] = frozenset(
    {
        "svchost.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "wmiprvse.exe",
        "lsm.exe",
        "winlogon.exe",
        "spoolsv.exe",
        "smss.exe",
        "taskmgr.exe",
        "lsass.exe",
    }
)

#: Commercial / vendor infrastructure that is weak evidence on its own.
COMMON_DOMAINS: frozenset[str] = frozenset(
    {
        "3cx.com",
        "www.3cx.com",
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "office.com",
        "office365.com",
        "google.com",
        "gstatic.com",
        "cloudflare.com",
        "amazonaws.com",
        "azure.com",
        "akamai.net",
        "digicert.com",
        "verisign.com",
        "letsencrypt.org",
    }
)

#: Tunnel/virtual-adapter domains AD generates in bulk; zero signal.
TUNNEL_DOMAIN_PREFIXES: tuple[str, ...] = ("isatap.", "teredo.", "wpad.", "_ldap._tcp.")

#: Public CDN ranges whose IPs are shared by thousands of tenants. Kept small
#: and explicit — this is a hint, never a security boundary.
CDN_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "104.16.0.0/13",  # Cloudflare
        "104.24.0.0/14",
        "172.64.0.0/13",
        "162.158.0.0/15",
        "13.32.0.0/15",  # CloudFront
        "13.224.0.0/14",
        "151.101.0.0/16",  # Fastly
        "199.232.0.0/16",
    )
)

_GUID_RE = re.compile(
    r"^\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?$",
    re.IGNORECASE,
)
_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.IGNORECASE)
_SID_RE = re.compile(r"^s-1-\d+(?:-\d+)+$", re.IGNORECASE)
_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_USER_SHAPE_RE = re.compile(r"^[a-z0-9][a-z0-9._$@\\-]{1,63}$", re.IGNORECASE)
_EXE_RE = re.compile(r"\.(?:exe|dll|sys|scr|com)$", re.IGNORECASE)
_QUOTES = "\"'`\u2018\u2019\u201c\u201d"

# ── Field-name hints ────────────────────────────────────────────────────────
# Only consulted when the value's shape does not decide the kind.
#
# Two different "host" concepts live in a Splunk notable and conflating them is
# the single worst entity bug this engine has had (doc §1):
#
# * ``dest`` / ``dvc`` / ``dest_nt_host`` / ``Computer`` / ``hostname`` name the
#   machine the *event* happened on. That is the victim identity a case must be
#   keyed on, and it is what ``_EVENT_HOST_LEAVES`` records so the observation
#   layer can prefer it.
# * ``host`` (and ``splunk_server``/``index``) is Splunk index metadata: the
#   host that *stored* the notable. On an ES search head that is the indexer or
#   search head itself, which is identical for every alert and therefore links
#   unrelated incidents. Those are skipped for Splunk-shaped payloads.
_EVENT_HOST_LEAVES: frozenset[str] = frozenset(
    {
        "dest",
        "dest_host",
        "dest_nt_host",
        "destnthost",
        "dvc",
        "dvc_host",
        "dvchost",
        "hostname",
        "host_name",
        "computer",
        "computername",
        "workstation",
        "workstationname",
        "devicename",
        "devicehostname",
        "orig_host",
        "src_host",
        "src_nt_host",
        # ``entity`` / ``risk_object`` are the notable's own "who/what is this
        # about" fields; when the declared type is a host these are event hosts.
        "entity",
        "risk_object",
    }
)

#: Splunk metadata columns that name the indexer, never the victim.
_INDEXER_FIELDS: frozenset[str] = frozenset(
    {"splunk_server", "splunk_host", "splunk_indexer", "indexer", "server", "index"}
)

_HOST_HINTS: frozenset[str] = frozenset(
    {
        "dest",
        "dest_host",
        "dest_nt_host",
        "destnthost",
        "dvc",
        "dvc_host",
        "dvchost",
        "host",
        "hostname",
        "host_name",
        "computer",
        "computername",
        "workstation",
        "workstationname",
        "devicename",
        "devicehostname",
        "orig_host",
        "src_host",
        "src_nt_host",
    }
)
_USER_HINTS: frozenset[str] = frozenset(
    {
        "user",
        "username",
        "src_user",
        "srcuser",
        "userid",
        "user_id",
        "subjectusername",
        "targetusername",
        "account",
        "accountname",
        "owner",
        "securityid",
        "subjectusersid",
        "targetusersid",
    }
)
_IP_HINTS: frozenset[str] = frozenset(
    {
        "src_ip",
        "srcip",
        "dst_ip",
        "dstip",
        "dest_ip",
        "destip",
        "ip",
        "ipaddress",
        "address",
        "answer",
        "threat_object",
        "client_ip",
        "clientip",
        "remote_ip",
        "remoteip",
        "saddr",
        "daddr",
        "source_ip",
        "destination_ip",
    }
)
_DOMAIN_HINTS: frozenset[str] = frozenset({"query", "domain", "fqdn", "url", "hostname_domain", "dest_domain"})
_HASH_HINTS: frozenset[str] = frozenset({"process_hash", "file_hash", "sha256", "md5", "sha1", "imphash", "hashes", "hash"})
_GUID_HINTS: frozenset[str] = frozenset(
    {
        "process_guid",
        "processguid",
        "parent_process_guid",
        "parentprocessguid",
        "sourceprocessguid",
        "targetprocessguid",
        "guid",
    }
)
_NET_HINTS: frozenset[str] = frozenset({"src", "dest", "dst", "source", "destination", "entity", "risk_object"})
_PROCESS_HINTS: frozenset[str] = frozenset(
    {
        "process_name",
        "process",
        "image",
        "original_file_name",
        "sourceimage",
        "targetimage",
        "parent_process_name",
        "parent_process",
        "process_path",
        "parent_process_path",
        "process_exec",
        "parent_process_exec",
    }
)
#: Fields whose values are free text / bulk noise and must never be mined.
_SKIP_FIELDS: frozenset[str] = frozenset(
    {
        "calltrace",
        "call_stack",
        "raw",
        "_raw",
        "notable_raw",
        "spl",
        "description",
        "rule_description",
        "risk_message",
        "message",
        "commandline",
        "command_line",
        "scriptblocktext",
        "next_steps",
        "investigation_hint",
        "title",
        "rule_name",
        "matched_rules",
        "macro_definitions",
        # Share/file artifacts are part of the *action*, not an entity. They
        # are consumed directly by the SMB observation signature instead.
        "relativetargetname",
        "sharename",
        "objectname",
        "targetfilename",
    }
)
_MAX_CANDIDATES = 2_000


@dataclass(frozen=True)
class Key:
    """One normalised correlation key with its weight and provenance.

    ``scope`` narrows the identity space of a value. Sysmon process GUIDs are
    only unique *inside a host* (doc §4.1), so a bare GUID token would link the
    same process GUID on two different machines. Scoping keeps
    ``process_guid`` strong without inventing cross-host evidence — on the
    2026-11-08 corpus one synthetic GUID repeats on every domain controller
    and otherwise merges five unrelated DCs into one case.
    """

    kind: str
    value: str
    weight: int
    origins: tuple[str, ...] = ()
    alias: bool = False
    scope: str | None = None

    @property
    def token(self) -> str:
        if self.scope:
            return f"{self.kind}:{self.scope}|{self.value}"
        return f"{self.kind}:{self.value}"


@dataclass
class ExtractedKeys:
    """Result of :func:`extract_keys`.

    The flat lists are conveniences; ``keys`` is the authoritative structure and
    the only thing scoring consumes.
    """

    keys: list[Key] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    event_hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    process_guids: list[str] = field(default_factory=list)
    process_names: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    stories: list[str] = field(default_factory=list)
    kill_chain: list[str] = field(default_factory=list)
    provenance: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    filtered: list[dict[str, str]] = field(default_factory=list)
    time_quality: str = "alert_time_fallback"
    event_time: str | None = None
    alert_time: str | None = None
    rule_name: str = ""
    severity: str = "medium"
    normalizer_version: str = NORMALIZER_VERSION
    resolution_source: str = "generic_fallback"
    missing_fields: list[str] = field(default_factory=list)

    # ── helpers used by the observation/scoring layers ──────────────────────
    @property
    def primary_host(self) -> str:
        """The host the event happened on, never the Splunk indexer.

        ``event_hosts`` only contains values that came from an event-host field
        (``dest``/``dvc``/``dest_nt_host``/``Computer``/``hostname``/…). When the
        payload has none, the strongest extracted host is the best available
        answer; it is *not* silently conflated with index metadata.
        """
        if self.event_hosts:
            return self.event_hosts[0]
        return self.hosts[0] if self.hosts else ""

    def by_kind(self, kind: str, *, min_weight: int = 1) -> list[Key]:
        return [k for k in self.keys if k.kind == kind and k.weight >= min_weight]

    def tokens(self, *, min_weight: int = 1) -> set[str]:
        return {k.token for k in self.keys if k.weight >= min_weight}

    def weight_of(self, token: str) -> int:
        for k in self.keys:
            if k.token == token:
                return k.weight
        return 0

    @property
    def has_entities(self) -> bool:
        return bool(self.keys)


# ────────────────────────────────────────────────────────────────────────────
# Normalisation helpers
# ────────────────────────────────────────────────────────────────────────────


def _clean(value: Any) -> str:
    """Trim quotes/whitespace and collapse internal whitespace."""
    text = str(value if value is not None else "").strip().strip(_QUOTES).strip()
    return re.sub(r"\s+", " ", text)


def _canon_ip(text: str) -> str | None:
    """Return a canonical IP string, or ``None`` if it isn't one.

    Handles the ``::ffff:10.0.1.15`` Windows/Sysmon form and bracketed IPv6.
    """
    candidate = text.strip().strip("[]")
    if candidate.lower().startswith("::ffff:"):
        candidate = candidate[7:]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _is_unroutable(ip: str) -> bool:
    """Loopback/unspecified/multicast/link-local — never a shared identity.

    Link-local matters in practice: Windows SMB notables report
    ``fe80::…`` interface addresses that differ per connection, so treating
    them as entities links unrelated hosts.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local


def _is_cdn(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CDN_NETWORKS if net.version == addr.version)


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private


def _leaf(path: str) -> str:
    """The last segment of a dotted payload path, normalised for lookup."""
    return re.sub(r"[^a-z0-9_]", "", path.rsplit(".", 1)[-1].lower())


def _field_hint(path: str) -> str | None:
    """Map a dotted payload path to a coarse hint (``host``/``user``/...)."""
    leaf = _leaf(path)
    if leaf in _SKIP_FIELDS:
        return "skip"
    if leaf in _INDEXER_FIELDS:
        return "indexer"
    if leaf in _GUID_HINTS:
        return "process_guid"
    if leaf in _HASH_HINTS:
        return "hash"
    if leaf in _HOST_HINTS:
        return "host"
    if leaf in _USER_HINTS:
        return "user"
    if leaf in _IP_HINTS:
        return "ip"
    if leaf in _DOMAIN_HINTS:
        return "domain"
    if leaf in _PROCESS_HINTS:
        return "process"
    if leaf in _NET_HINTS:
        return "net"
    return None


def _walk(value: Any, prefix: str, out: list[tuple[str, str]], *, depth: int = 0) -> None:
    """Flatten nested dicts/lists into ``(dotted_path, scalar)`` pairs."""
    if len(out) >= _MAX_CANDIDATES or depth > 6:
        return
    if isinstance(value, Mapping):
        for key, sub in value.items():
            if isinstance(key, str):
                _walk(sub, f"{prefix}.{key}" if prefix else key, out, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _walk(item, prefix, out, depth=depth + 1)
        return
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        return  # never correlate on bare counters/thresholds
    if isinstance(value, str):
        text = _clean(value)
        if text:
            out.append((prefix, text))


def _as_list(value: Any) -> list[str]:
    """Flatten a vendor field that may be a scalar, a list, or a newline blob."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_as_list(item))
        return out
    text = _clean(value)
    if not text:
        return []
    parts = re.split(r"[\r\n;,]+", text)
    return [p.strip() for p in parts if p.strip()]


def _norm_story(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _is_splunk_payload(payload: Mapping[str, Any]) -> bool:
    """True for payloads built by the Splunk notable pipeline.

    Only then does ``host`` mean "indexer". A payload from another vendor may
    legitimately use ``host`` for the machine the event happened on, and
    dropping it there would lose the only victim identity available.
    """
    markers = ("alert_time", "date_context", "time_window", "annotations", "alert_fields", "rule_name")
    return sum(1 for marker in markers if marker in payload) >= 4


def _indexer_values(payload: Mapping[str, Any]) -> set[str]:
    """Values that identify the Splunk indexer/search head, not the victim.

    Two sources: the connector records it in ``_meta.indexer_host`` (preferred,
    because it survives payload projection), and a pipeline-built payload may
    still carry ``host``/``splunk_server`` inside ``alert_fields``.
    """
    values: set[str] = set()
    meta = payload.get("_meta")
    if isinstance(meta, Mapping):
        for key in ("indexer_host", "indexer", "splunk_server"):
            for item in _as_list(meta.get(key)):
                values.add(item.lower())
    fields = payload.get("alert_fields")
    if isinstance(fields, Mapping):
        for key, value in fields.items():
            leaf = _leaf(str(key))
            if leaf == "host" or leaf in _INDEXER_FIELDS:
                for item in _as_list(value):
                    values.add(item.lower())
    return values


# ────────────────────────────────────────────────────────────────────────────
# Classification + weighting
# ────────────────────────────────────────────────────────────────────────────


def _classify(raw: str, hint: str | None) -> tuple[str, str] | None:
    """Return ``(kind, canonical_value)`` or ``None`` if the value is not a key.

    Order matters: shape first, hint second. This is what makes the extractor
    survive vendor field drift (Splunk ``dest``, Sysmon ``Computer``,
    CloudTrail ``requestParameters.sourceIPAddress`` …).
    """
    text = _clean(raw)
    if not text:
        return None
    lowered = text.lower()

    if hint in {"skip", "indexer"}:
        return None

    # 1. GUID (Sysmon process GUIDs). Must precede hash/user checks.
    guid = _GUID_RE.match(text)
    if guid:
        return ("process_guid", guid.group(1).lower())

    # 2. SID. System SIDs are filtered by the caller.
    if _SID_RE.match(text):
        return ("user", lowered)

    # 3. IP address, including ::ffff: mapped form.
    ip = _canon_ip(text)
    if ip:
        return ("ip", ip)

    # 4. File hash.
    if _HASH_RE.match(text) and (hint in {"hash", None} or len(text) in {32, 40, 64}):
        # Only accept a bare 32/40/64-hex token; a GUID was already consumed
        # above and an arbitrary long hex string in free text is still a hash
        # only when it matches the exact shapes.
        return ("hash", lowered)

    # 5. URLs: the hostname is the durable identity, the path is ephemeral.
    if "://" in text or text.lower().startswith("www."):
        try:
            host = urlsplit(text if "://" in text else f"//{text}").hostname or ""
        except ValueError:
            host = ""
        if host and _FQDN_RE.match(host):
            return ("host" if hint == "host" else "domain", host.lower().rstrip("."))
        return None

    # 6. Paths / executables are never entity keys (they are noise or, for the
    #    documented system processes, explicitly zero-weight).
    if "\\" in text or "/" in text:
        return None
    if _EXE_RE.search(text):
        return None

    # 6. FQDN-ish. A host hint keeps it a host (Splunk `dest` is a victim host);
    #    otherwise it is a domain observation.
    if _FQDN_RE.match(text):
        if hint in {"host", "net"} and not lowered.startswith(TUNNEL_DOMAIN_PREFIXES):
            return ("host", lowered.rstrip("."))
        # An unhinted FQDN is a domain observation. Treating it as a host is how
        # SMB ``RelativeTargetName`` values like ``admin.key`` become phantom
        # servers, complete with a phantom short-name alias.
        return ("domain", lowered.rstrip("."))

    if hint == "host":
        return ("host", lowered)
    if hint == "user":
        return ("user", lowered)
    if hint == "domain":
        return ("domain", lowered)

    # 7. Unhinted fallback: only for hints that explicitly allow a bare token.
    if hint == "net" and _USER_SHAPE_RE.match(text) and "." not in text:
        return ("host", lowered)
    return None


def _weight(
    kind: str,
    value: str,
    *,
    freq: Mapping[tuple[str, str], int],
    common_values: frozenset[str],
    threat_intel_values: frozenset[str],
    alias: bool,
) -> int:
    """Assign the doc §4.1 weight class to a normalised key."""
    f = int(freq.get((kind, value), 0))

    if kind == "process_guid":
        weight = WEIGHT_STRONG
    elif kind == "hash":
        # A hash seen twice in 30 days is still a strong file identity; a hash
        # seen constantly (e.g. a signed OS binary) is not.
        weight = WEIGHT_STRONG if f <= 2 else WEIGHT_MEDIUM
    elif kind == "ip":
        if _is_cdn(value) or value.startswith(("isatap.", "teredo.")):
            return 0
        weight = WEIGHT_MEDIUM if _is_private(value) else WEIGHT_STRONG
    elif kind == "domain":
        if value.startswith(TUNNEL_DOMAIN_PREFIXES):
            return 0
        if value in threat_intel_values:
            weight = WEIGHT_STRONG
        elif value in COMMON_DOMAINS or value in common_values or f > T_COMMON_DOMAIN:
            # ``common_values`` is the tenant's own ambient set (frequency
            # service): a zone every alert mentions is exactly as weak as a
            # well-known public domain, and this is what stops a tenant-wide
            # domain from correlating unrelated activity on its own.
            weight = WEIGHT_WEAK
        else:
            weight = WEIGHT_MEDIUM
    elif kind == "user":
        if value in SYSTEM_SIDS or value.endswith("$"):
            weight = WEIGHT_WEAK
        elif value in common_values or f > T_USER_COMMON:
            weight = WEIGHT_WEAK
        else:
            weight = WEIGHT_MEDIUM
    elif kind == "host":
        if value in common_values or f > H_HUB:
            weight = WEIGHT_WEAK
        else:
            weight = WEIGHT_MEDIUM
    else:  # pragma: no cover — KINDS is exhaustive
        weight = WEIGHT_WEAK

    if alias:
        weight = min(weight, WEIGHT_MEDIUM)
    return weight


# ────────────────────────────────────────────────────────────────────────────
# Public entry point
# ────────────────────────────────────────────────────────────────────────────


def extract_keys(
    llm_payload: Mapping[str, Any] | None,
    normalizer_version: str = NORMALIZER_VERSION,
    *,
    freq: Mapping[tuple[str, str], int] | None = None,
    common_values: Iterable[str] | None = None,
    threat_intel_values: Iterable[str] | None = None,
    identity_map: Mapping[str, Any] | None = None,
    identity_map_source: str = "generic_fallback",
) -> ExtractedKeys:
    """Extract weighted correlation keys from one ``alerts.llm_payload``.

    Parameters
    ----------
    llm_payload:
        The immutable payload as stored in Postgres (a ``dict``). ``None`` or an
        empty mapping yields an empty result rather than raising — callers run
        inside a consumer loop and must never wedge on one malformed alert.
    normalizer_version:
        Stamped onto the result so a future re-normalisation can be replayed
        selectively.
    freq:
        ``{(kind, value): count_30d}`` from the frequency service. Missing
        entries are treated as ``0`` (never seen), which is the conservative
        choice for a brand-new tenant.
    common_values:
        Extra known-common values (lowercase) supplied by the frequency service.
    threat_intel_values:
        Known-malicious domains; these get the strong weight regardless of
        frequency.
    identity_map:
        Optional rule-specific field registry. When present, only these named
        fields are mined; it replaces vendor-name guessing for that alert.
    identity_map_source:
        Resolution audit label: exact, tenant_pattern, global_pattern,
        generic_fallback, or missing.
    """
    payload: Mapping[str, Any] = llm_payload or {}
    freq_map: Mapping[tuple[str, str], int] = freq or {}
    common = frozenset(str(v).lower() for v in (common_values or ())) | COMMON_DOMAINS
    intel = frozenset(str(v).lower() for v in (threat_intel_values or ()))

    result = ExtractedKeys(normalizer_version=normalizer_version)

    # ── Time quality (doc §3.3) ────────────────────────────────────────────
    source = str(payload.get("event_time_source") or "").strip().lower()
    result.time_quality = "first_event" if source == "first_event" else "alert_time_fallback"
    result.event_time = _clean(payload.get("event_time")) or None
    result.alert_time = _clean(payload.get("alert_time")) or None
    result.rule_name = _clean(payload.get("rule_name"))
    result.severity = (_clean(payload.get("severity")) or "medium").lower()

    # ── MITRE context (used for L2, never for L1) ─────────────────────────
    annotations = payload.get("annotations")
    if isinstance(annotations, Mapping):
        for technique in _as_list(annotations.get("mitre_attack")):
            result.techniques.append(technique.upper())
        for story in _as_list(annotations.get("analytic_story")):
            result.stories.append(_norm_story(story))
        for phase in _as_list(annotations.get("kill_chain_phases")):
            result.kill_chain.append(_norm_story(phase))

    result.resolution_source = identity_map_source

    # ── Candidate collection ──────────────────────────────────────────────
    candidates: list[tuple[str, str]] = []

    if identity_map:
        candidates, missing_fields = _mapped_candidates(payload, identity_map)
        result.missing_fields = missing_fields
    else:
        # Top-level semantic fields carry the strongest signal. ``entity`` is
        # Splunk ES's "what this notable is about"; risk_object is the RBA target.
        for field_name, type_field in (("entity", "entity_type"), ("risk_object", "risk_object_type")):
            raw_value = payload.get(field_name)
            declared = _clean(payload.get(type_field)).lower()
            if raw_value is None:
                continue
            hint = {
                "system": "host",
                "host": "host",
                "user": "user",
                "ip": "ip",
                "domain": "domain",
                "url": "domain",
            }.get(declared)
            for item in _as_list(raw_value):
                candidates.append((f"{field_name}#{hint or 'net'}", item))

        for path, value in _pairs(payload):
            candidates.append((path, value))

    # ── Indexer metadata (doc §1 / §3.2 rule 2) ───────────────────────────
    # On a Splunk notable, ``host`` is the host that *stored* the event (the
    # indexer or search head), not the host the event happened on. It is the
    # same value for every alert in the tenant, so treating it as an entity
    # collapsed unrelated incidents into one case. Skip it — and skip any
    # ``entity``/``risk_object`` value that is literally that host, which is how
    # the indexer leaks into the payload through the ``entity`` fallback.
    splunk_shaped = _is_splunk_payload(payload)
    indexer_values = _indexer_values(payload) if splunk_shaped else set()

    # ── Classification, filtering, weighting ──────────────────────────────
    seen: dict[tuple[str, str], dict[str, Any]] = {}

    for raw_path, raw_value in candidates[:_MAX_CANDIDATES]:
        path = raw_path
        hint_override = None
        if "#" in path:  # ``entity#host`` form used for typed top-level fields
            path, hint_override = path.split("#", 1)
        path_hint = hint_override or _field_hint(path)

        if splunk_shaped and _leaf(path) == "host":
            indexer_values.add(_clean(raw_value).lower())
            _note_filtered(result, raw_value, path, "splunk_indexer_host")
            continue
        if _leaf(path) in _INDEXER_FIELDS:
            indexer_values.add(_clean(raw_value).lower())
            _note_filtered(result, raw_value, path, "splunk_indexer_host")
            continue
        if _clean(raw_value).lower() in indexer_values:
            _note_filtered(result, raw_value, path, "splunk_indexer_host")
            continue

        if path_hint == "process":
            _note_process(raw_value, result)
            continue

        lowered = _clean(raw_value).lower()
        if lowered in PLACEHOLDERS:
            _note_filtered(result, raw_value, path, "placeholder")
            continue
        if _SID_RE.match(lowered) and lowered in SYSTEM_SIDS:
            _note_filtered(result, raw_value, path, "system_sid")
            continue

        classified = _classify(raw_value, path_hint)
        if classified is None:
            continue
        kind, value = classified

        # System processes that arrive as a host/user value are filtered here.
        if kind in {"host", "user"} and value in {p.removesuffix(".exe") for p in SYSTEM_PROCESSES}:
            _note_filtered(result, raw_value, path, "system_process")
            continue
        if kind == "ip" and _is_unroutable(value):
            _note_filtered(result, raw_value, path, "unroutable")
            continue

        weight = _weight(
            kind,
            value,
            freq=freq_map,
            common_values=common,
            threat_intel_values=intel,
            alias=False,
        )
        if weight <= 0:
            _note_filtered(result, raw_value, path, "zero_weight")
            continue

        slot = seen.get((kind, value))
        if slot is None:
            seen[(kind, value)] = {"origins": [path], "weight": weight}
        else:
            if path not in slot["origins"]:
                slot["origins"].append(path)
            slot["weight"] = max(slot["weight"], weight)

        # FQDN host → also emit the short name so ``mswin-dc01`` correlates with
        # ``mswin-dc01.attackrange.local`` (doc §3 rule 3).
        if kind == "host" and value.count(".") >= 1 and not value.replace(".", "").isdigit():
            short = value.split(".", 1)[0]
            if len(short) >= 3 and short not in PLACEHOLDERS:
                alias_weight = _weight(
                    kind,
                    short,
                    freq=freq_map,
                    common_values=common,
                    threat_intel_values=intel,
                    alias=True,
                )
                if alias_weight > 0 and (kind, short) not in seen:
                    seen[("host", short)] = {"origins": [f"{path}->short_name"], "weight": alias_weight}

        # A UPN / down-level account and its bare name are the same principal.
        # Rules disagree about which form they emit: Kerberos and LDAP rules
        # publish ``administrator@corp.local`` while SAM and Security rules
        # publish ``administrator``, so without this twin the two halves of one
        # identity only meet when both alerts also share a host. The twin is an
        # alias (capped at medium) and scoring counts it in the same L1 slot as
        # the UPN, so it bridges without adding weight.
        if kind == "user" and ("@" in value or "\\" in value):
            account = value.split("@", 1)[0].rsplit("\\", 1)[-1]
            if len(account) >= 2 and account not in PLACEHOLDERS and ("user", account) not in seen:
                seen[("user", account)] = {
                    "origins": [f"{path}->upn_account"],
                    "weight": min(weight, WEIGHT_MEDIUM),
                }

        # A domain that is really a host (Splunk ``dest`` carrying an FQDN
        # because the hint was absent) still gets a domain twin: DNS evidence
        # and process evidence must be able to meet on the same value.
        if kind == "host" and value.count(".") >= 1:
            if ("domain", value) not in seen:
                domain_weight = _weight(
                    "domain",
                    value,
                    freq=freq_map,
                    common_values=common,
                    threat_intel_values=intel,
                    alias=True,
                )
                if domain_weight > 0:
                    seen[("domain", value)] = {"origins": [f"{path}->domain"], "weight": domain_weight}

    _materialise(result, seen)
    return result


def _mapped_field_values(payload: Mapping[str, Any], field_name: str) -> list[str]:
    """Return values for one rule registry field name without legacy guessing."""
    target = str(field_name).strip()
    if not target:
        return []

    values: list[str] = []
    target_leaf = _leaf(target)

    if "." in target:
        node: Any = payload
        for segment in target.split("."):
            if not isinstance(node, Mapping):
                node = None
                break
            matched = next(
                (key for key in node.keys() if str(key).lower() == segment.lower()),
                None,
            )
            if matched is None:
                node = None
                break
            node = node[matched]
        if node is not None:
            values.extend(_as_list(node))

    for key, raw in payload.items():
        if isinstance(key, str) and _leaf(key) == target_leaf:
            values.extend(_as_list(raw))

    for section_name in ("alert_fields", "rule"):
        block = payload.get(section_name)
        if not isinstance(block, Mapping):
            continue
        pairs: list[tuple[str, str]] = []
        _walk(block, section_name, pairs)
        for path, value in pairs:
            if _leaf(path) == target_leaf or path.lower().endswith("." + target.lower()):
                values.append(value)

    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        clean = _clean(value)
        if clean:
            key = clean.lower()
            if key not in seen:
                seen.add(key)
                out.append(clean)
    return out


def _mapped_candidates(
    payload: Mapping[str, Any],
    identity_map: Mapping[str, Any],
) -> tuple[list[tuple[str, str]], list[str]]:
    """Build candidates strictly from a rule identity map."""
    candidates: list[tuple[str, str]] = []
    missing: list[str] = []
    kind_fields = {
        "host": identity_map.get("host_fields", []),
        "user": identity_map.get("user_fields", []),
        "ip": identity_map.get("ip_fields", []),
        "domain": identity_map.get("domain_fields", []),
        "hash": identity_map.get("hash_fields", []),
        "process_guid": identity_map.get("process_guid_fields", []),
    }
    excluded = {
        str(field_name).strip().lower()
        for field_name in (identity_map.get("excluded_fields", []) or [])
        if str(field_name).strip()
    }
    overrides = identity_map.get("field_kind_overrides", {}) or {}
    override_lookup = {str(field_name).lower(): str(kind).lower() for field_name, kind in overrides.items()}

    listed_fields: set[str] = set()
    for kind, field_names in kind_fields.items():
        for field_name in field_names or []:
            name = str(field_name).strip()
            if not name:
                continue
            leaf_key = _leaf(name)
            listed_fields.add(leaf_key)
            if leaf_key in excluded:
                continue

            hint = override_lookup.get(name.lower(), kind)
            values = _mapped_field_values(payload, name)
            if not values:
                missing.append(name.lower())
                continue
            for value in values:
                candidates.append((f"{name}#{hint}", value))

    for field_name in identity_map.get("excluded_fields", []) or []:
        leaf_key = str(field_name).strip().lower()
        if leaf_key:
            listed_fields.add(leaf_key)

    return candidates[:_MAX_CANDIDATES], missing


def _pairs(payload: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Flatten the parts of the payload worth mining."""
    out: list[tuple[str, str]] = []
    for section in ("alert_fields", "rule"):
        block = payload.get(section)
        if isinstance(block, Mapping):
            _walk(block, section, out)
    # ``annotations`` holds MITRE/story, not entities; ``time_window`` and
    # ``date_context`` hold timestamps and calendar facts. Both are skipped.
    return out


def _note_process(value: str, result: ExtractedKeys) -> None:
    """Record the executable basename only.

    Sysmon rules sometimes stuff the whole command line into ``process`` or
    ``process_exec``; taking the first whitespace-delimited token keeps the
    process identity usable (and keeps the dedup key stable).
    """
    text = _clean(value)
    if not text or text.lower() in PLACEHOLDERS:
        return
    token = text.strip(_QUOTES).split()[0].strip(_QUOTES)
    name = token.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if not name or name in PLACEHOLDERS or "=" in name:
        return
    if not _EXE_RE.search(name) and not re.match(r"^[a-z0-9._-]{2,64}$", name):
        return
    if name not in result.process_names:
        result.process_names.append(name)


def _note_filtered(result: ExtractedKeys, value: str, path: str, reason: str) -> None:
    if len(result.filtered) >= 200:
        return
    result.filtered.append({"value": _clean(value)[:200], "field": path, "reason": reason})


def _materialise(result: ExtractedKeys, seen: Mapping[tuple[str, str], Mapping[str, Any]]) -> None:
    """Turn the dedup map into ordered keys + per-kind lists + provenance."""
    order = {kind: index for index, kind in enumerate(KINDS)}
    keys = [
        Key(
            kind=kind,
            value=value,
            weight=int(meta["weight"]),
            origins=tuple(meta["origins"]),
            alias=any(
                o.endswith(("->short_name", "->domain", "->upn_account"))
                for o in meta["origins"]
            ),
        )
        for (kind, value), meta in seen.items()
    ]
    keys.sort(key=lambda k: (order.get(k.kind, 99), -k.weight, k.value))

    # Process GUIDs are host-scoped (see Key.scope). Use the strongest host we
    # extracted, preferring the FQDN form when both FQDN and short name exist.
    scope_host = ""
    for candidate in keys:
        if candidate.kind == "host" and not candidate.alias:
            scope_host = candidate.value
            break
    if scope_host:
        keys = [
            Key(
                kind=k.kind,
                value=k.value,
                weight=k.weight,
                origins=k.origins,
                alias=k.alias,
                scope=scope_host if k.kind == "process_guid" else k.scope,
            )
            for k in keys
        ]
    result.keys = keys

    # Hosts that came from an event-host field (dest/dvc/Computer/hostname/…)
    # are the victim identities. They are recorded separately from the general
    # host bucket so the observation layer keys a campaign on the machine the
    # event happened on instead of whichever host sorted first.
    #
    # An FQDN event host is normalised to its short alias when that alias exists
    # (``mswin-dc01.attackrange.local`` → ``mswin-dc01``). Both forms are keys,
    # so grouping on the short name keeps a bare ``dest=EC2AMAZ-FKEOM7G`` alert
    # in the same observation as its FQDN sibling instead of splitting the two.
    host_values = {k.value for k in keys if k.kind == "host"}
    for key in keys:
        if key.kind != "host" or key.alias:
            continue
        if not any(_leaf(origin) in _EVENT_HOST_LEAVES for origin in key.origins):
            continue
        short = key.value.split(".", 1)[0]
        value = short if "." in key.value and short in host_values else key.value
        if value not in result.event_hosts:
            result.event_hosts.append(value)

    buckets = {
        "host": result.hosts,
        "user": result.users,
        "ip": result.ips,
        "domain": result.domains,
        "hash": result.hashes,
        "process_guid": result.process_guids,
    }
    for key in keys:
        buckets[key.kind].append(key.value)
        result.provenance.setdefault(key.kind, {})[key.value] = list(key.origins)


__all__ = [
    "COMMON_DOMAINS",
    "ExtractedKeys",
    "KINDS",
    "Key",
    "NORMALIZER_VERSION",
    "PLACEHOLDERS",
    "SYSTEM_PROCESSES",
    "SYSTEM_SIDS",
    "T_COMMON_DOMAIN",
    "T_USER_COMMON",
    "H_HUB",
    "WEIGHT_MEDIUM",
    "WEIGHT_STRONG",
    "WEIGHT_WEAK",
    "extract_keys",
]
