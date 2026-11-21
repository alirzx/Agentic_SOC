import ipaddress
import json
import re
from pathlib import Path

from app.normalizer.extract_keys import extract_keys

CORPUS = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "plans"
    / "case"
    / "all-in-one-2"
    / "llm_payload_only.json"
)

SEED_MIGRATION = (
    Path(__file__).resolve().parents[2] / "api" / "migrations" / "090_correlation_rule_identity_maps.sql"
)

#: JSON literals embedded in the seed SQL (single-quoted arrays and objects).
_SQL_JSON_LITERAL = re.compile(r"'(\[[^']*\]|\{[^']*\})'")
_KIND_KEYS = (
    "host_fields",
    "user_fields",
    "ip_fields",
    "domain_fields",
    "hash_fields",
    "process_guid_fields",
    "excluded_fields",
)

IDENTITY_MAP = {
    "host_fields": ["dest", "dvc", "Computer", "hostname", "host_name", "orig_host"],
    "user_fields": ["user", "username", "src_user", "srcuser", "target_user", "Caller_User_Name", "subjectUserName", "TargetUserName"],
    "ip_fields": ["src", "dest", "src_ip", "dst_ip", "dest_ip", "daddr", "saddr", "source_ip", "destination_ip"],
    "domain_fields": ["domain", "query", "url", "dest_domain", "fqdn"],
    "hash_fields": ["file_hash", "process_hash", "hash", "sha1", "sha256", "md5", "imphash"],
    "process_guid_fields": ["process_guid", "SourceProcessGUID", "TargetProcessGUID", "ParentProcessGuid", "parent_process_guid"],
    "excluded_fields": ["host", "splunk_server", "splunk_host", "splunk_indexer", "indexer", "server", "index"],
    "field_kind_overrides": {
        "dest": "host",
        "dvc": "host",
        "Computer": "host",
        "hostname": "host",
        "host_name": "host",
        "orig_host": "host",
        "src": "ip",
        "dst_ip": "ip",
        "dest_ip": "ip",
        "src_ip": "ip",
        "user": "user",
        "username": "user",
        "src_user": "user",
        "Caller_User_Name": "user",
        "process_guid": "process_guid",
        "SourceProcessGUID": "process_guid",
        "TargetProcessGUID": "process_guid",
        "file_hash": "hash",
        "process_hash": "hash",
    },
}


def _corpus_payloads():
    with CORPUS.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            payload = row.get("llm_payload")
            if isinstance(payload, str):
                yield json.loads(payload)
            elif isinstance(payload, dict):
                yield payload


def _reject_duplicate_keys(pairs):
    seen: set[str] = set()
    for key, _value in pairs:
        assert key not in seen, f"duplicate JSON key in seed SQL: {key}"
        seen.add(key)
    return dict(pairs)


def test_seed_sql_has_no_duplicate_json_keys():
    """Postgres JSONB keeps the last duplicate key, silently flipping a mapping.

    A duplicated ``dest`` once turned every Splunk ``dest`` victim host into an
    IP field, which dropped the host identity for most of the corpus.
    """
    sql = SEED_MIGRATION.read_text(encoding="utf-8")
    literals = _SQL_JSON_LITERAL.findall(sql)
    assert literals, "seed migration contains no JSON literals"
    for literal in literals:
        json.loads(literal, object_pairs_hook=_reject_duplicate_keys)


def test_seed_field_lists_are_unique_and_parse():
    sql = SEED_MIGRATION.read_text(encoding="utf-8")
    for literal in re.findall(r"'(\[[^']*\])'", sql):
        values = json.loads(literal, object_pairs_hook=_reject_duplicate_keys)
        lowered = [str(value).strip().lower() for value in values]
        assert len(lowered) == len(set(lowered)), f"duplicate field in {literal}"


def _global_escu_seed() -> dict:
    """Return the ``ESCU - *`` global pattern row exactly as the migration stores it."""
    sql = SEED_MIGRATION.read_text(encoding="utf-8")
    body = sql.split("'ESCU - *', 'ESCU - *'", 1)[1].split("ON CONFLICT", 1)[0]
    literals = _SQL_JSON_LITERAL.findall(body)
    assert len(literals) == len(_KIND_KEYS) + 1, literals
    fields = {
        key: json.loads(value)
        for key, value in zip(_KIND_KEYS, literals[: len(_KIND_KEYS)], strict=True)
    }
    fields["field_kind_overrides"] = json.loads(
        literals[len(_KIND_KEYS)], object_pairs_hook=_reject_duplicate_keys
    )
    return fields


def test_seeded_global_map_keeps_dest_as_a_host_field():
    identity_map = _global_escu_seed()
    assert identity_map["field_kind_overrides"]["dest"] == "host"
    assert "dest" in identity_map["host_fields"]


def test_seeded_global_map_recovers_victim_hosts_from_the_corpus():
    """The seed must actually yield hosts; the previous override produced almost none."""
    identity_map = _global_escu_seed()
    total = 0
    with_hosts = 0
    indexer_values: set[str] = set()

    for payload in _corpus_payloads():
        total += 1
        keys = extract_keys(payload, identity_map=identity_map)
        if keys.hosts:
            with_hosts += 1
        for host in keys.hosts:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise AssertionError(f"IP leaked into hosts: {host}")
            assert host.lower() not in indexer_values

        meta = payload.get("_meta") if isinstance(payload.get("_meta"), dict) else {}
        for name in ("indexer_host", "indexer", "splunk_server"):
            value = str(meta.get(name) or "").strip().lower()
            if value:
                indexer_values.add(value)
        fields = payload.get("alert_fields") if isinstance(payload.get("alert_fields"), dict) else {}
        for name, value in fields.items():
            if str(name).lower() in {"host", "splunk_host", "splunk_server", "splunk_indexer", "indexer", "server", "index"}:
                if isinstance(value, list):
                    indexer_values.update(str(item).strip().lower() for item in value)
                elif value is not None:
                    indexer_values.add(str(value).strip().lower())

    assert total == 664
    # Measured with the corrected seed: 479 of 664 payloads yield an event host.
    assert with_hosts >= 470, f"seeded map only produced hosts for {with_hosts}/{total} payloads"


def test_registry_normalizer_passes_all_real_corpus_payloads():
    assert CORPUS.exists(), CORPUS

    count = 0
    for payload in _corpus_payloads():
        keys = extract_keys(payload, identity_map=IDENTITY_MAP)

        for host in keys.hosts:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                continue
            raise AssertionError(f"IP-like victim host leaked from {payload.get('rule_name')}: {host}")

        meta = payload.get("_meta") if isinstance(payload.get("_meta"), dict) else {}
        indexer_values = {
            str(meta.get(name) or "").strip().lower()
            for name in ("indexer_host", "indexer", "splunk_server")
            if str(meta.get(name) or "").strip()
        }
        fields = payload.get("alert_fields") if isinstance(payload.get("alert_fields"), dict) else {}
        for name, value in fields.items():
            if str(name).lower() in {"host", "splunk_host", "splunk_server", "splunk_indexer", "indexer", "server", "index"}:
                if isinstance(value, list):
                    indexer_values.update(str(item).strip().lower() for item in value)
                elif value is not None:
                    indexer_values.add(str(value).strip().lower())
        for host in keys.hosts:
            assert host.lower() not in indexer_values

        count += 1

    assert count == 664
