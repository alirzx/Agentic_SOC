"""Registry rows must decode the way asyncpg actually returns them.

This pool registers no ``jsonb`` codec, so every JSON column arrives as ``str``.
Building a ``RuleIdentityMap`` straight from a row therefore has to decode, or a
real database read raises (and a string is iterated character by character).
"""

from __future__ import annotations

import json
import uuid

from app.services.rule_registry import _row_to_map, resolve_rule_identity_map

_ROW = {
    "id": uuid.UUID("00000000-0000-0000-0000-000000009005"),
    "tenant_id": None,
    "rule_name": "ESCU - *",
    "rule_name_pattern": "ESCU - *",
    "is_active": True,
    "host_fields": json.dumps(["dest", "Computer"]),
    "user_fields": json.dumps(["user"]),
    "ip_fields": json.dumps(["src", "dest"]),
    "domain_fields": "[]",
    "hash_fields": "[]",
    "process_guid_fields": "[]",
    "excluded_fields": json.dumps(["host", "splunk_server"]),
    "field_kind_overrides": json.dumps({"dest": "host", "src": "ip"}),
    "notes": None,
    "source": "corpus-20261121",
}


def test_row_with_jsonb_returned_as_text_decodes_into_fields():
    mapped = _row_to_map(_ROW)

    assert mapped.host_fields == ("dest", "Computer")
    assert mapped.excluded_fields == ("host", "splunk_server")
    assert mapped.field_kind_overrides == {"dest": "host", "src": "ip"}


def test_decoded_row_resolves_and_classifies_dest_as_a_host():
    mapped = _row_to_map(_ROW)
    resolution = resolve_rule_identity_map(uuid.uuid4(), "ESCU - Something - Rule", [mapped])

    assert resolution.matched_source == "global_pattern"
    assert resolution.map is not None
    assert resolution.map.field_kind_overrides["dest"] == "host"


def test_malformed_json_degrades_to_empty_instead_of_raising():
    broken = dict(_ROW, host_fields="{not json", field_kind_overrides="[1,2,3]")
    mapped = _row_to_map(broken)

    assert mapped.host_fields == ()
    assert mapped.field_kind_overrides == {}
