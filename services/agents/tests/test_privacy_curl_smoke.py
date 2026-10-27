"""Offline fake-curl regression for the operator smoke workflow."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

TENANT = "11111111-1111-1111-1111-111111111111"
PROFILE = "agentic-soc-v1"
KEY = "synthetic-smoke-service-credential"
CONTEXT = "ctx_synthetic_curl_smoke"

_FAKE_CURL = r'''#!/usr/bin/env python3
import json, sys
from urllib.parse import urlsplit

args = sys.argv[1:]
method = args[args.index("--request") + 1]
output = args[args.index("--output") + 1]
path = urlsplit(args[-1]).path
status = 200
payload = {}

if path == "/health":
    payload = {"status":"ok","service":"soorin-data-privacy-gateway"}
elif path == "/ready":
    payload = {"status":"ready","store":"synthetic"}
elif path == "/v1/policies":
    payload = {"policies":[{"name":"agentic-soc-v1","version":"1.0.0"}]}
elif path == "/v1/contexts" and method == "POST":
    status = 201
    payload = {
        "context_id":"ctx_synthetic_curl_smoke",
        "tenant_id":"11111111-1111-1111-1111-111111111111",
        "profile":"agentic-soc-v1",
        "policy_version":"1.0.0",
        "expires_at":"2099-01-01T00:00:00+00:00",
    }
elif path == "/v1/contexts/ctx_synthetic_curl_smoke" and method == "GET":
    payload = {
        "context_id":"ctx_synthetic_curl_smoke",
        "tenant_id":"11111111-1111-1111-1111-111111111111",
        "profile":"agentic-soc-v1",
        "policy_version":"1.0.0",
        "expires_at":"2099-01-01T00:00:00+00:00",
    }
elif path == "/v1/classify":
    payload = {"counts":{"HOST":1},"total_detected":3}
elif path == "/v1/encode":
    payload = {
        "context_id":"ctx_synthetic_curl_smoke",
        "policy_version":"1.0.0",
        "format":"json",
        "payload":{
            "src_ip":"IP_V4_PRIVATE_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "hostname":"HOST_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "username":"USER_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "severity":"high",
            "mitre_technique":"T1110.003",
        },
        "expires_at":"2099-01-01T00:00:00+00:00",
        "stats":{"tokenized_unique":3},
    }
elif path == "/v1/decode":
    payload = {
        "context_id":"ctx_synthetic_curl_smoke",
        "format":"json",
        "payload":{
            "src_ip":"10.20.3.7",
            "hostname":"dc01.corp.example",
            "username":"CORP\\alice",
            "severity":"high",
            "mitre_technique":"T1110.003",
        },
        "stats":{"rehydrated":3,"unknown_aliases":0},
    }
elif path == "/v1/contexts/ctx_synthetic_curl_smoke" and method == "DELETE":
    status = 204
else:
    status = 404
    payload = {"code":"NOT_FOUND","detail":"not found"}

if output != "/dev/null":
    with open(output, "w", encoding="utf-8") as handle:
        if status != 204:
            json.dump(payload, handle)
if "--write-out" in args:
    sys.stdout.write(str(status))
'''


def test_curl_smoke_positive_flow_with_fake_curl(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_curl = fake_bin / "curl"
    fake_curl.write_text(_FAKE_CURL, encoding="utf-8")
    fake_curl.chmod(fake_curl.stat().st_mode | stat.S_IXUSR)

    script = Path(__file__).resolve().parents[1] / "scripts" / "privacy_gateway_curl_smoke.sh"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "AISOC_PRIVACY_REMOTE_URL": "http://privacy.synthetic.test",
        "AISOC_PRIVACY_REMOTE_API_KEY": KEY,
        "AISOC_PRIVACY_REMOTE_PROFILE": PROFILE,
        "AISOC_PRIVACY_TEST_TENANT_ID": TENANT,
        "AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS": "3",
    }
    completed = subprocess.run(
        ["bash", str(script)],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "PASS remote privacy Gateway synthetic smoke" in completed.stdout
    assert KEY not in completed.stdout + completed.stderr
    assert CONTEXT not in completed.stdout + completed.stderr
