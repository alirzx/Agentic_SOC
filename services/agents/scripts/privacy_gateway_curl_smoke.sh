#!/usr/bin/env bash
# Synthetic-only Remote Privacy Gateway smoke test. This intentionally never
# prints credentials, context IDs, request headers, or response payloads.
set -euo pipefail
set +x

MODE="positive"
if [[ "${1:-}" == "--negative" ]]; then
  MODE="${2:-}"
fi

required=(AISOC_PRIVACY_REMOTE_URL AISOC_PRIVACY_REMOTE_API_KEY AISOC_PRIVACY_TEST_TENANT_ID)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "FAIL missing required configuration: ${name}" >&2
    exit 2
  fi
done

BASE_URL="${AISOC_PRIVACY_REMOTE_URL%/}"
PROFILE="${AISOC_PRIVACY_REMOTE_PROFILE:-agentic-soc-v1}"
TENANT="${AISOC_PRIVACY_TEST_TENANT_ID}"
CONNECT_TIMEOUT="${AISOC_PRIVACY_REMOTE_CONNECT_TIMEOUT_SECONDS:-5}"
REQUEST_TIMEOUT="${AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS:-30}"
CA_FILE="${AISOC_PRIVACY_REMOTE_CA_FILE:-}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ "$BASE_URL" == *"@"* ]]; then
  echo "FAIL Gateway URL must not embed credentials" >&2
  exit 2
fi
"$PYTHON_BIN" - "$TENANT" <<'PY'
import sys, uuid
uuid.UUID(sys.argv[1])
PY

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aisoc-privacy-smoke.XXXXXX")"
chmod 700 "$TMP_DIR"
AUTH_CONFIG="$TMP_DIR/curl-auth.conf"
umask 077
printf 'header = "Authorization: Bearer %s"\n' "$AISOC_PRIVACY_REMOTE_API_KEY" > "$AUTH_CONFIG"

CONTEXT_ID=""
cleanup() {
  if [[ -n "$CONTEXT_ID" ]]; then
    printf 'header = "Authorization: Bearer %s"\n' "$AISOC_PRIVACY_REMOTE_API_KEY" > "$AUTH_CONFIG"
    local cleanup_args=(--silent --show-error --connect-timeout "$CONNECT_TIMEOUT" --max-time "$REQUEST_TIMEOUT"
      --config "$AUTH_CONFIG" --request DELETE --output /dev/null)
    if [[ -n "$CA_FILE" ]]; then cleanup_args+=(--cacert "$CA_FILE"); fi
    curl "${cleanup_args[@]}" "$BASE_URL/v1/contexts/$CONTEXT_ID" || true
  fi
  find "$TMP_DIR" -type f -exec chmod 600 {} + 2>/dev/null || true
  rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT INT TERM

request() {
  local method="$1" path="$2" output="$3" expected="$4" body="${5:-}" status
  local args=(--silent --show-error --connect-timeout "$CONNECT_TIMEOUT" --max-time "$REQUEST_TIMEOUT"
    --config "$AUTH_CONFIG" --request "$method" --output "$output" --write-out '%{http_code}')
  if [[ -n "$CA_FILE" ]]; then args+=(--cacert "$CA_FILE"); fi
  if [[ -n "$body" ]]; then args+=(--header 'Content-Type: application/json' --data-binary "@$body"); fi
  status="$(curl "${args[@]}" "$BASE_URL$path")"
  if [[ "$status" != "$expected" ]]; then
    echo "FAIL ${method} ${path} returned HTTP ${status}" >&2
    return 1
  fi
}

json_assert() {
  "$PYTHON_BIN" - "$@"
}

negative_check() {
  local out="$TMP_DIR/negative.json" body="$TMP_DIR/negative-request.json"
  case "$MODE" in
    invalid-credential)
      printf 'header = "Authorization: Bearer invalid"\n' > "$AUTH_CONFIG"
      request GET /v1/policies "$out" 401
      ;;
    unauthorized-tenant)
      [[ -n "${AISOC_PRIVACY_TEST_UNAUTHORIZED_TENANT_ID:-}" ]] || { echo "FAIL missing AISOC_PRIVACY_TEST_UNAUTHORIZED_TENANT_ID" >&2; return 2; }
      [[ "$AISOC_PRIVACY_TEST_UNAUTHORIZED_TENANT_ID" != "$TENANT" ]] || { echo "FAIL unauthorized tenant must differ from authorized tenant" >&2; return 2; }
      "$PYTHON_BIN" - "$AISOC_PRIVACY_TEST_UNAUTHORIZED_TENANT_ID" "$PROFILE" "$body" <<'PY'
import json, sys, uuid
uuid.UUID(sys.argv[1])
json.dump({"tenant_id":sys.argv[1],"profile":sys.argv[2],"ttl_seconds":300}, open(sys.argv[3],"w"))
PY
      request POST /v1/contexts "$out" 403 "$body"
      ;;
    invalid-context)
      request GET /v1/contexts/ctx_invalid_synthetic "$out" 400
      ;;
    cross-tenant)
      [[ -n "${AISOC_PRIVACY_TEST_SECOND_API_KEY:-}" ]] || { echo "FAIL missing AISOC_PRIVACY_TEST_SECOND_API_KEY" >&2; return 2; }
      "$PYTHON_BIN" - "$TENANT" "$PROFILE" "$body" <<'PY'
import json,sys
json.dump({"tenant_id":sys.argv[1],"profile":sys.argv[2],"ttl_seconds":300},open(sys.argv[3],"w"))
PY
      request POST /v1/contexts "$out" 201 "$body"
      CONTEXT_ID="$(json_assert "$out" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); assert isinstance(d.get("context_id"),str); print(d["context_id"])
PY
)"
      printf 'header = "Authorization: Bearer %s"\n' "$AISOC_PRIVACY_TEST_SECOND_API_KEY" > "$AUTH_CONFIG"
      request GET "/v1/contexts/$CONTEXT_ID" "$out" 403
      printf 'header = "Authorization: Bearer %s"\n' "$AISOC_PRIVACY_REMOTE_API_KEY" > "$AUTH_CONFIG"
      ;;
    malformed)
      printf '{"tenant_id":' > "$body"
      request POST /v1/contexts "$out" 422 "$body"
      ;;
    expired)
      [[ -n "${AISOC_PRIVACY_TEST_EXPIRED_CONTEXT_ID:-}" ]] || { echo "FAIL missing AISOC_PRIVACY_TEST_EXPIRED_CONTEXT_ID" >&2; return 2; }
      request GET "/v1/contexts/${AISOC_PRIVACY_TEST_EXPIRED_CONTEXT_ID}" "$out" 400
      ;;
    unavailable)
      if request GET /health "$out" 200; then
        echo "FAIL Gateway unexpectedly reachable" >&2
        return 1
      fi
      ;;
    *) echo "FAIL unknown negative test: $MODE" >&2; return 2 ;;
  esac
  echo "PASS negative ${MODE}"
}

if [[ "$MODE" != "positive" ]]; then
  negative_check
  exit 0
fi

OUT="$TMP_DIR/response.json"
BODY="$TMP_DIR/request.json"
request GET /health "$OUT" 200
json_assert "$OUT" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); assert d.get("status")=="ok" and d.get("service")=="soorin-data-privacy-gateway"
PY
echo "PASS GET /health"

request GET /ready "$OUT" 200
json_assert "$OUT" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); assert d.get("status")=="ready" and isinstance(d.get("store"),str) and d["store"]
PY
echo "PASS GET /ready"

request GET /v1/policies "$OUT" 200
json_assert "$OUT" "$PROFILE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); p=d.get("policies"); assert isinstance(p,list)
assert any(isinstance(x,dict) and x.get("name")==sys.argv[2] and isinstance(x.get("version"),str) for x in p)
PY
echo "PASS GET /v1/policies"

"$PYTHON_BIN" - "$TENANT" "$PROFILE" "$BODY" <<'PY'
import json,sys
json.dump({"tenant_id":sys.argv[1],"profile":sys.argv[2],"ttl_seconds":300},open(sys.argv[3],"w"))
PY
request POST /v1/contexts "$OUT" 201 "$BODY"
CONTEXT_ID="$(json_assert "$OUT" "$TENANT" "$PROFILE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); assert d.get("tenant_id")==sys.argv[2] and d.get("profile")==sys.argv[3]
assert isinstance(d.get("context_id"),str) and d["context_id"].startswith("ctx_")
assert isinstance(d.get("policy_version"),str) and isinstance(d.get("expires_at"),str)
print(d["context_id"])
PY
)"
echo "PASS POST /v1/contexts"

request GET "/v1/contexts/$CONTEXT_ID" "$OUT" 200
json_assert "$OUT" "$TENANT" "$PROFILE" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); assert d.get("tenant_id")==sys.argv[2] and d.get("profile")==sys.argv[3]
PY
echo "PASS GET /v1/contexts/{id}"

"$PYTHON_BIN" - "$PROFILE" "$BODY" <<'PY'
import json,sys
p={"src_ip":"10.20.3.7","hostname":"dc01.corp.example","username":"CORP\\alice","severity":"high","mitre_technique":"T1110.003"}
json.dump({"profile":sys.argv[1],"format":"json","payload":p,"registrations":[]},open(sys.argv[2],"w"))
PY
request POST /v1/classify "$OUT" 200 "$BODY"
json_assert "$OUT" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); assert isinstance(d.get("counts"),dict) and isinstance(d.get("total_detected"),int)
PY
echo "PASS POST /v1/classify"

"$PYTHON_BIN" - "$CONTEXT_ID" "$TENANT" "$PROFILE" "$BODY" <<'PY'
import json,sys
p={"src_ip":"10.20.3.7","hostname":"dc01.corp.example","username":"CORP\\alice","severity":"high","mitre_technique":"T1110.003"}
r=[{"kind":"HOST","value":p["hostname"],"source":"soc.curl-smoke","role":"host"},{"kind":"USER","value":p["username"],"source":"soc.curl-smoke","role":"user"}]
json.dump({"context_id":sys.argv[1],"tenant_id":sys.argv[2],"profile":sys.argv[3],"purpose":"llm-egress","format":"json","payload":p,"registrations":r},open(sys.argv[4],"w"))
PY
request POST /v1/encode "$OUT" 200 "$BODY"
PROTECTED="$TMP_DIR/protected.json"
json_assert "$OUT" "$PROTECTED" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); p=d.get("payload"); assert isinstance(p,dict)
rendered=json.dumps(p); assert all(x not in rendered for x in ("10.20.3.7","dc01.corp.example","CORP\\alice"))
assert isinstance(d.get("stats"),dict) and isinstance(d.get("expires_at"),str)
json.dump(p,open(sys.argv[2],"w"))
PY
echo "PASS POST /v1/encode"

"$PYTHON_BIN" - "$CONTEXT_ID" "$PROTECTED" "$BODY" <<'PY'
import json,sys
json.dump({"context_id":sys.argv[1],"format":"json","payload":json.load(open(sys.argv[2])),"purpose":"llm-response","reveal_credentials":False},open(sys.argv[3],"w"))
PY
request POST /v1/decode "$OUT" 200 "$BODY"
json_assert "$OUT" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); expected={"src_ip":"10.20.3.7","hostname":"dc01.corp.example","username":"CORP\\alice","severity":"high","mitre_technique":"T1110.003"}
assert d.get("payload")==expected and d.get("stats",{}).get("unknown_aliases",0)==0
PY
echo "PASS POST /v1/decode"

request DELETE "/v1/contexts/$CONTEXT_ID" "$OUT" 204
CONTEXT_ID=""
echo "PASS DELETE /v1/contexts/{id}"
echo "PASS remote privacy Gateway synthetic smoke"
