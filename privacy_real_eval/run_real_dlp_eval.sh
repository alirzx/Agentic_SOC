#!/usr/bin/env bash
# Reusable real-provider / real-Splunk DLP evaluation runner for Agentic_SOC.
# Expected layout:
#   Agentic_SOC/
#     privacy_real_eval/
#       run_real_dlp_eval.sh
#       privacy_real_workflow_probe.py
#       real_notable_template.json
#
# Run from either the repo root or this directory:
#   ./privacy_real_eval/run_real_dlp_eval.sh
#   OR
#   cd privacy_real_eval && ./run_real_dlp_eval.sh

set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# Resolve repository root from the script location, not from the caller's cwd.
if [[ -d "$SCRIPT_DIR/services/agents/app" ]]; then
  ROOT="$SCRIPT_DIR"
elif [[ -d "$SCRIPT_DIR/../services/agents/app" ]]; then
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
else
  echo "ERROR: could not locate Agentic_SOC repository root." >&2
  echo "Expected services/agents/app either beside this script or one directory above it." >&2
  exit 2
fi

PROBE="$SCRIPT_DIR/privacy_real_workflow_probe.py"
TEMPLATE="$SCRIPT_DIR/real_notable_template.json"

if [[ ! -f "$PROBE" ]]; then
  echo "ERROR: missing $PROBE" >&2
  echo "Keep privacy_real_workflow_probe.py in the same directory as this runner." >&2
  exit 2
fi

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT/.venv/bin/python"
elif [[ -x "$ROOT/services/agents/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT/services/agents/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
else
  echo "ERROR: Python 3 / project virtualenv not found." >&2
  exit 2
fi

export PYTHONPATH="$ROOT/services/agents${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONUNBUFFERED=1

RUN_ROOT="$SCRIPT_DIR/runs"
mkdir -p "$RUN_ROOT"
chmod 700 "$RUN_ROOT"
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$RUN_ROOT/$STAMP"
mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"

cleanup() {
  unset OPENAI_API_KEY AISOC_PRIVACY_TOKEN_KEY SPLUNK_TOKEN || true
}
trap cleanup EXIT INT TERM

prompt_required() {
  local __var_name="$1"
  local __prompt="$2"
  local __value=""
  while [[ -z "$__value" ]]; do
    read -r -p "$__prompt" __value
  done
  printf -v "$__var_name" '%s' "$__value"
}

prompt_secret() {
  local __var_name="$1"
  local __prompt="$2"
  local __value=""
  while [[ -z "$__value" ]]; do
    read -r -s -p "$__prompt" __value
    echo
  done
  printf -v "$__var_name" '%s' "$__value"
}

validate_uuid() {
  "$PYTHON_BIN" - "$1" <<'PY' >/dev/null
import sys, uuid
uuid.UUID(sys.argv[1])
PY
}

safe_route() {
  "$PYTHON_BIN" - "$1" <<'PY'
import sys
from urllib.parse import urlparse
u=urlparse(sys.argv[1])
h=u.hostname or 'configured-host'
if u.port:
    h=f'{h}:{u.port}'
suffix='/v1' if u.path.rstrip('/').endswith('/v1') else '/...'
print(f'{u.scheme or "https"}://{h}/...{suffix}')
PY
}

echo "============================================================"
echo " Agentic_SOC - Real Provider / Real Splunk DLP Evaluation"
echo "============================================================"
echo "Repository root: $ROOT"
echo "Test directory:  $SCRIPT_DIR"
echo
echo "This run makes REAL external provider calls."
echo "Human Trace captures real internal SOC context into private local files."
echo "Database/Kafka/memory writeback side effects are disabled by this runner."
echo

# ---------------------------------------------------------------------------
# Workflow selection
# ---------------------------------------------------------------------------
echo "Workflow:"
echo "  1) Auto-Triage only"
echo "  2) Investigator only (Recon -> Forensic -> Responder -> Report)"
echo "  3) Both [recommended]"
read -r -p "Select [1/2/3] (default 3): " WORKFLOW_CHOICE
case "${WORKFLOW_CHOICE:-3}" in
  1) WORKFLOW="auto-triage" ;;
  2) WORKFLOW="investigator" ;;
  3) WORKFLOW="both" ;;
  *) echo "ERROR: invalid workflow selection." >&2; exit 2 ;;
esac

# ---------------------------------------------------------------------------
# Input source
# ---------------------------------------------------------------------------
echo
echo "Input source:"
echo "  1) Existing real JSON/JSONL notable file"
echo "  2) Read one real notable from Splunk REST using an SPL search"
read -r -p "Select [1/2] (default 1): " SOURCE_CHOICE
SOURCE_CHOICE="${SOURCE_CHOICE:-1}"

if [[ "$SOURCE_CHOICE" == "1" ]]; then
  if [[ -f "$TEMPLATE" ]]; then
    echo "Template available at: $TEMPLATE"
  fi
  prompt_required INPUT_FILE "Path to real notable JSON/JSONL: "
  if [[ "$INPUT_FILE" != /* ]]; then
    if [[ -f "$SCRIPT_DIR/${INPUT_FILE#./}" ]]; then
      INPUT_FILE="$SCRIPT_DIR/${INPUT_FILE#./}"
    elif [[ -f "$ROOT/${INPUT_FILE#./}" ]]; then
      INPUT_FILE="$ROOT/${INPUT_FILE#./}"
    else
      INPUT_FILE="$SCRIPT_DIR/${INPUT_FILE#./}"
    fi
  fi
  if [[ ! -f "$INPUT_FILE" ]]; then
    echo "ERROR: input file does not exist: $INPUT_FILE" >&2
    exit 2
  fi
elif [[ "$SOURCE_CHOICE" == "2" ]]; then
  if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required for Splunk REST mode." >&2
    exit 2
  fi
  prompt_required SPLUNK_BASE_URL "Splunk management URL (example https://splunk.example:8089): "
  SPLUNK_BASE_URL="${SPLUNK_BASE_URL%/}"
  prompt_secret SPLUNK_TOKEN "Splunk token (hidden): "
  echo "Enter an exact READ-ONLY SPL search returning the notable to test."
  echo 'Example: search index=notable search_name="Example Rule" | head 1'
  prompt_required SPLUNK_QUERY "SPL search: "
  read -r -p "Verify Splunk TLS certificate? [Y/n]: " VERIFY_TLS
  CURL_TLS=()
  if [[ "${VERIFY_TLS:-Y}" =~ ^[Nn]$ ]]; then
    CURL_TLS=(-k)
  fi

  SPLUNK_EXPORT="$RUN_DIR/splunk_export_raw.jsonl"
  echo "Fetching one read-only Splunk search/export result..."
  curl --fail --silent --show-error "${CURL_TLS[@]}" \
    -H "Authorization: Splunk $SPLUNK_TOKEN" \
    --data-urlencode "search=$SPLUNK_QUERY" \
    --data-urlencode "output_mode=json" \
    --data-urlencode "exec_mode=oneshot" \
    -X POST \
    "$SPLUNK_BASE_URL/services/search/jobs/export" \
    > "$SPLUNK_EXPORT"
  chmod 600 "$SPLUNK_EXPORT"
  if [[ ! -s "$SPLUNK_EXPORT" ]]; then
    echo "ERROR: Splunk returned an empty export." >&2
    exit 1
  fi
  INPUT_FILE="$SPLUNK_EXPORT"
  unset SPLUNK_TOKEN
else
  echo "ERROR: invalid input source." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Tenant + test identity
# ---------------------------------------------------------------------------
echo
while true; do
  prompt_required TENANT_ID "Canonical tenant UUID: "
  if validate_uuid "$TENANT_ID" 2>/dev/null; then
    break
  fi
  echo "Invalid UUID. Use the platform canonical tenant UUID, not a slug/UUID5 placeholder."
  TENANT_ID=""
done

read -r -p "Case/test ID (blank = derive from notable): " CASE_ID

# ---------------------------------------------------------------------------
# Provider + privacy secret input
# ---------------------------------------------------------------------------
echo
prompt_required OPENAI_BASE_URL "OPENAI_BASE_URL (OpenAI-compatible, normally ending in /v1): "
prompt_secret OPENAI_API_KEY "OPENAI_API_KEY (hidden): "
prompt_required PROVIDER_MODEL "Provider model name (example DeepSeek-V4-Flash): "

while true; do
  prompt_secret AISOC_PRIVACY_TOKEN_KEY "AISOC_PRIVACY_TOKEN_KEY (hidden, >=32 bytes): "
  if (( ${#AISOC_PRIVACY_TOKEN_KEY} >= 32 )); then
    break
  fi
  echo "Privacy key is too short. Use a stable >=32-byte secret, e.g. 64 hex characters."
  AISOC_PRIVACY_TOKEN_KEY=""
done

read -r -p "Human Trace max chars per stage [200000]: " TRACE_MAX
TRACE_MAX="${TRACE_MAX:-200000}"
if ! [[ "$TRACE_MAX" =~ ^[0-9]+$ ]] || (( TRACE_MAX < 1000 )); then
  echo "ERROR: Human Trace max chars must be an integer >= 1000." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Controlled test runtime profile
# ---------------------------------------------------------------------------
export OPENAI_BASE_URL OPENAI_API_KEY AISOC_PRIVACY_TOKEN_KEY
unset LLM_BASE_URL || true

for role in TRIAGE RECON INVESTIGATION REPORT SUMMARY COPILOT NL; do
  export "AISOC_MODEL_PIN_${role}=$PROVIDER_MODEL"
done

export AISOC_LLM_PRIVACY_ENABLED=1
export AISOC_LLM_PRIVACY_STREAM_MAX_CHARS=1000000
export AISOC_LLM_HUMAN_TRACE_ENABLED=1
export AISOC_LLM_HUMAN_TRACE_MAX_CHARS="$TRACE_MAX"
export AISOC_LLM_RESPONSE_CACHE=0
export AISOC_AGENTS_LLM_CONTRACT_ENFORCED=1
export AISOC_DETERMINISTIC=0
export AISOC_SKIP_EMBEDDINGS=1

# Real provider I/O is allowed, but internal mutation paths are suppressed.
export AISOC_AGENT_KAFKA_DISABLE=1
export AISOC_AGENT_MEMORY_SUPPRESSION=0
export AISOC_AGENT_MEMORY_WRITEBACK=0
export AISOC_AGENT_ESCALATE_TO_GRAPH=0
unset DATABASE_URL || true

if [[ "${AISOC_AIRGAPPED:-0}" =~ ^(1|true|yes|on)$ ]]; then
  echo "ERROR: AISOC_AIRGAPPED is enabled. Refusing to override deployment egress policy." >&2
  exit 2
fi

SAFE_PROVIDER_ROUTE="$(safe_route "$OPENAI_BASE_URL")"
cat > "$RUN_DIR/test_profile.txt" <<EOF2
Agentic_SOC real DLP evaluation
workflow=$WORKFLOW
input=$INPUT_FILE
tenant_uuid=$TENANT_ID
provider_route=$SAFE_PROVIDER_ROUTE
provider_model=$PROVIDER_MODEL
privacy=ON
human_trace=ON
human_trace_max_chars=$TRACE_MAX
response_cache=OFF
deterministic=OFF
skip_embeddings=ON
llm_contract=ON
database_writes=OFF
kafka=OFF
memory_suppression=OFF
memory_writeback=OFF
worker_auto_escalation=OFF
EOF2
chmod 600 "$RUN_DIR/test_profile.txt"

echo
echo "------------------------------------------------------------"
echo "Test profile"
echo "------------------------------------------------------------"
echo "Workflow:        $WORKFLOW"
echo "Provider route:  $SAFE_PROVIDER_ROUTE"
echo "Model:           $PROVIDER_MODEL"
echo "Tenant UUID:     $TENANT_ID"
echo "Input:           $INPUT_FILE"
echo "Output:          $RUN_DIR"
echo "Privacy:         ON"
echo "Human Trace:     ON (contains real SOC data locally)"
echo "Cache:           OFF (forces real provider call)"
echo "Internal writes: OFF"
echo

# ---------------------------------------------------------------------------
# Offline DLP sanity test using the same privacy key and canonical tenant.
# ---------------------------------------------------------------------------
echo "Running offline privacy projection/rehydration sanity check..."
set +e
(
  cd "$ROOT/services/agents"
  "$PYTHON_BIN" -m app.scripts.privacy_smoke --tenant-id "$TENANT_ID"
) 2>&1 | tee "$RUN_DIR/offline_privacy_smoke.log"
OFFLINE_RC=${PIPESTATUS[0]}
set -e
chmod 600 "$RUN_DIR/offline_privacy_smoke.log"
if (( OFFLINE_RC != 0 )); then
  echo "ERROR: offline privacy smoke failed. Real provider call will not run." >&2
  exit "$OFFLINE_RC"
fi

# ---------------------------------------------------------------------------
# Optional synthetic provider preflight.
# ---------------------------------------------------------------------------
read -r -p "Run one synthetic REAL-provider preflight first? [Y/n]: " RUN_PREFLIGHT
if ! [[ "${RUN_PREFLIGHT:-Y}" =~ ^[Nn]$ ]]; then
  echo "Running existing privacy_provider_probe.py against the configured provider..."
  set +e
  (
    cd "$ROOT/services/agents"
    "$PYTHON_BIN" -m app.scripts.privacy_provider_probe --privacy on
  ) 2>&1 | tee "$RUN_DIR/provider_preflight.log"
  PREFLIGHT_RC=${PIPESTATUS[0]}
  set -e
  chmod 600 "$RUN_DIR/provider_preflight.log"
  if (( PREFLIGHT_RC != 0 )); then
    echo "ERROR: provider preflight failed. Real notable workflow will not be sent." >&2
    exit "$PREFLIGHT_RC"
  fi
fi

# ---------------------------------------------------------------------------
# Real workflow run.
# ---------------------------------------------------------------------------
CMD=(
  "$PYTHON_BIN" "$PROBE"
  --input "$INPUT_FILE"
  --tenant-id "$TENANT_ID"
  --workflow "$WORKFLOW"
  --output-dir "$RUN_DIR"
)
if [[ -n "$CASE_ID" ]]; then
  CMD+=(--case-id "$CASE_ID")
fi

echo "Running real workflow(s) through Privacy Gateway -> provider -> local rehydration..."
set +e
"${CMD[@]}" 2>&1 | tee "$RUN_DIR/console.log"
RUN_RC=${PIPESTATUS[0]}
set -e
chmod 600 "$RUN_DIR/console.log"
chmod -R go-rwx "$RUN_DIR"

echo
if (( RUN_RC == 0 )); then
  echo "PASS: real DLP evaluation completed."
  echo "Run directory: $RUN_DIR"
  echo "Key evidence files:"
  [[ -f "$RUN_DIR/comparison_auto_triage.json" ]] && echo "  comparison_auto_triage.json"
  [[ -f "$RUN_DIR/comparison_investigator.json" ]] && echo "  comparison_investigator.json"
  [[ -f "$RUN_DIR/investigator_llm_audit.json" ]] && echo "  investigator_llm_audit.json"
  echo "  summary.json"
  echo
  echo "Comparison files contain INTERNAL_INPUT -> PROVIDER_INPUT -> PROVIDER_RESPONSE -> LOCAL_RESPONSE."
else
  echo "FAIL: workflow returned exit code $RUN_RC. See $RUN_DIR/console.log" >&2
fi

exit "$RUN_RC"
