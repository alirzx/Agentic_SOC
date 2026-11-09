#!/usr/bin/env bash
# Safe repeatable build for existing Server 55 aisoc-demo deployment.
# No 'down', seed/bootstrap, Docker prune or volume removal.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OVERRIDE="${SOC_RUNTIME_OVERRIDE:-$HOME/soc-deploy/runtime-security.override.yml}"
C=(docker compose --project-directory "$ROOT" -p aisoc-demo
  -f infra/compose/docker-compose.demo.yml
  -f infra/compose/privacy-network.override.yml
  -f infra/compose/privacy-ca.override.yml
  -f "$OVERRIDE")
APPS=(api agents web fusion connectors realtime ingest-worker)

preflight() {
  [[ -s .env ]] || { echo 'FAIL: .env missing' >&2; return 1; }
  [[ -f "$OVERRIDE" ]] || { echo "FAIL: runtime override missing" >&2; return 1; }
  docker network inspect aisoc-privacy >/dev/null
  "${C[@]}" config --quiet
  "${C[@]}" config --format json | python3 -c '
import json,sys
data=json.load(sys.stdin)
services=data["services"]
expected={"postgres","redis","kafka","zookeeper","api","agents","web","fusion","connectors","realtime","ingest-worker"}
assert expected <= services.keys(), "missing services"
assert data["networks"]["privacy_gateway"]["name"]=="aisoc-privacy"
for name in ("api","agents"):
  service=services[name]
  env=service["environment"]
  assert "privacy_gateway" in service["networks"]
  for var,value in {
    "AISOC_LLM_PRIVACY_ENABLED":"1",
    "AISOC_LLM_PRIVACY_REQUIRED":"1",
    "AISOC_PRIVACY_BACKEND":"remote",
    "AISOC_PRIVACY_REMOTE_URL":"https://privacy-gateway:8443",
    "SSL_CERT_FILE":"/run/secrets/aisoc-dlp-ca.pem",
    "ENV":"production"
  }.items():
    assert str(env.get(var,""))==value, f"{name}: invalid {var}"
  assert env.get("AISOC_PRIVACY_REMOTE_API_KEY"), f"{name}: token empty"
  assert len(env.get("AISOC_AGENTS_TENANT_SIGNING_KEY","").encode())>=32
  assert any(v.get("target")=="/run/secrets/aisoc-dlp-ca.pem" and v.get("read_only") for v in service.get("volumes",[]))
assert services["api"]["environment"]["AISOC_PRIVACY_REMOTE_API_KEY"]==services["agents"]["environment"]["AISOC_PRIVACY_REMOTE_API_KEY"]
assert services["api"]["environment"]["AISOC_AGENTS_TENANT_SIGNING_KEY"]==services["agents"]["environment"]["AISOC_AGENTS_TENANT_SIGNING_KEY"]
print("PASS: 11 services; HTTPS, private CA, tenant signature and remote privacy validated (secrets hidden)")
'
  [[ "$(docker inspect aisoc-demo-api --format '{{ index .Config.Labels "com.docker.compose.project" }}')" == "aisoc-demo" ]]
  echo "PASS: existing Compose project verified"
}

snapshot() {
  local stamp manifest service container image
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  umask 077
  mkdir -p "$HOME/soc_git_backups"
  manifest="$HOME/soc_git_backups/app-images-before-build-$stamp.txt"
  for service in "${APPS[@]}"; do
    container="aisoc-demo-$service"
    [[ "$service" == "ingest-worker" ]] && container="aisoc-demo-ingest"
    image="$(docker inspect "$container" --format '{{.Image}}')"
    docker image tag "$image" "aisoc-rollback/$service:before-$stamp"
    printf '%s %s\n' "$service" "$image" >> "$manifest"
  done
  chmod 600 "$manifest"
  echo "PASS: seven current application images tagged for rollback"
  echo "MANIFEST: $manifest"
}

build() {
  preflight
  snapshot
  for service in "${APPS[@]}"; do
    echo "Building $service (running containers stay untouched)"
    "${C[@]}" build "$service"
  done
  echo "PASS: seven image builds finished; no containers recreated"
}

smoke() {
  preflight
  for service in api agents; do
    echo "Testing DLP HTTPS from newly built $service image"
    "${C[@]}" run --rm --no-deps --entrypoint python "$service" -c '
import json,os,urllib.request
base=os.environ["AISOC_PRIVACY_REMOTE_URL"].rstrip("/")
for endpoint in ("/health","/ready"):
    with urllib.request.urlopen(base+endpoint,timeout=20) as response:
        assert response.status==200
        assert isinstance(json.load(response),dict)
request=urllib.request.Request(
    base+"/v1/policies",
    headers={"Authorization":"Bearer "+os.environ["AISOC_PRIVACY_REMOTE_API_KEY"]}
)
with urllib.request.urlopen(request,timeout=20) as response:
    assert response.status==200
    assert isinstance(json.load(response),dict)
print("PASS: verified TLS, health, readiness, authenticated policies")
'
  done
}

case "${1:-}" in
  preflight) preflight ;;
  snapshot) snapshot ;;
  build) build ;;
  smoke) smoke ;;
  status) "${C[@]}" ps -a ;;
  images) "${C[@]}" images ;;
  *) echo "Usage: bash scripts/server55_soc_build.sh preflight|snapshot|build|smoke|status|images"; exit 2 ;;
esac
