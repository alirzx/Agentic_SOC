#!/usr/bin/env bash
# Safe repeatable build for existing Server 55 aisoc-demo deployment.
# No 'down', seed/bootstrap, Docker prune or volume removal.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OVERRIDE="${SOC_RUNTIME_OVERRIDE:-$HOME/soc-deploy/runtime-security.override.yml}"
ENV_FILE="${SOC_COMPOSE_ENV:-$ROOT/.env}"
TKG="${SOC_TKG_OVERLAY:-off}"
C=(docker compose --project-directory "$ROOT" --env-file "$ENV_FILE" -p aisoc-demo
  -f infra/compose/docker-compose.demo.yml
  -f infra/compose/privacy-network.override.yml
  -f infra/compose/privacy-ca.override.yml)
case "$TKG" in
  off) ;;
  on) C+=(-f infra/compose/tkg-network.override.yml --profile tkg-sync) ;;
  private-ca) C+=(-f infra/compose/tkg-network.override.yml -f infra/compose/tkg-ca.override.yml --profile tkg-sync) ;;
  *) echo 'FAIL: SOC_TKG_OVERLAY must be off, on or private-ca' >&2; exit 2 ;;
esac
# Keep on-host security settings authoritative over tracked overlays.
C+=(-f "$OVERRIDE")
APPS=(api agents web fusion connectors realtime ingest-worker correlation)

resolved_config() {
  [[ -s "$ENV_FILE" ]] || { echo 'FAIL: Compose environment file missing' >&2; return 1; }
  [[ -f "$OVERRIDE" ]] || { echo 'FAIL: runtime override missing' >&2; return 1; }
  "${C[@]}" config --format json 2>/dev/null || { echo 'FAIL: Compose inputs could not resolve' >&2; return 1; }
}

config() {
  resolved_config | python3 -c '
import json,sys
from pathlib import Path
from urllib.parse import urlsplit
data=json.load(sys.stdin)
services=data["services"]
tkg=sys.argv[1]
expected={"postgres","redis","kafka","zookeeper","api","agents","web","fusion","connectors","realtime","ingest-worker","correlation"}
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
assert {name for name,svc in services.items() if "privacy_gateway" in svc.get("networks",{})}=={"api","agents"}
assert all(p.get("host_ip") in {"127.0.0.1","::1"} for p in services["ingest-worker"].get("ports",[])), "ingest must be private"
enabled=lambda env,key: str(env.get(key,"")).lower() in {"1","true","on","yes"}
agents=services["agents"]["environment"]
if tkg=="off":
  assert not enabled(agents,"AISOC_TKG_RECON_ENABLED"), "TKG enabled without its overlay"
else:
  assert data["networks"]["aisoc_tkg"]["external"] and data["networks"]["aisoc_tkg"]["name"]=="aisoc-tkg"
  assert {name for name,svc in services.items() if "aisoc_tkg" in svc.get("networks",{})}=={"api","agents","tkg-sync","tkg-reconcile"}
  assert agents["AISOC_TKG_RECON_PROFILE"] in {"standard","deep_case"}, "invalid Recon profile"
  if enabled(agents,"AISOC_TKG_RECON_ENABLED"):
    horizon=float(agents.get("AISOC_TKG_RECON_TIMEOUT_SECONDS") or (240 if agents["AISOC_TKG_RECON_PROFILE"]=="deep_case" else 120))
    dlp_timeout=float(agents.get("AISOC_PRIVACY_REMOTE_TIMEOUT_SECONDS") or 30)
    assert float(agents.get("AISOC_PRIVACY_CONTEXT_TTL_SECONDS") or 3600)>horizon+dlp_timeout, "DLP context expires before configured Recon budget"
  db_users={}
  assert not enabled(agents,"AISOC_TKG_RECON_LOOP_ENABLED") or enabled(agents,"AISOC_TKG_RECON_ENABLED"), "planner requires historical Recon"
  for name,role,flag,dsn in (
    ("api","reader",None,None), ("agents","reader","AISOC_TKG_RECON_ENABLED",None),
    ("tkg-sync","ingest","AISOC_TKG_AUTO_INGEST_ENABLED","DATABASE_URL"),
    ("tkg-reconcile","diagnostics","AISOC_TKG_RECONCILE_ENABLED","AISOC_TKG_RECONCILE_DATABASE_URL"),
  ):
    service=services[name]
    assert "aisoc-demo" in service["networks"]
    env=service["environment"]
    mounts={v["target"]:v for v in service.get("volumes",[])}
    target=f"/run/secrets/tkg/{role}"
    assert {k for k in mounts if k.startswith("/run/secrets/tkg/")}=={target}
    assert mounts[target]["read_only"]
    if tkg=="private-ca":
      assert mounts["/run/ca/tkg.pem"]["read_only"]
      assert env["AISOC_TKG_CA_FILE"]=="/run/ca/tkg.pem"
    if (flag and enabled(env,flag)) or (name=="api" and enabled(agents,"AISOC_TKG_RECON_ENABLED")):
      if sys.argv[2]=="runtime":
        assert Path(mounts[target]["source"]).is_dir(), f"{name}: credential mount is unavailable"
        if tkg=="private-ca":
          assert Path(mounts["/run/ca/tkg.pem"]["source"]).is_file(), f"{name}: TKG CA is unavailable"
      origin=env["AISOC_TKG_ORIGIN_SERVER55"]
      assert origin=="http://soorin-tkg:1516" or origin.startswith("https://"), f"{name}: invalid TKG origin"
    if dsn:
      assert service["image"]==services["api"]["image"] and "build" not in service and not service.get("ports")
      assert service.get("mem_limit") and service.get("cpus") and "tkg-sync" in service.get("profiles",[])
      if enabled(env,flag):
        db_users[name]=urlsplit(env[dsn]).username
        assert db_users[name], f"{name}: dedicated database login required"
  api_db=urlsplit(services["api"]["environment"].get("DATABASE_URL","")).username
  assert len(set(db_users.values()))==len(db_users) and api_db not in db_users.values(), "database logins must be separate"
print("PASS: SOC Compose, network, image and privacy policy validated (secrets hidden)")
' "$TKG" "${1:-static}"
}

preflight() {
  config runtime
  docker network inspect aisoc-privacy >/dev/null
  if [[ "$TKG" != off ]]; then
    docker network inspect aisoc-tkg >/dev/null
  fi
  [[ "$(docker inspect aisoc-demo-api --format '{{ index .Config.Labels "com.docker.compose.project" }}')" == "aisoc-demo" ]]
  echo "PASS: existing Compose project verified"
}

# Check both Debian Release metadata endpoints before beginning a full build.
# APT still verifies Debian's GPG signatures inside the Docker image.
apt_probe() {
  command -v curl >/dev/null || { echo 'FAIL: curl required for apt-probe' >&2; return 1; }
  local archive="${APT_DEBIAN_MIRROR:-https://archive.debian.petiak.ir/debian}"
  local security="${APT_SECURITY_MIRROR:-https://mirror.dogado.de/debian-security}"
  local entry url
  for entry in "$archive|trixie" "$security|trixie-security"; do
    url="${entry%%|*}/dists/${entry##*|}/InRelease"
    [[ "$url" == https://* ]] || { echo 'FAIL: Debian repository URL must be HTTPS' >&2; return 1; }
    echo "Checking Debian repository: $url"
    curl --fail --location --silent --show-error --retry 1 --max-time 18 --output /dev/null "$url" ||
      { echo "FAIL: Debian repository unreachable: $url" >&2; return 1; }
  done
  echo "PASS: both Debian release endpoints reachable; APT will validate signatures"
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
    if ! image="$(docker inspect "$container" --format '{{.Image}}' 2>/dev/null)"; then
      if [[ "$service" == correlation ]]; then
        printf '%s %s\n' "$service" absent >> "$manifest"
        continue
      fi
      echo "FAIL: current $service image could not be inventoried" >&2
      return 1
    fi
    docker image tag "$image" "aisoc-rollback/$service:before-$stamp"
    printf '%s %s\n' "$service" "$image" >> "$manifest"
  done
  chmod 600 "$manifest"
  echo "PASS: existing application images tagged for rollback"
  echo "MANIFEST: $manifest"
}

build() {
  preflight
  apt_probe
  snapshot
  for service in "${APPS[@]}"; do
    echo "Building $service (running containers stay untouched)"
    "${C[@]}" build "$service"
  done
  echo "PASS: application image builds finished; no containers recreated"
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
  config) config ;;
  preflight) preflight ;;
  apt-probe) apt_probe ;;
  snapshot) snapshot ;;
  build) build ;;
  smoke) smoke ;;
  status) "${C[@]}" ps -a ;;
  images) "${C[@]}" images ;;
  *) echo "Usage: bash scripts/server55_soc_build.sh config|preflight|apt-probe|snapshot|build|smoke|status|images"; exit 2 ;;
esac
