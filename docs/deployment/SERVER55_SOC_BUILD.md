# Server 55: Mirror-aware, non-destructive SOC build

This workflow targets the existing `aisoc-demo` Compose project and preserves its PostgreSQL, Redis, Kafka and ZooKeeper containers, named volumes, and independently deployed `soorin-privacy-v2` production Gateway.

## Current server prerequisites

- Source `main` synced with both remotes, clean worktree.
- Existing `.env` mode 0600, remote Privacy backend enabled and required; current SOC Bearer token and tenant signing key already match DLP. **Never regenerate the DLP master key or its registered SOC token for a routine SOC build.**
- Gateway Caddy, FastAPI and TLS Redis healthy; external network `aisoc-privacy` exists.
- Private CA at `/opt/soorin/secrets/dlp/soc-ca-bundle.pem`; runtime override `~/soc-deploy/runtime-security.override.yml`.
- Four Compose inputs: `infra/compose/docker-compose.demo.yml`, `privacy-network.override.yml`, `privacy-ca.override.yml`, and the server-only runtime override.
- Enough disk/memory for seven application builds. Build sequentially rather than concurrently on constrained hosts.

## Safe one-command stages

```bash
cd /home/api/Agentic_SOC
git status -sb
bash scripts/server55_soc_build.sh preflight
bash scripts/server55_soc_build.sh build
bash scripts/server55_soc_build.sh smoke
bash scripts/server55_soc_build.sh images
```

The helper deliberately has **no** destructive deployment or Compose `down` command. `build` tags the existing seven running application image IDs as `aisoc-rollback/<service>:before-<UTC timestamp>`, saves a private manifest under `~/soc_git_backups`, and builds one service at a time. The currently running application containers are not replaced. `smoke` uses disposable containers built from the new API and Agents images with their network and CA settings and checks TLS HTTPS, health, readiness and Bearer policy access. It does not send customer data or contact an LLM provider.

## Registry selection

Python service Dockerfiles use one configurable **trusted** mirror for both pip (Poetry bootstrap) and Poetry resolution, default Liara. Select Chabokan only if it is trusted and tested with HTTP GET:

```bash
curl -fLsS --max-time 15 -o /dev/null https://mirror2.chabokan.net/pypi/simple/poetry/
# Select Chabokan for this invocation. Compose reads the exported variable:
export PYPI_INDEX_URL=https://mirror2.chabokan.net/pypi/simple/
bash scripts/server55_soc_build.sh build
unset PYPI_INDEX_URL
```

No source mixing and no TLS-disable option. The Python Dockerfiles resolve within the image and fail loudly on a dependency incompatibility, rather than installing partial manual pip fallback lists. **Only Agents currently has a committed Poetry lockfile.** For reproducible supply-chain pinning, create/review locked dependencies for API, Fusion and Connectors separately; this is not silently auto-committed during an operations build.

The web Dockerfile installs pnpm itself using the configured npm mirror. Realtime uses `npm ci` and its existing `package-lock.json`. Go ingest already uses the Liara proxy and its checked-in `go.sum`. Debian `apt` / Alpine `apk` mirrors are separate. If those fail, use documented trusted OS mirrors, not Python mirrors.

## Production caveats and controlled cutover

The source tree is based on a demo Compose whose DB/Redis/secret defaults need a separate migration and hardening plan. Merely setting `ENV=production` does not make a deployment production-certified. Previously exposed temporary SLA SSH credentials require revocation/rotation.

After successful image build and disposable-container DLP smoke, validate authorized and unauthorized Tenant Context/Encode/Decode, confirm strict fail-closed model egress, and only then plan a **selective** `up -d --no-deps --no-build` application cutover with tested rollback tags. Never run `docker compose down -v`, seed/bootstrap, unreviewed migrations, or volume pruning. Preserve the standalone DLP production Compose, Redis TLS volume, and legacy services during the rollback window.

## Debian APT mirror preflight (API and Agents)

Python mirrors do **not** provide Debian operating-system packages. The two images based on `python:3.11-slim` install OS libraries via signed Debian APT repositories. The base image currently uses Debian 13 `trixie`; the previous build failed reaching `deb.debian.org` over HTTP port 80.

The Dockerfiles select the previously working regional Debian archive over HTTPS and an independently mirrored, signed Debian Security repository (Dogado) over HTTPS by default. That security mirror has a current `trixie-security` index, but **reachability from Server 55 is not yet confirmed**. Mirror selection is configurable without changing any credentials or runtime Compose service configuration. Debian APT signature verification remains enforced. The regional archive is listed by Debian's mirror service, but its HTTPS availability from Server 55 must be tested.

```bash
cd /home/api/Agentic_SOC
# Use GET, not HEAD. Check BOTH releases and refuse invalid/empty responses.
curl -fLsS --max-time 15 -o /dev/null https://archive.debian.petiak.ir/debian/dists/trixie/InRelease
curl -fLsS --max-time 15 -o /dev/null https://mirror.dogado.de/debian-security/dists/trixie-security/InRelease

# If a reachable trusted Debian mirror differs, override WITHOUT changing tracked files:
export APT_DEBIAN_MIRROR=https://archive.debian.petiak.ir/debian
export APT_SECURITY_MIRROR=https://mirror.dogado.de/debian-security

# Build the previously blocked API first:
docker compose --project-directory "$PWD" -p aisoc-demo \
  -f infra/compose/docker-compose.demo.yml \
  -f infra/compose/privacy-network.override.yml \
  -f infra/compose/privacy-ca.override.yml \
  -f "$HOME/soc-deploy/runtime-security.override.yml" build api agents
```

If either preflight request fails, select another **trusted, reachable HTTPS mirror that actually serves the matching signed trixie/trixie-security repository** before attempting the build. Do not disable signature checks or switch to `http://` merely to bypass connectivity issues.

A fresh `python:3.11-slim` tag might eventually move beyond Debian trixie. The Dockerfile currently assumes the standard `/etc/apt/sources.list.d/debian.sources` layout and must be revised if the base image layout changes; pinning the base image by digest after acceptance is recommended.

The CLI warning that `--progress` is a global Compose flag is harmless. For detailed logs use `docker compose --progress plain ... build api`, or simply run the build helper's `build` stage.

## OpenSSL APT version skew: root cause and safe recovery

On 2026-11-09, `deb.debian.org/debian-security` timed out in the Docker build. APT printed a warning but continued with only the regional `trixie`/updates indexes. The base Python Trixie image already contained `libssl3t64` at `3.5.7-1~deb13u3`, while the available `libssl-dev` candidate required `3.5.7-1~deb13u2`. This was **both** a network problem and a resulting OS package-version mismatch, not a Python/Poetry dependency conflict.

The Dockerfiles now use `APT::Update::Error-Mode=any`, so missing Debian Security metadata fails the build immediately; they do not disable GPG signature checks, remove `trixie-security`, pin a stale OpenSSL version, or downgrade system libraries. The security URL is selected with `APT_SECURITY_MIRROR`; default `https://mirror.dogado.de/debian-security`. The Debian security index is publicly available, but always confirm access from this server:

```bash
cd /home/api/Agentic_SOC
bash scripts/server55_soc_build.sh apt-probe
```

Only proceed when both GET probes pass. If security mirror is unreachable, select another trusted mirror **that actually serves** `/debian-security/dists/trixie-security/InRelease` and rerun; do not proceed with the partial APT indexes. The Docker build prints `apt-cache policy libssl-dev libssl3t64` for further troubleshooting; if an exact-version mismatch persists after a fully successful APT update, review the mirror sync state and base image digest before changing package requirements.

After a successful probe, build the blocked API and Agents first, then the remaining app images using the helper. Do not rebuild or update running DLP containers as part of this fix.

## Poetry application isolation: packaging/virtualenv conflict (2026-11-09)

After Debian APT and Liara PyPI connectivity were fixed, the API build reached dependency installation but `python -m pip check` reported:

```
virtualenv 21.15.6 has requirement packaging>=26.3, but you have packaging 24.2
```

This is a **build-tool versus runtime environment collision**, not a failed Python dependency resolution: Poetry 2.5.1 and its own `virtualenv` requirement had been installed in the system interpreter, while `POETRY_VIRTUALENVS_CREATE=false` made the API install runtime dependencies in that *same* interpreter, downgrading `packaging`.

All four Python images now set `POETRY_VIRTUALENVS_CREATE=true` and `POETRY_VIRTUALENVS_IN_PROJECT=true`. Poetry still bootstraps using the configured Liara mirror, but creates an isolated `/app/.venv` for application dependencies. The integrity check is now `/app/.venv/bin/python -m pip check`, and the runtime `PATH` begins with `/app/.venv/bin`. Poetry itself remains outside that project virtualenv. Neither the private Gateway nor any Docker data volume is affected.

```bash
cd /home/api/Agentic_SOC
bash scripts/server55_soc_build.sh preflight
# API had already passed OS mirror and PyPI resolution; rebuild first.
docker compose --project-directory "$PWD" -p aisoc-demo \
  -f infra/compose/docker-compose.demo.yml \
  -f infra/compose/privacy-network.override.yml \
  -f infra/compose/privacy-ca.override.yml \
  -f "$HOME/soc-deploy/runtime-security.override.yml" build api
# If this succeeds, build agents, fusion and connectors, then web/realtime/ingest:
bash scripts/server55_soc_build.sh build
bash scripts/server55_soc_build.sh smoke
```

Do not remove `pip check`, force a newer `packaging` in the application, or pin/downgrade Poetry's `virtualenv` solely to make an unsafe shared environment pass. If `/app/.venv/bin/python -m pip check` reveals another conflict, that is now a true **application** dependency consistency issue and should be resolved using its Poetry constraints and lockfile. Create and commit the missing API/Fusion/Connectors lockfiles in a separate reviewed reproducibility task.


## Privacy/LLM probe execution inside the Agents image

Agents code lives in `/app/app`; operational scripts live in `/app/scripts`.
The Agents Dockerfile sets `PYTHONPATH=/app` and verifies both CLI help entrypoints
during image build. Use `python -m scripts.<module>` with `--workdir /app`
for Compose one-off runs. **Never run a production LLM call with privacy disabled.**

Set `AISOC_PRIVACY_TEST_TENANT_ID` to the existing canonical UUID
authorized for the SOC DLP client. The test uses a fake *local* model, but the
real HTTPS DLP for context, encode, decode and cleanup. No external provider
is contacted:

```bash
cd /home/api/Agentic_SOC
SOC_COMPOSE=(
  docker compose --project-directory "$PWD" -p aisoc-demo
  -f infra/compose/docker-compose.demo.yml
  -f infra/compose/privacy-network.override.yml
  -f infra/compose/privacy-ca.override.yml
  -f "$HOME/soc-deploy/runtime-security.override.yml"
)
"${SOC_COMPOSE[@]}" config --quiet
"${SOC_COMPOSE[@]}" build agents
"${SOC_COMPOSE[@]}" run --rm --no-deps --workdir /app \
  -e AISOC_PRIVACY_TEST_TENANT_ID \
  --entrypoint python agents -m scripts.check_protected_llm_flow
```

After this succeeds, stop any active investigations and selectively recreate
only `agents` with `--no-deps --no-build --force-recreate`. Run
`docker exec -e AISOC_PRIVACY_TEST_TENANT_ID="$AISOC_PRIVACY_TEST_TENANT_ID"
aisoc-demo-agents python -m scripts.check_protected_llm_flow` to verify the
new running image. Existing infrastructure volumes and DLP Compose are untouched.

A **separate**, explicitly authorized real-LLM Auto-Triage test is
`python -m scripts.privacy_provider_probe --privacy on --allow-provider-call`
with the same tenant variable. It contacts the configured LLM provider, so run
only after checking model routing, budget and operator approval. This probe
does not exercise Kafka consumer offsets, tenant BYOK resolution or the full
API→Agents Investigation route.

If a script fails with `ModuleNotFoundError: app` despite this build gate,
inspect `PYTHONPATH` and Python working directory on that exact image;
do not reinstall Poetry dependencies or modify CA / DLP credentials.
