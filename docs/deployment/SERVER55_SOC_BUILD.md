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

The Dockerfiles now select a regional Debian archive over HTTPS by default and the official Debian HTTPS security archive. Mirror selection is configurable without changing any credentials or runtime Compose service configuration. Debian APT signature verification remains enforced. The regional archive is listed by Debian's mirror service, but its HTTPS availability from Server 55 must be tested.

```bash
cd /home/api/Agentic_SOC
# Use GET, not HEAD. Check BOTH releases and refuse invalid/empty responses.
curl -fLsS --max-time 15 -o /dev/null https://archive.debian.petiak.ir/debian/dists/trixie/InRelease
curl -fLsS --max-time 15 -o /dev/null https://deb.debian.org/debian-security/dists/trixie-security/InRelease

# If a reachable trusted Debian mirror differs, override WITHOUT changing tracked files:
export APT_DEBIAN_MIRROR=https://archive.debian.petiak.ir/debian
export APT_SECURITY_MIRROR=https://deb.debian.org/debian-security

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
