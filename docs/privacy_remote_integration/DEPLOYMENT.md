# Deployment topologies

## Same Docker host, separate Compose projects

Separate Compose projects do not share service DNS automatically. The optional
`infra/compose/privacy-network.override.yml` attaches only SOC `api` and
`agents` to a pre-created external network while preserving their existing
network:

```bash
docker network create aisoc-privacy
export AISOC_PRIVACY_EXTERNAL_NETWORK=aisoc-privacy
docker compose -f docker-compose.yml \
  -f infra/compose/privacy-network.override.yml config --quiet
```

The Gateway operator must attach the Gateway's **TLS endpoint** to that same
external network through a Gateway-side deployment override. The SOC repository
does not and must not modify the independent Gateway deployment. A shared
network supplies routing/DNS only; it does not supply TLS. With
`AISOC_LLM_PRIVACY_REQUIRED=1`, both SOC clients reject an `http://` Gateway
URL even on the same host. Configure `AISOC_PRIVACY_REMOTE_URL` with a private
HTTPS name that matches the certificate.

The Gateway's audited Compose currently publishes `8484:8484`, which binds all
host interfaces. This conflicts with Gateway README/deployment text that says
the port is loopback-only. Treat the Compose file as authoritative: until the
Gateway operator changes its deployment mapping to `127.0.0.1:8484:8484` or
removes the host publication, restrict port 8484 with host/cloud firewall rules
and place an authenticated TLS proxy or service mesh in front. The Gateway
repository remains read-only in this integration.

## Two-machine deployment

## Gateway host (Machine B)

Run the independent Gateway on a private host with:

```dotenv
DLP_DEV_MODE=false
DLP_UI_ENABLED=false
DLP_STORE_BACKEND=redis
DLP_REDIS_URL=redis://<private-redis-endpoint>/0
DLP_MASTER_KEY_B64=<secret-manager-value>
DLP_CLIENTS_JSON=<secret-manager-value>
```

`DLP_CLIENTS_JSON` stores the SHA-256 digest of the SOC service credential,
the client ID, and an explicit canonical tenant allowlist. Keep
`allow_tenantless=false` and `allow_secret_decode=false` for the SOC client.
The `agentic-soc-v1` profile must exist in `DLP_PROFILE_DIR`; preserve the
32-byte decoded `DLP_MASTER_KEY_B64` for the lifetime of active Contexts.
Production Redis must be persistent, authenticated, encrypted in transit, and
private. Defaults are a 3600-second Context TTL, 86400-second maximum TTL,
64-MiB request cap, and 1,000,000 mapping-entry cap; capacity-test any changes.

The audited Gateway release describes itself as a development release rather
than production-certified. It has health/readiness but no persistent audit sink
or hardened metrics endpoint, and its master-key rotation workflow is not yet
versioned. These are Gateway-side production blockers/accepted assumptions,
not changes this SOC repository can make.

The Gateway container listens on port 8484. Its current repository Compose
mapping publishes that port on every host interface, so restrict it to SOC VPN
sources and terminate HTTPS/mTLS at an authenticated proxy or service mesh. Do
not expose Redis publicly. Disable the development UI and demo credentials.

Verify locally on Machine B:

```bash
curl --fail --silent http://127.0.0.1:8484/health
curl --fail --silent http://127.0.0.1:8484/ready
```

## SOC host (Machine A)

Set `AISOC_PRIVACY_REMOTE_URL` to a routable private/VPN DNS name. A Docker
service name on Machine B is not resolvable from an independent Docker bridge on
Machine A. Confirm DNS, route, firewall, certificate chain, and clock health
from inside the agents container.

Inject `AISOC_PRIVACY_REMOTE_API_KEY` through the deployment secret mechanism,
not Compose source or a committed `.env`. Rebuild the agents image and restart
agents. The Dockerfile installs HTTPX directly and smoke-imports the internal
REST transport after copying application source. It does not clone or install
the Gateway repository.

Inject one separate `AISOC_AGENTS_TENANT_SIGNING_KEY` (at least 32 random
bytes) into both SOC API and Agents. The API uses it only to authenticate the
canonical tenant on internal investigation requests; it must not equal the
provider key, Gateway client credential, Gateway master key, or Local privacy
token key.

Run the SOC smoke script from the same container/network namespace that will
make production calls. Passing host-side curl alone does not prove container
routing.

Production is recognized from `AISOC_ENV`, `ENV`, `ENVIRONMENT`, or `APP_ENV`
when any is `prod` or `production`. A configured external provider with Privacy
disabled fails startup. Request-scoped BYOK calls are also blocked at the
central provider boundary if Privacy is disabled. Deliberate Local rollback
still requires Privacy enabled and a valid Local token key.

## TLS and authentication

- Use HTTPS or mTLS over the private network in production.
- Restrict ingress to authorized SOC machines/VPN addresses.
- Rotate the Bearer credential and its Gateway hash together.
- Keep TLS keys, Bearer credentials, provider keys, Gateway master keys, and
  Redis credentials in separate secret-manager entries.
- Never place credentials in the Gateway URL.
- For a private CA, mount its bundle into the agents container and set the
  standard `SSL_CERT_FILE` path in both API and Agents. The supplied
  `privacy-ca.override.yml` is compatible with both root and demo service names.
  Never use `curl -k` or disable certificate verification. No override is
  needed for a publicly trusted certificate.

## Local host port preflight

The 2026-10-30 read-only container inventory found active listeners on host
ports `6379`, `8080`, `9090`, and `7687`. Those conflict with root Compose
Redis, enrichment, ingest metrics, and Neo4j Bolt defaults respectively. The
demo Compose defaults avoid those four conflicts (`16379`, `18081`, and no
Neo4j/ingest-metrics publication), while `.env.example` also moves root
Postgres/Redis/Kafka to `5433`/`6380`/`9093`. Recheck ports immediately before
startup; do not stop unrelated containers automatically. Use a reviewed local
override for fixed root ports or select the slim demo topology rather than
changing internal container ports.

## Rollout

1. Deploy and verify the Gateway and private Redis.
2. Run the non-provider connectivity script for authorized synthetic tenants.
3. Build/deploy agents with privacy enabled and backend `remote`.
4. Run one synthetic Auto-Triage request and inspect sanitized operation stats.
5. Run one synthetic four-agent investigation.
6. Expand tenant allowlists and traffic gradually.

No production deployment is performed by this repository patch; host access and
deployment authorization are separate prerequisites.

Before rollout, confirm VPN DNS and routing, ingress firewall rules, TLS chain,
service credential hash, canonical tenant allowlist, Gateway and Redis
readiness, request timeouts, and clock synchronization on both machines.
