# Two-Machine Deployment

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

The Gateway container listens on port 8484. Its repository Compose mapping
publishes that port on the host, so restrict it with host/cloud firewall rules
to SOC VPN source addresses. Put an authenticated TLS reverse proxy or service
mesh in front of it for production. Do not expose Redis publicly. Disable the
development UI and demo credentials.

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
not Compose source or a committed `.env`. Rebuild the agents image so the pinned
SDK is present, then restart agents. The Dockerfile asserts that
`soorin_privacy` imports successfully, including on its pip fallback path.

Run the SOC smoke script from the same container/network namespace that will
make production calls. Passing host-side curl alone does not prove container
routing.

## TLS and authentication

- Use HTTPS or mTLS over the private network in production.
- Restrict ingress to authorized SOC machines/VPN addresses.
- Rotate the Bearer credential and its Gateway hash together.
- Keep TLS keys, Bearer credentials, provider keys, Gateway master keys, and
  Redis credentials in separate secret-manager entries.
- Never place credentials in the Gateway URL.

## Rollout

1. Deploy and verify the Gateway and private Redis.
2. Run the non-provider connectivity script for authorized synthetic tenants.
3. Build/deploy agents with privacy enabled and backend `remote`.
4. Run one synthetic Auto-Triage request and inspect sanitized operation stats.
5. Run one synthetic four-agent investigation.
6. Expand tenant allowlists and traffic gradually.

No production deployment is performed by this repository patch; host access and
deployment authorization are separate prerequisites.
