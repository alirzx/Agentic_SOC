# Migration and Rollback

## Migration

```text
Legacy Local backend
  -> deploy independent Gateway and Redis
  -> validate SDK/API and synthetic semantics
  -> deploy SOC Remote adapter with cache disabled
  -> canary Auto-Triage
  -> canary Investigator
  -> controlled tenant rollout
  -> consider legacy cleanup only after measured equivalence
```

Local privacy remains available as an explicit compatibility backend on this
branch. It is never selected automatically after a Remote error.

Before enabling Remote mode, verify canonical tenant resolution, Gateway tenant
allowlists, `agentic-soc-v1`, HTTPS routing, context TTL, stream buffer sizing,
and that the pinned SDK is present in the built image.

## Rollback

Rollback is a deployment decision, not a runtime fallback:

1. Stop or drain agents so no provider response remains tied to an in-flight
   Remote context.
2. Set `AISOC_PRIVACY_BACKEND=local` and restore the separately managed
   `AISOC_PRIVACY_TOKEN_KEY`, or disable external-provider LLM traffic and use
   the deterministic/local-only posture.
3. Restart agents and verify startup plus focused privacy tests.
4. Do not reuse Remote protected response-cache entries. Remote caching is
   disabled, and old Context IDs/mappings are not portable to Local mode.
5. Preserve Gateway audit metadata for incident review, then delete expired
   contexts according to Gateway retention policy.

Never respond to a Gateway outage by setting privacy disabled while external
providers remain reachable. Safe deterministic fallbacks/manual review may
continue because they do not make a provider call.

Recognized production environments also enforce this at the central agents
provider boundary. There is no runtime Remote-to-Local switch: drain in-flight
work, change configuration deliberately, restart, and revalidate.

## Legacy cleanup gate

Do not remove `privacy/redactor.py`, Local tests, or tenant/context propagation
until production canaries demonstrate semantic equivalence, multi-agent context
stability, and acceptable measured latency. This patch keeps Local as the
documented rollback rather than prematurely deleting it.
