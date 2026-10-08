---
title: LLM gateway (LiteLLM)
description: Route every live LLM call through a single LiteLLM gateway — assign local or hosted models per task by alias, and get centralized latency/token/cost/error metrics — without changing AiSOC code.
---

# LLM gateway (LiteLLM)

AiSOC runs several distinct LLM workloads — triage, recon, investigation, the
contextual copilot, summaries, reports, and natural-language generation. The
**LiteLLM gateway** is the single entry point for every *live* LLM call these
workloads make. AiSOC asks for a **logical task alias**; the gateway decides
which real provider and model that alias resolves to.

```
AiSOC task ──▶ alias (e.g. "aisoc-triage") ──▶ LiteLLM ──▶ real model
```

This gives operators two things without any AiSOC code change:

1. **Per-task model assignment.** Point `aisoc-triage` at a cheap local model
   and `aisoc-investigation` at a strong hosted one — or swap either at any time
   — by editing one config file.
2. **Centralized observability.** LiteLLM exports per-task latency, tokens,
   cost, errors, retries, and fallbacks on `/metrics`, scraped by the bundled
   Prometheus (job `aisoc-litellm`). This complements the
   [Investigation Ledger](../concepts/llmops.md), which records *what the agent
   decided*; the gateway records *what each model call cost and how it behaved*.

The gateway sits in front of the LLM tier of the
[multi-model router](../concepts/model-router.md). When no live model is
reachable, AiSOC still degrades to its **deterministic offline path** — the
gateway is never on the critical path for a baseline triage.

## Tenant privacy projection

Routing and privacy enforcement are separate controls. The agents service can
call a configured gateway or a provider directly, so its privacy boundary is
the sanctioned invocation layer in `app.llm.contract`, immediately before
network egress. Enable it with a deployment-wide high-entropy key:

```bash
AISOC_LLM_PRIVACY_ENABLED=1
AISOC_PRIVACY_TOKEN_KEY=<at-least-32-random-bytes>
AISOC_LLM_PRIVACY_STREAM_MAX_CHARS=1000000
# Separate key used by an authenticated upstream to sign X-Tenant-Id:
AISOC_AGENTS_TENANT_SIGNING_KEY=<different-at-least-32-random-bytes>
```

For each tenant, private IP, host, asset, user, email, and path identities
become stable typed HMAC aliases. Structured classification is semantic and
path-aware: fields such as `device.name`, `src_endpoint.ip`, `account.name`,
and Splunk `entity` / `risk_object` values with a sibling type are recognized
without flattening away their parent context. Valid addresses retain their
IPv4/IPv6 scope prefix. A non-placeholder malformed value in an IP-semantic
field, such as `src_ip="B_309"`, becomes a reversible `IP_OPAQUE_*` alias
instead of falling through in plaintext.

The projector first discovers authoritative identities across the complete
structured value and then transforms it. Repeats in titles, narratives, and
quoted Splunk search expressions therefore use the same alias regardless of
dictionary order. Contextual forms such as `hostname=...`, `user="..."`, and
`| search dest="..."` are recognized, while unrelated public domains, URLs,
hashes, CVEs, MITRE IDs, and plain-text public IOC addresses remain available
for model reasoning. Common absence sentinels (`unknown`, `n/a`, `none`,
`null`, `not available`, and `-`) stay readable rather than becoming false
identities.

Secrets and credential-like values are irreversibly replaced with
`[REDACTED_SECRET]`. The provider response is restored locally from the active
request map; unknown or partial aliases are never guessed. When privacy is
active, the central LLM boundary also injects one system instruction explaining
that aliases are opaque stable identities which must be preserved exactly and
must not be decoded, abbreviated, or treated as malicious evidence. Internal
storage, Splunk queries, tools, Kafka, Postgres, and the entity graph continue
to use canonical values.

Keep the key consistent across agents replicas and restarts. Changing it
changes every alias; V1 intentionally has no persistent alias catalog or key
rotation migration. If privacy is enabled but the key or tenant context is
missing, the call fails before network access. This V1 boundary covers the
agents service's sanctioned chat calls. API-service-owned LLM synthesis paths
remain a separate deployment boundary and must not be described as protected
until they are routed through a shared service/package in a follow-up release.

Direct Copilot, contextual Copilot, Explain, and NL-playbook requests do not
trust a browser-controlled `X-Tenant-Id` by itself. An authenticated upstream
must either set `request.state.authenticated_tenant_id` or add
`X-AiSOC-Tenant-Signature`, the HMAC of the tenant identifier using
`AISOC_AGENTS_TENANT_SIGNING_KEY`. For explicit local development only,
`AISOC_AGENTS_ALLOW_UNSIGNED_TENANT_HEADER=1` accepts the unsigned header; the
agents service refuses that escape hatch when `AISOC_ENV=production`. With
privacy enabled, an unavailable trusted tenant causes deterministic fallback or
failure before provider egress.

Both the root and demo Compose definitions pass the privacy settings into the
agents container with privacy disabled and secret values empty by default.

### Offline privacy smoke tests

From `services/agents`, use a temporary synthetic key. Both commands are local
and make zero network calls:

```bash
export AISOC_PRIVACY_TOKEN_KEY="$(openssl rand -hex 32)"
PYTHONPATH=. python -m app.scripts.privacy_smoke --tenant-id synthetic-smoke
PYTHONPATH=. python -m app.scripts.privacy_splunk_smoke --tenant-id synthetic-smoke
```

Each prints `ORIGINAL`, `PROVIDER_SAFE`, and `REHYDRATED`, then finishes with
`INVARIANTS: PASS`.

### Optional real-provider A/B probe

The provider probe is opt-in and never runs in CI. It uses the fused-alert
state builder, auto-triage agent, central model factory, safe invocation
contract, and privacy gateway. It never prints API keys, privacy keys, or a
credential-bearing provider URL:

```bash
PYTHONPATH=. python -m app.scripts.privacy_provider_probe --privacy on
PYTHONPATH=. python -m app.scripts.privacy_provider_probe --privacy off
```

These commands perform a real provider call using `OPENAI_BASE_URL`,
`OPENAI_API_KEY`, and `AISOC_MODEL_PIN_TRIAGE`. Use synthetic input only and
compare the ON/OFF results for operational A/B validation.

## Task aliases

The shipped aliases mirror AiSOC's workloads. They live in
`infra/litellm/config.yaml`:

| Alias                 | Workload                                   | Shipped default   |
| --------------------- | ------------------------------------------ | ----------------- |
| `aisoc-triage`        | Auto-triage of fused alerts (high volume)  | `gpt-4o-mini`     |
| `aisoc-recon`         | Recon / enrichment reasoning               | `gpt-4o-mini`     |
| `aisoc-investigation` | Deep multi-step investigation              | `gpt-4o`          |
| `aisoc-copilot`       | Contextual analyst copilot                 | `gpt-4o-mini`     |
| `aisoc-summary`       | Alert / incident summaries                 | `gpt-4o-mini`     |
| `aisoc-report`        | Analyst-facing report write-ups            | `gpt-4o`          |
| `aisoc-nl`            | NL→query / NL→detection translation        | `gpt-4o-mini`     |

The "shipped default" is only the *example* mapping in the config — the whole
point is that you change it. The alias names stay constant.

## Enable the gateway

The `litellm` service is defined in `docker-compose.yml` and starts with the
stack. To route AiSOC through it, set in your `.env`:

```bash
LITELLM_MASTER_KEY=<a-strong-key>          # AiSOC authenticates to the gateway with this
OPENAI_API_KEY=<your-real-provider-key>    # LiteLLM uses this to reach the upstream model
OPENAI_BASE_URL=http://litellm:4000/v1     # send AiSOC's calls to the gateway
# and set AiSOC's client key to the gateway key:
# OPENAI_API_KEY=${LITELLM_MASTER_KEY}     # (in the AiSOC services' environment)
```

AiSOC now requests a task **alias** for every live call, so an alias only
resolves when it reaches the gateway. If you don't run the gateway, pin each
role to a concrete provider model instead (the **escape hatch**):

```bash
AISOC_MODEL_PIN_TRIAGE=gpt-4o-mini
AISOC_MODEL_PIN_INVESTIGATION=gpt-4o
# … one per role: triage, recon, investigation, copilot, summary, report, nl
```

With neither the gateway nor pin overrides configured, AiSOC uses its
deterministic offline path. (`OPENAI_MODEL` still applies to the separate
"explain this alert" / BYOK path.)

## Direct provider (no LiteLLM) — Arvan / DeepSeek

For an OpenAI-compatible gateway such as Arvan Cloud AI DeepSeek-V4-Flash,
skip LiteLLM and point AiSOC straight at the provider. This is what drives
**AI Investigation** (`POST /api/v1/agents/investigate`) and **Copilot**:

```bash
OPENAI_BASE_URL=https://arvancloudai.ir/gateway/models/DeepSeek-V4-Flash/<gateway-token>/v1
OPENAI_API_KEY=<your-api-key>
AISOC_MODEL_PIN_TRIAGE=DeepSeek-V4-Flash
AISOC_MODEL_PIN_RECON=DeepSeek-V4-Flash
AISOC_MODEL_PIN_INVESTIGATION=DeepSeek-V4-Flash
AISOC_MODEL_PIN_COPILOT=DeepSeek-V4-Flash
AISOC_MODEL_PIN_SUMMARY=DeepSeek-V4-Flash
AISOC_MODEL_PIN_REPORT=DeepSeek-V4-Flash
AISOC_MODEL_PIN_NL=DeepSeek-V4-Flash
AISOC_DETERMINISTIC=0
```

Never commit the API key or gateway token — keep them in `.env` / Fly secrets.

DeepSeek / Arvan gateways are **chat-only**. MITRE→Qdrant embedding is skipped
automatically when `OPENAI_BASE_URL` points at Arvan/DeepSeek unless you set a
separate embeddings provider:

```bash
AISOC_EMBEDDING_BASE_URL=https://api.openai.com/v1
AISOC_EMBEDDING_API_KEY=<openai-embeddings-key>
# or explicitly disable:
AISOC_SKIP_EMBEDDINGS=1
```

## Re-point a task to a local model

Duplicate the alias in `infra/litellm/config.yaml` with a local backend. The
alias name **must stay the same** so AiSOC is unaware of the swap:

```yaml
- model_name: aisoc-triage
  litellm_params:
    model: ollama/llama3.1
    api_base: http://ollama:11434
```

Commented Ollama, vLLM, and Anthropic examples ship in the config. For a fully
offline deployment, see [air-gapped operation](./air-gapped.md), which fronts a
local Ollama.

## Observe

- **Metrics:** `curl http://localhost:4000/metrics` (or the Grafana/Prometheus
  stack under the `monitoring` profile) shows `litellm_*` counters broken down
  by task alias and model.
- **Health:** `curl http://localhost:4000/health/liveliness`.

## Notes

- Host port `4000` is bound to `127.0.0.1` only, like the rest of the stack.
- No provider key is ever written to `infra/litellm/config.yaml` — aliases
  resolve credentials from the process environment (`os.environ/...`).
