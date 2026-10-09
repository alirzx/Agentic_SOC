---
title: LLM routing and privacy gateway
description: Operate model routing and the centralized privacy boundary for sanctioned services/agents external chat egress.
---

# LLM routing and privacy gateway

AiSOC runs several distinct LLM workloads — triage, recon, investigation, the
contextual copilot, summaries, reports, and natural-language generation. The
**LiteLLM gateway** is the preferred routing entry point for these workloads.
AiSOC asks for a **logical task alias**; the gateway decides which real
provider and model that alias resolves to. Direct OpenAI-compatible routing is
also supported, so privacy enforcement belongs in the agents-service client
boundary rather than in one particular routing deployment.

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

The provider-bound pipeline is:

```text
Internal canonical evidence
→ context minimization / prompt serialization
→ semantic and path-aware identity discovery
→ irreversible secret masking
→ tenant-scoped deterministic pseudonymization
→ privacy-aware system guidance
→ LLM input contract
→ external chat provider
→ exact active-session rehydration
```

The identity families are `USER`, `EMAIL`, `HOST`, `IP`, `IP_OPAQUE`,
`ASSET`, and `PATH`. `SECRET` values are not identities: they become
`[REDACTED_SECRET]` and never enter the reverse map. Examples use synthetic
values only:

```text
src_ip=B_309                          → IP_OPAQUE_...
device.name=endpoint01.synthetic.test → HOST_...
user=unknown                          → unknown
session_token=synthetic-secret        → [REDACTED_SECRET]
```

Current sanctioned agents-service chat surfaces are:

| Surface | Provider boundary | Tenant context |
| --- | --- | --- |
| Auto-triage and specialized router agents | `safe_ainvoke` | fused worker, graph runner, or router |
| Full investigator agents | `safe_ainvoke` | investigator run/stream lifetime |
| Generic Copilot and Explain | `safe_chat_completions_request` | trusted request tenant |
| Contextual Copilot | `safe_ainvoke` / `safe_astream` | trusted request tenant |
| NL playbook drafting | `safe_ainvoke` | trusted request tenant; deterministic fallback otherwise |
| New runtime triage/investigation | `safe_ainvoke` | `SocOrchestrator.run` lifetime |
| Optional NL-query enhancement | `safe_chat_completions_request` | caller-bound context; currently no production caller |

`app.runtime.llm_gateway.LLMGateway` and the generic tool-loop helper currently
have no production caller. The static no-bypass test still guards them against
future direct model invocation.

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

HMAC aliases are not decrypted. Each active gateway session retains only an
in-memory `alias → original` mapping. A provider-emitted alias in a tool
argument is restored before the local tool executes; any private identity
included in the next model turn is projected again before egress.

Privacy-enabled streaming is intentionally buffered up to
`AISOC_LLM_PRIVACY_STREAM_MAX_CHARS`. The boundary reassembles all provider
chunks before exact restoration, so an alias split between chunks is never
partially exposed to the caller. Privacy-disabled streaming preserves the
underlying chunk behavior.

The response cache uses only provider-safe projected prompt material. Its
namespace includes the tenant-derived privacy namespace and privacy policy
version, preventing cross-tenant and cross-policy reuse. The stable identity
HMAC namespace remains `aisoc-privacy-v1`; the current projection/cache policy
is `v1.1`.

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

A public-looking FQDN is protected when a structured field, nested path,
typed entity, or contextual label establishes that it is tenant-owned. A
public-looking FQDN appearing only in unconstrained prose may remain visible so
public IOC reasoning is not destroyed. Organization-owned domain and CIDR
inventory is intentionally deferred.

Both the root and demo Compose definitions pass the privacy settings into the
agents container with privacy disabled and secret values empty by default.

### Offline privacy smoke tests

From `services/agents`, use a temporary synthetic key. Both commands are local
and make zero network calls:

```bash
export AISOC_LLM_PRIVACY_ENABLED=1
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

### Hermetic regression checks

Privacy-sensitive tests own their environment. Run the same focused selection
once with a synthetic privacy-enabled parent shell and once with both privacy
variables absent; both runs must pass. This proves a developer's exported
variables cannot silently change test semantics. Provider calls are mocked in
unit tests, and the optional probe above is the only intentionally real chat
test.

### External model egress outside the chat boundary

At startup, `app.tools.mitre_full` can send the public ATT&CK technique corpus
to a configured embeddings API before storing vectors in Qdrant. This contains
public corpus text, not tenant evidence, and is intentionally outside the chat
Privacy Gateway. The same module exposes a semantic-search embedding helper,
but no production caller currently uses it. It must not be connected to
tenant-private query text until the separate embedding privacy policy exists.

### V1.1 boundaries and later work

V1.1 does not implement data-classification tiers, an
`ALLOW/TOKENIZE/MASK/BLOCK/LOCAL_ONLY` policy engine, organization-owned
CIDR/domain inventory, a persistent encrypted token vault, key-rotation
migration, output DLP, provider sensitivity routing, configurable token scope,
tenant-private embedding policy, or a cross-service privacy gateway. These are
later-phase controls and must not be inferred from the agents-service chat
boundary described here.

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

Factory-routed agents workloads request a task **alias**, so an alias only
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
