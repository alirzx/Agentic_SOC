# Agentic_SOC Real-Provider DLP Evaluation

This directory is a reproducible, side-effect-controlled evaluation harness for the Agentic_SOC LLM Privacy / Data Preventing Layer.

It deliberately reuses the product's own agent code, prompts, `safe_ainvoke` boundary, Privacy Gateway, deterministic tenant-scoped pseudonymization, Human Trace, and provider model routing. It is not a separate mock implementation of the DLP algorithm.

## What it tests

Each real LLM call is captured as four evidence stages:

1. `INTERNAL_INPUT` — agent prompt/context before privacy projection.
2. `PROVIDER_INPUT` — exact provider-visible prompt after DLP projection.
3. `PROVIDER_RESPONSE` — response returned by the external model.
4. `LOCAL_RESPONSE` — response after exact local alias rehydration.

The harness also runs the existing offline privacy smoke before external calls.

## Safety profile

Normal evaluation mode intentionally disables product mutation paths:

- database writes: off
- Kafka worker path: off
- memory suppression/writeback: off
- worker auto-escalation: off
- response cache: off, so a provider test actually calls the provider
- Human Trace: on for evaluation artifacts only

Generated traces may contain sensitive internal data and are written under `runs/`, which is ignored by Git. Never commit that directory.

Provider API keys and privacy keys are read interactively and are never written to the repository or result metadata.

## Default tenant

Normal test runs automatically use the repository seed tenant:

```text
00000000-0000-0000-0000-000000000001
```

The runner does **not** ask the user for a tenant ID.

A full deployment with another canonical tenant can override it without editing files:

```bash
AISOC_TEST_TENANT_UUID="<canonical-tenant-uuid>" ./privacy_real_eval/run_real_dlp_eval.sh
```

## Requirements

Run from an Agentic_SOC clone containing `services/agents`. The runner prefers the repository `.venv`, then `services/agents/.venv`, then `python3`.

At runtime the user supplies only operational/provider information:

- workflow: Auto-Triage, Investigator, or both
- input source/scenario
- `OPENAI_BASE_URL`
- `OPENAI_API_KEY`
- provider model name
- `AISOC_PRIVACY_TOKEN_KEY`
- optional case/test ID and Human Trace size

No provider credential is stored.

## Run

From the repository root:

```bash
./privacy_real_eval/run_real_dlp_eval.sh
```

Or:

```bash
cd privacy_real_eval
./run_real_dlp_eval.sh
```

### Input modes

The runner supports:

1. **Bundled sanitized Splunk scenarios**. Recommended for reproducible regression tests.
2. **Existing JSON/JSONL**. Use an exported or prepared notable.
3. **Live read-only Splunk REST export**. Requires a Splunk management URL, token, and an exact read-only SPL search.

All JSON/JSONL is validated before a provider call.

## Investigator modes

The default is:

```text
AISOC_DLP_EVAL_INTERNAL_SERVICES=isolated
```

This still runs the real `InvestigatorOrchestrator`, Recon, Forensic, Responder and Report Writer, their real prompts, the real LLM contract, DLP projection and real provider calls. Only unavailable internal context/enrichment network calls are replaced with deterministic local stubs so a developer laptop does not need the full deployed stack.

When running against the full Agentic_SOC stack:

```bash
AISOC_DLP_EVAL_INTERNAL_SERVICES=live ./privacy_real_eval/run_real_dlp_eval.sh
```

## Bundled scenarios

The fixtures in `mock_data/` preserve the field layout and nested Splunk/OCSF-style structures observed in real product notables, but production hostnames, usernames, connector IDs and event IDs are sanitized before committing.

Current scenarios include password spraying, suspicious Windows registry modification, PowerShell from WindowsApps, inbound-firewall registry modification, a password spray with a successful authentication, and an authorized/benign registry-change control.

These fixtures are designed to exercise:

- private/opaque source identifiers
- host/device identities
- user identities
- nested `splunk_notable` fields
- `risk_object` / `normalized_risk_object`
- MITRE metadata
- raw nested event strings
- placeholder values such as `unknown`
- malicious and benign/authorized reasoning paths

## Output

Every run gets a private timestamped directory under `runs/`.

Typical evidence:

```text
comparison_auto_triage.json
result_auto_triage.json
trace_auto_triage.jsonl
comparison_investigator.json
result_investigator.json
investigator_llm_audit.json
input_snapshot.json
run_meta.json
summary.json
console.log
test_profile.txt
```

Use the `comparison_*.json` files for the final DLP report because they align the four privacy-boundary stages for each model call.

## Important interpretation

HMAC aliases are deterministic pseudonyms, not encrypted ciphertext. A known alias is restored only from the active local token-to-original mapping. Secrets represented as `[REDACTED_SECRET]` are intentionally irreversible.

A successful evaluation should demonstrate that raw private identities are absent from the provider-visible stage while public security semantics, relationships, MITRE IDs, scores and rule context remain usable by the model.
