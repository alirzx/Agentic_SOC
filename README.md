<div align="center">

<img src="apps/web/public/logo-mark.svg" alt="Soorin Agentic SOC" width="120" />

# Soorin Agentic SOC

Self-hostable AI Security Operations Center from [Soorin Security](https://soorinsec.ir). Agent prompts, tool calls, and rationale are logged step-by-step and replayable.

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![GitHub](https://img.shields.io/badge/GitHub-SoorinSecurity%2FAgentic__SOC-181717?style=flat-square&logo=github)](https://github.com/SoorinSecurity/Agentic_SOC)

</div>

---

## Run it locally

This is **your** fork. Demo images are **built from this repo** (not upstream GHCR), so playbooks, agents, and other local changes are in the containers.

```bash
git clone https://github.com/SoorinSecurity/Agentic_SOC.git
cd Agentic_SOC
pnpm install
cp .env.example .env
pnpm aisoc:demo
```

On a clean Ubuntu 22.04 machine (installs Docker, Node 20, pnpm, then starts the stack):

```bash
curl -fsSL https://raw.githubusercontent.com/SoorinSecurity/Agentic_SOC/main/install.sh | bash
```

Or from inside a clone: `./install.sh`

When it finishes, open:

- Console: http://localhost:5000
- Showcase case: http://localhost:5000/cases/INC-RT-001?tab=ledger

Stop with `pnpm aisoc:demo:down`. Health check: `pnpm aisoc:doctor`.

| If you have… | Run this | What you get |
|---|---|---|
| **Python 3.10+** (no Docker) | `pip install -e packages/aisoc-sandbox && aisoc-sandbox demo` | Offline Detect → Triage → Hunt → Respond walkthrough. No API key. |
| **Docker + pnpm** | `pnpm aisoc:demo` | Local stack (Postgres, Redis, Kafka, api, agents, web). |
| **Nothing** | `./install.sh` | Bootstraps Docker, Node, pnpm, git; then runs the demo. |

For live LLM investigation, put at least one key in `.env`:

```env
OPENAI_API_KEY=sk-...
# or
ANTHROPIC_API_KEY=sk-ant-...
```

Default seeded login (full stack): `admin@aisoc.local` / `changeme`. Demo path auto-logs in as `demo@tryaisoc.com`.

راهنمای نصب گام‌به‌گام روی اوبونتو ۲۲.۰۴: [`docs/INSTALL_UBUNTU.md`](docs/INSTALL_UBUNTU.md). نصب یک‌کلیکی: [`docs/QUICK_INSTALL.md`](docs/QUICK_INSTALL.md). توسعه سرویس‌به‌سرویس: [`docs/runbooks/LOCAL_DEVELOPMENT.md`](docs/runbooks/LOCAL_DEVELOPMENT.md).

---

## What this product is

Soorin Agentic SOC ingests security events, correlates them, runs AI-driven investigation, and surfaces the result in a SOC console. Decisions are stored in an Investigation Ledger (prompt, response, evidence, tool calls). You control what leaves your perimeter; run a hosted LLM or a local model (Ollama/vLLM) for an air-gapped path.

The orchestrator lives in [`services/agents/`](services/agents/). Soorin runtime contracts are in [`services/agents/app/runtime/`](services/agents/app/runtime/). Spec: [`Soorin_Agentic_SOC_Specification.md`](Soorin_Agentic_SOC_Specification.md).

---

## What you'll see in the console

| Page | Description |
|---|---|
| **Alerts** | Queue with SLA, claim, triage, Investigation Rail |
| **Cases** | Workspace + replayable Investigation Ledger |
| **Hunt** | Natural-language hunt → ES\|QL / SPL / KQL |
| **Connectors** | Schema-driven click-and-connect sources |

---

## Architecture

Connectors → ingest (OCSF) → Kafka → fusion / detection / agents → Postgres + console.

Apps: `apps/web` (Next.js), `apps/docs`. Backend under `services/` (api, agents, fusion, connectors, ingest, …). Local compose: [`infra/compose/`](infra/compose/).

---

## What's in the box

- **83 click-and-connect data connectors** (EDR/XDR, SIEM, NDR, cloud, CNAPP, identity, SaaS, VCS, K8s audit, network) with schema-driven config, live `Test connection`, and vault-encrypted secrets. Federated search across Splunk SPL / Sentinel KQL / Elastic ES|QL / QRadar AQL. Walkthrough: [`apps/docs/docs/connectors/index.md`](apps/docs/docs/connectors/index.md).
- End-to-end SIEM spine: connector ingest → ClickHouse lake → detection corpus → fused alert.
- Autonomous triage with copilot / dry-run response by default (human approval for real actions).
- Investigation Rail + replayable Investigation Ledger.
- Hunt-as-Code and `/hunt` workbench.
- Soorin golden playbooks and technique mapping under `playbooks/doc/` and `services/agents/app/runtime/playbooks/`.

---

## Extend it

- **Detection rule.** YAML under [`detections/`](detections/) plus fixtures.
- **Connector.** Subclass `BaseConnector` in `services/connectors/app/connectors/`, register it, add `plugins/<id>/plugin.yaml`.
- **Playbook.** YAML under [`playbooks/`](playbooks/).

---

## Company

- Website: [soorinsec.ir](https://soorinsec.ir)
- GitHub: [SoorinSecurity/Agentic_SOC](https://github.com/SoorinSecurity/Agentic_SOC)
- Email: [info@soorinsec.ir](mailto:info@soorinsec.ir)
- LinkedIn: [soorinsec](https://www.linkedin.com/company/soorinsec)

Internal env vars and Docker service names still use the `AISOC_*` prefix so the runtime does not break. That is expected.

---

## License

[MIT](LICENSE) — original upstream contributors; this fork is maintained by Soorin Security.

[Report a bug](https://github.com/SoorinSecurity/Agentic_SOC/issues) · [Docs](apps/docs/)
