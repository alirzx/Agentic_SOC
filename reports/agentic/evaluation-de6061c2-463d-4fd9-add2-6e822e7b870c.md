# Agentic SOC Benchmark Report

**Run ID:** `de6061c2-463d-4fd9-add2-6e822e7b870c`
**Dataset:** golden-benchmark-v1 (1.0)
**Pipeline Validity:** PIPELINE_DEGRADED

## Model & Version
- Provider: arvancloudai.ir
- Model: DeepSeek-V4-Flash
- Agent: runtime/v2.0
- Workflow: agentic-eval-v1.6
- Prompt: agentic-soc-llm/v1
- Tool: soc-tools/v1

## Cases
- Total: 1
- Completed: 1
- Failed: 0

## Scores
- Existing SOC: N/A
- Agentic SOC: 0.5833333333333334
- Delta: N/A

## Metrics
- Evidence Support: 50.00%
- MITRE F1: 0.00%
- IOC F1: 100.00%
- Correlation F1: 100.00%
- Unsupported Claims: 25.00%
- Dangerous Actions: 0.0
- Action Leakage: 0.0

## Cost & Latency
- Cost status: MEASURED
- Estimated cost: 0.010151
- Avg latency ms: 46856.0

## Production Readiness
- Status: GATES_FAILED

## Executive Summary
Evaluated 1 cases on golden-benchmark-v1: agentic=0.58 existing=1.00 delta=-0.42; readiness=GATES_FAILED.

## Limitations
- Synthetic golden cases labeled SYNTHETIC — not production ground truth.
- Analyst efficiency NOT_AVAILABLE unless operator timings supplied.
- Primary scoring is deterministic; LLM judge excluded from readiness.
- Pipeline ran with degraded adapters — see pipeline_status.