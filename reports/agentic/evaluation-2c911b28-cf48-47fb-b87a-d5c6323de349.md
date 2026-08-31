# Agentic SOC Benchmark Report

**Run ID:** `2c911b28-cf48-47fb-b87a-d5c6323de349`
**Dataset:** golden-benchmark-v1 (1.0)
**Pipeline Validity:** VALID

## Model & Version
- Provider: arvancloudai.ir
- Model: DeepSeek-V4-Flash
- Agent: runtime/v1.0
- Workflow: agentic-eval-v1.5
- Prompt: agentic-soc-runtime/v1
- Tool: soc-tools/v1

## Cases
- Total: 12
- Completed: 12
- Failed: 0

## Scores
- Existing SOC: 1.0
- Agentic SOC: 0.6167052469135802
- Delta: -0.3832947530864198

## Metrics
- Evidence Support: 63.72%
- MITRE F1: 16.67%
- IOC F1: 72.22%
- Correlation F1: 91.67%
- Unsupported Claims: 5.90%
- Dangerous Actions: 0.0
- Action Leakage: 0.0

## Cost & Latency
- Cost status: NOT_AVAILABLE
- Estimated cost: 0.0
- Avg latency ms: 391.5833333333333

## Production Readiness
- Status: GATES_FAILED

## Executive Summary
Evaluated 12 cases on golden-benchmark-v1: agentic=0.62 existing=1.00 delta=-0.38; readiness=GATES_FAILED.

## Limitations
- Synthetic golden cases labeled SYNTHETIC — not production ground truth.
- Analyst efficiency NOT_AVAILABLE unless operator timings supplied.
- Primary scoring is deterministic; LLM judge excluded from readiness.