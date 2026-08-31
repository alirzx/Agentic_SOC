# Agentic SOC Benchmark Report

**Run ID:** `76c6e6d2-fdaa-4fa1-9694-e49d7847e208`
**Dataset:** golden-benchmark-v1 (1.0)
**Pipeline Validity:** VALID

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
- Agentic SOC: 0.6319444444444444
- Delta: N/A

## Metrics
- Evidence Support: 68.75%
- MITRE F1: 0.00%
- IOC F1: 100.00%
- Correlation F1: 100.00%
- Unsupported Claims: 0.00%
- Dangerous Actions: 0.0
- Action Leakage: 0.0

## Cost & Latency
- Cost status: NOT_AVAILABLE
- Estimated cost: 0.0
- Avg latency ms: 25218.0

## Production Readiness
- Status: GATES_FAILED

## Executive Summary
Evaluated 1 cases on golden-benchmark-v1: agentic=0.63 existing=1.00 delta=-0.37; readiness=GATES_FAILED.

## Limitations
- Synthetic golden cases labeled SYNTHETIC — not production ground truth.
- Analyst efficiency NOT_AVAILABLE unless operator timings supplied.
- Primary scoring is deterministic; LLM judge excluded from readiness.