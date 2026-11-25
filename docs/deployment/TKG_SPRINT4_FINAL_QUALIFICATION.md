# Sprint 4 final qualification — checkpoint review

Status: **implementation substantially complete; release qualification OPEN**.
Reviewed SOC checkpoint `5b745039d7e15fb8909d5a6345f014065a5756b3`
and TKG checkpoint `50f323e7fd56091e20ac311ba017d662acb464d4`.
This record replaces the missing qualification document linked by the Server 55 runbook.
It is not a report of a new execution.

## Evidence and release gates

| Gate | Status | Evidence / remaining action |
|---|---|---|
| Organization main integration | Source reviewed | SOC merge d9e1781d includes e6bf4cf0. |
| Durable producer and receipt reconciler | Implemented; regression pending | Migration 094/095, frozen requests, fenced updates, separate status PAT and DB login. |
| Multi-root stateful Recon | Implemented; regression pending | Signed scope, bounded seeds, five read tools, working memory, protected planner and final assessment. |
| Search wire identity | Adapter correction included; regression pending | TKG ChunkView uses id; SOC normalizes the chunk identity and rejects contradictory aliases. Search does not confer graph authority. |
| Budgets and coverage | Implemented; qualification pending | Byte-based conservative packing and admission estimates are not provider token measurements. Record stop reason, omitted evidence and actual usage. |
| Privacy | Earlier baseline passed; new multi-turn run pending | Keep DLP mandatory. Confirm provider-bound redaction, successful decoding, isolation, failure handling and context lifetime for this revision. |
| Static Compose matrix | Passed as reported by Codex | Actual Server 55 overrides and credential mounts not checked by that run. |
| Full corpus materialization | OPEN | Earlier 64/640 admission tests materialized six samples each. Interrupted medium qualification has no completion record. |
| Real model evaluation / signed full pipeline | OPEN | Prove Connector to Kafka/Fusion, outbox, bound receipt, Recon tools and report with synthetic data. |
| Image and deployment qualification | OPEN | Verify migrations, image revision/digest, model caches, existing volume identity, role grants, TLS and resource headroom before cutover. |
| Final CI / merge | OPEN | Run targeted regression on the reviewed heads. Do not claim production readiness from the existence of tests. |

## Configuration and deployment notes

- Keep TKG and Recon flags disabled until their specific prerequisites pass.
- DeepSeek-V4-Flash is not in the current Recon model price table. Set both reviewed
  `AISOC_TKG_RECON_UNKNOWN_INPUT_USD_PER_1K` and
  `AISOC_TKG_RECON_UNKNOWN_OUTPUT_USD_PER_1K` values for the actual deployment
  tariff; do not use an invented price or zero. The unknown-price admission guard
  intentionally stops protected Historical Recon.
- Use the existing SOC security override as the final Compose input. Preserve DLP
  CA, credentials and privacy network. Use distinct reader, ingest and receipt
  credentials and separate database logins for submission and polling.
- The TKG hardened production interface validates immutable registry digests,
  existing volume identity and a unified CPU model service. A historical local
  build tag is not a registry digest. Do not substitute new empty volumes or
  recreate databases to satisfy a static preflight.
- The new TKG script is an inspection/preflight interface, not a build or rollout
  command. Follow the reviewed release procedure for image production and cutover.
- Metrics exported by the standalone workers are local text files; arrange
  approved collection before claiming dashboard coverage.
- Verify receipt authorization with Viewer membership and explicit KB scope,
  current RLS/GRANTs and credential revocation. Do not grant admin to Recon.
- Keep full materialization, production model evaluation and heavy image builds
  off the constrained developer machine. Use an approved CI or server window.

## Sequence

1. Lightweight targeted regression and source review on both feature branches.
2. Verify actual server inventory, approved immutable images, backups and recovery
   compatibility; validate Compose and migration prerequisites.
3. Qualify TKG first, then SOC with integration disabled, retaining previous images.
4. Enable synthetic-workspace submission and polling; prove bound and replay.
5. Enable preflight Recon, then bounded planner, then Deep Case by explicit approval.
6. Record evidence of full pipeline, privacy, model quality and resource behavior
   before marking the release accepted.

No server deployment, role change, credential rotation, container operation or
live provider call was performed by this checkpoint review.
