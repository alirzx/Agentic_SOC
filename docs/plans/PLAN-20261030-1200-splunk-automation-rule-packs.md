# Plan — Automation-rule packs for Splunk (Windows) correlation rules

**Date Created:** 2026-10-30 12:00
**Status:** IMPLEMENTED — verified below
**Owner:** Runbook surface (`services/api` + `apps/web`)
**Detection corpus:** local checkout of Splunk Security Content (`detections/endpoint/**`)

---

## Goal

Give the Runbook an importable set of automation rules that fire on **named Splunk
correlation searches** for Windows endpoints, instead of forcing every tenant to author
rules from scratch against generic alert shape.

## What the corpus actually gives us

| Question | Answer (measured, not assumed) |
| --- | --- |
| Where do Windows detections live? | `detections/endpoint/**/*.yml` in Splunk Security Content |
| What is the detection name? | the YAML `name:` field — the same string a notable carries as `search_name` |
| Is `asset_type` usable? | No. In the current corpus it is effectively always `Endpoint`; "Windows" has to come from `data_source` (Sysmon / XmlWinEventLog) or the SPL itself (`` `sysmon` ``, `EventCode=`) |
| How many Windows detections? | ~1 399 of ~2 181 endpoint detections |
| Does AiSOC already have the field? | Yes — `rule_name` is in `_ALLOWED_FIELDS` and is populated from the notable, so no encoding work was needed |

## Design

1. **`services/api/app/services/runbook/packs.py`** — a `RulePack` / `PackRule` registry
   (`PACKS`, `list_packs`, `get_pack`, `pack_rule_payloads`, `covered_detection_names`).
   Each rule is one condition:

   ```json
   {"field": "rule_name", "op": "in", "value": ["Access LSASS Memory for Dump Creation", "..."]}
   ```

   One `in` condition, **not** N `eq` conditions: conditions are ANDed, so N separate
   equalities could never match a single alert.

2. **Pack `windows-splunk`** — 31 hand-picked, high-value Windows detections groups,
   covering 93 ESCU detection names:

   | Action | Rules | Autonomy |
   | --- | --- | --- |
   | `add_alert_tag` | 11 | L1 |
   | `create_case` | 18 | L2 |
   | `isolate_host` | 2 | L3 |

   Every rule: `dry_run=True`, `subject_type="alert"`, `trigger_type="alert.created"`,
   `owner_team="detection-engineering"`, `docs_ref` → console doc anchor. Autonomy is
   deliberately conservative: importing installs *decisions*, an operator raises
   autonomy per rule after previewing matches against real alerts.

3. **API** (`app/api/v1/endpoints/runbook.py`):

   | Route | Permission | Behaviour |
   | --- | --- | --- |
   | `GET /runbook/automation-rules/packs` | `alerts:read` | pack id, label, description, source, `rule_count`, `covered_detections`, `docs_ref` |
   | `POST /runbook/automation-rules/packs/{pack_id}/import` | `alerts:write` | 404 unknown pack; inserts rules whose names are not already present; returns `created` / `skipped` |

   Both declared **before** `/automation-rules/{rule_id}` — FastAPI matches in
   registration order, so a later declaration would parse `packs` as a rule id (the same
   class of defect Phase 13 fixed for the ledger catch-all). Conditions are validated
   with `validate_conditions()` before insert, so a malformed rule fails the import
   loudly rather than installing an inert row.

4. **UI** (`apps/web/src/components/runbook/AutomationRulesView.tsx`) — a **Packs**
   button opens a dialog listing packs with rule/detection counts and an **Import**
   action; the result is reported as `Imported N rules (M already present)` and the list
   reloads. No Splunk-search picker in this iteration (deliberate: `rule_name` matching
   needs no corpus introspection at author time).

5. **Not done on purpose**
   - Seeding packs for every tenant. A tenant without Windows telemetry would get rules
     that can never fire — visible as "configured" while doing nothing.
   - Matching on `asset_type`/`data_source` instead of `rule_name`. Names come from the
     notable and are exact; inferring "Windows-ness" from telemetry heuristics would
     mismatch silently.
   - Auto-raising autonomy for pack rules.

## Defect found while testing (fixed)

`condition_eval._coerce()` stringified a list when the subject field was a string, which
turned `in` into a **substring** test: `rule_name in [93 names]` matched every alert whose
`rule_name` was `""`. Containers are no longer coerced; `_op_in` is membership-only (a
scalar value becomes a one-item list, a non-iterable right side fails closed), and
`contains` remains the substring operator. The regression assertions live in
`tests/test_automation_rule_packs.py` and `tests/test_runbook_automation.py`.

## Tests

`services/api/tests/test_automation_rule_packs.py`:

- every pack rule's conditions pass `validate_conditions()`;
- a subject built from each rule's first ESCU name matches, and a neutral subject
  (`rule_name=""`, `severity="info"`) does not;
- the pack reports non-zero rules and detections, and detection names are unique per
  pack;
- `GET /packs` and `POST /packs/{id}/import` happy path, unknown pack → 404, existing
  names skipped.

## Docs

- `apps/docs/docs/console/runbook.md` → *Automation Rules → Windows — Splunk rule pack*
- `docs/operations/runbook.md` → *Rule packs (Splunk detections)*
- `docs/plans/RUNBOOK-PROGRESS.md` → Phase 14

## Verified

- `pytest` api runbook suites (11 files incl. `test_automation_rule_packs.py`) → **420
  passed, 15 skipped**
- `ruff check` on `packs.py`, `condition_eval.py`, `endpoints/runbook.py` and both touched
  test files → clean
- `tsc --noEmit` (apps/web) → clean
- `vitest run src/components/runbook` → **24 passed** (the new Packs-dialog test is
  `imports a rule pack and reports what changed`)
