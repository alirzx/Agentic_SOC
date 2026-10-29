# Automation Rules Debugging Guide

## Common Issues & Solutions

### Issue: Alerts don't match automation rules

**Symptoms:**
- Alerts are created in database
- Automation rules are defined
- But run_rules_for_trigger doesn't trigger any actions

**Root Causes:**

#### 1. Default rules not seeded yet
**Check:** Query `SELECT COUNT(*) FROM automation_rules;`

**If empty (0 rows):**
```bash
# Call the seeding endpoint
curl -X GET http://localhost:8000/api/v1/automation-rules \
  -H "Cookie: aisoc.session=YOUR_TOKEN"
```

This endpoint auto-seeds `DEFAULT_AUTOMATION_RULES` for new tenants.

#### 2. Subject fields missing in alert creation
**Root Cause:** When `run_rules_for_trigger()` is called from `alerts.py`, the `subject_fields` dict must include ALL fields that conditions may reference.

**Fields required in subject_fields:**
- severity
- status  
- priority
- confidence
- confidence_label
- funnel_stage
- disposition
- source
- connector_type
- category
- title
- description
- tags
- affected_ips
- affected_hosts
- affected_users
- risk_score
- mitre_tactics
- mitre_techniques
- rule_name

**If missing:** Rules that reference those fields will silently fail (condition evaluation returns False).

**Check the code:**
- `services/api/app/api/v1/endpoints/alerts.py` line ~638 (alert.created)
- `services/api/app/api/v1/endpoints/alerts.py` line ~1185 (alert.updated)

#### 3. Condition evaluation logic
**Check:** `services/api/app/services/runbook/condition_eval.py`

**How it works:**
1. For each condition dict: `{"field": "severity", "op": "in", "value": ["high", "critical"]}`
2. Extract `actual = subject_fields[field]`
3. If field missing → `actual = None` → condition fails
4. Compare using operator (eq, in, contains, etc.)

**Common operators:**
- `eq` - equals (case-insensitive for strings)
- `in` - value in list (case-insensitive)
- `contains` - substring match (case-insensitive)
- `array_contains` - item in array field
- `ge` / `gt` / `le` / `lt` - numeric comparison

**Debug tip:** If a condition is failing unexpectedly, log the subject_fields dict and verify the field exists and has the expected value.

---

## Testing

Run the automation rule tests:

```bash
cd services/api
python -m pytest tests/test_automation_rule_subject_fields.py -xvs
python -m pytest tests/test_runbook_automation.py -xvs
python -m pytest tests/test_runbook_gate.py -xvs
```

## Related Code

| File | Purpose |
|------|---------|
| `services/api/app/api/v1/endpoints/alerts.py` | Alert creation/update → calls `run_rules_for_trigger()` with subject_fields |
| `services/api/app/api/v1/endpoints/runbook.py` | Seeds `DEFAULT_AUTOMATION_RULES` on first access |
| `services/api/app/services/runbook/rule_executor.py` | Executes rules: queries automation_rules table, evaluates conditions |
| `services/api/app/services/runbook/condition_eval.py` | Safe condition evaluator (no eval(), whitelisted operators) |
| `services/api/tests/test_automation_rule_subject_fields.py` | Regression test for subject_fields completeness |
| `services/api/tests/test_runbook_automation.py` | Tests for condition evaluation & default rules |

## Regression Test Coverage

The following regression tests prevent the subject_fields bug from recurring:

1. **test_subject_fields_completeness_for_alerts()**
   - Verifies all `_ALLOWED_FIELDS` are present in subject_fields dict
   - Fails if any allowed field is missing

2. **test_condition_eval_allowed_fields_are_reasonable()**
   - Sanity check on `_ALLOWED_FIELDS` definition
   - Ensures no documented fields are missing

3. **test_each_default_rule_matches_a_realistic_subject()**
   - Parametrized over `DEFAULT_AUTOMATION_RULES`
   - Verifies each rule's conditions match a built subject dict

4. **test_each_default_rule_rejects_a_non_matching_subject()**
   - Parametrized over `DEFAULT_AUTOMATION_RULES`
   - Verifies each rule's conditions DON'T match a flipped subject dict
