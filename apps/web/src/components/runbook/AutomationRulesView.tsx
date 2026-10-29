'use client';

import type { FC } from 'react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { AlertTriangle, Copy, FileDown, FileUp, Info, Plus, Play, Pause, Search, Trash2, ChevronDown, ChevronUp, Shield, Pencil, Loader2 } from 'lucide-react';
import { request } from '@/lib/api';
import { RunbookModal } from '@/components/runbook/RunbookModal';

// ── Types ─────────────────────────────────────────────────────────────────────

interface AutomationRule {
  id: string;
  name: string;
  description: string | null;
  trigger_type: string;
  conditions: Condition[];
  action_slug: string;
  action_params: Record<string, unknown>;
  autonomy_level: string;
  dry_run: boolean;
  enabled: boolean;
  priority: number;
  trigger_count: number;
  last_triggered_at: string | null;
  created_at: string;
  updated_at: string;
  subject_type: string;
  playbook_ref: string | null;
  docs_ref: string | null;
  owner_team: string | null;
  success_count: number;
  failed_count: number;
  denied_count: number;
}

interface Condition {
  field: string;
  op: string;
  value: unknown;
}

interface AlertPreviewItem {
  id: string;
  title: string;
  severity: string;
  confidence: number | null;
  status: string;
  source?: string | null;
  tags?: string[];
}

interface RulePreviewResult {
  alert_id: string;
  matched: boolean;
  status: string;
  action_slug: string;
  reason?: string | null;
}

interface RulePreviewResponse {
  rule_id: string;
  results: RulePreviewResult[];
}

/** Response of the unsaved-draft preview (POST /automation-rules/preview). */
interface RuleDraftPreview {
  evaluated: number;
  matched: number;
  action_slug: string;
  evaluated_against: string;
  matches: Array<{
    alert_id: string;
    title: string;
    severity: string;
    confidence: number | null;
    status: string;
    action_slug: string;
    reason: string | null;
    condition_values?: Record<string, unknown>;
  }>;
  errors: string[];
}

const TRIGGER_LABELS: Record<string, string> = {
  'alert.created': 'Alert created',
  'alert.updated': 'Alert updated',
  // No code path emits these two yet; the list marks them so an operator does
  // not wonder why a saved rule has never fired.
  'case.created': 'Case created (inert)',
  'manual': 'Manual (inert)',
};

const INERT_TRIGGERS = new Set(['case.created', 'manual']);

const AUTONOMY_COLORS: Record<string, string> = {
  L0: 'text-red-400 bg-red-500/10',
  L1: 'text-orange-400 bg-orange-500/10',
  L2: 'text-yellow-400 bg-yellow-500/10',
  L3: 'text-blue-400 bg-blue-500/10',
  L4: 'text-emerald-400 bg-emerald-500/10',
};

const AUTONOMY_LABELS: Record<string, string> = {
  L0: 'Always requires analyst approval',
  L1: 'Suggests to analyst (never executes alone)',
  L2: 'Executes after analyst review',
  L3: 'Executes autonomously above confidence floor',
  L4: 'Fully autonomous — no approval needed',
};

const AUTONOMY_DESCRIPTIONS: Record<string, string> = {
  L0: 'Blocks the action until a human approves it. Best for destructive or high-risk steps.',
  L1: 'Only recommends the action to an analyst; it never executes on its own.',
  L2: 'The rule can run after a human has reviewed it, but it is still gated by the analyst workflow.',
  L3: 'Runs automatically when the alert meets the configured confidence floor and policy checks pass.',
  L4: 'Fully autonomous — no approval step is required. Reserve this for low-risk, trusted actions only.',
};

const AUTONOMY_OPTION_LABELS: Record<string, string> = {
  L0: 'L0 — Always requires analyst approval',
  L1: 'L1 — Suggests to analyst (never executes alone)',
  L2: 'L2 — Executes after analyst review',
  L3: 'L3 — Executes autonomously above confidence floor',
  L4: 'L4 — Fully autonomous — no approval needed',
};

// ── Create / Edit Form ────────────────────────────────────────────────────────

interface RuleFormState {
  name: string;
  description: string;
  trigger_type: string;
  conditions: Condition[];
  action_slug: string;
  autonomy_level: string;
  dry_run: boolean;
  enabled: boolean;
  priority: number;
  subject_type: string;
  playbook_ref: string;
  docs_ref: string;
  owner_team: string;
}

const BLANK_FORM: RuleFormState = {
  name: '',
  description: '',
  trigger_type: 'alert.created',
  conditions: [],
  action_slug: 'close_alert',
  autonomy_level: 'L2',
  dry_run: true,
  enabled: true,
  priority: 100,
  subject_type: 'alert',
  playbook_ref: '',
  docs_ref: '',
  owner_team: '',
};

const SUBJECT_TYPE_OPTIONS = ['alert', 'case', 'incident', 'all'];
const AUTONOMY_OPTIONS = ['L0', 'L1', 'L2', 'L3', 'L4'];

/**
 * Only two triggers are emitted anywhere in the codebase today. The other two
 * are accepted and stored (removing them would break existing rules), so the
 * picker has to say they are inert instead of implying they fire.
 */
const TRIGGER_META: Record<string, { label: string; help: string; live: boolean }> = {
  'alert.created': {
    label: 'Alert created',
    help: 'Fires once, right after an alert row is committed.',
    live: true,
  },
  'alert.updated': {
    label: 'Alert updated',
    help: 'Fires on every committed change to an alert (status, tags, assignee, disposition).',
    live: true,
  },
  'case.created': {
    label: 'Case created (not wired yet)',
    help: 'Accepted and stored, but no code path emits this trigger yet. Rules using it never fire.',
    live: false,
  },
  manual: {
    label: 'Manual (not wired yet)',
    help: 'Accepted and stored, but nothing invokes a manual run yet. Rules using it never fire.',
    live: false,
  },
};
const TRIGGER_OPTIONS = ['alert.created', 'alert.updated', 'case.created', 'manual'];

const SUBJECT_TYPE_HELP: Record<string, string> = {
  alert: 'Runs on alert events only — and only where the trigger matches.',
  case: 'Reserved for case-scoped rules. No case trigger fires yet, so such a rule is stored but idle.',
  incident: 'Reserved for incident-scoped rules. No incident trigger fires yet.',
  all: 'Matches alert, case and incident events alike.',
};

/**
 * Exactly the fields the executor populates for an alert
 * (`app/services/runbook/rule_executor.py::alert_subject_fields`). A field that
 * is not in that dict can never match, so it is not offered here.
 *
 * `risk_score` is deliberately absent: it exists in the alert *response* schema
 * but not on the `alerts` table, so a condition on it would silently never fire.
 */
const FIELD_HELP: Record<string, { help: string; example: string }> = {
  severity: { help: 'Five-tier severity ladder (info → critical).', example: 'critical' },
  status: { help: 'Alert workflow status.', example: 'new' },
  priority: { help: 'Numeric priority on the alert row.', example: '90' },
  confidence: {
    help: 'Fusion confidence as an integer 0–100. Compare numerically (gt/ge/lt).',
    example: '85',
  },
  confidence_label: { help: 'Confidence band emitted by fusion.', example: 'high' },
  funnel_stage: { help: 'Where the alert sits in the response funnel.', example: 'triaged' },
  disposition: {
    help: 'Analyst verdict recorded on the alert.',
    example: 'true_positive',
  },
  source: {
    help: "Producing system; falls back to connector_type, then 'manual'.",
    example: 'splunk',
  },
  connector_type: { help: 'Connector family that produced the alert.', example: 'splunk' },
  category: { help: 'Alert category.', example: 'endpoint' },
  title: { help: 'Alert title. Use contains / startswith rather than eq.', example: 'Mimikatz' },
  description: { help: 'Alert description text.', example: 'lsass access' },
  tags: { help: 'Alert tags (list). Use array_contains.', example: 'ransomware' },
  affected_ips: { help: 'IPs on the alert (list). Use array_contains.', example: '10.0.4.12' },
  affected_hosts: { help: 'Hostnames on the alert (list). Use array_contains.', example: 'FIN-WS-04' },
  affected_users: { help: 'Usernames on the alert (list). Use array_contains.', example: 'alice' },
  mitre_tactics: { help: 'MITRE tactics (list). Use array_contains.', example: 'Credential Access' },
  mitre_techniques: { help: 'MITRE technique ids (list). Use array_contains.', example: 'T1003' },
  rule_name: { help: 'Detection rule that produced the alert.', example: 'Mimikatz string match' },
};
const FIELD_OPTIONS = Object.keys(FIELD_HELP);

const OP_HELP: Record<string, string> = {
  eq: 'Equals. Text compares case-insensitively.',
  ne: 'Not equal.',
  lt: 'Less than (numeric).',
  le: 'Less than or equal.',
  gt: 'Greater than (numeric).',
  ge: 'Greater than or equal.',
  in: 'Value is one of a list — enter JSON, e.g. ["critical","high"].',
  not_in: 'Value is none of a list — enter JSON.',
  contains: 'Text contains the value.',
  not_contains: 'Text does not contain the value.',
  startswith: 'Text starts with the value.',
  endswith: 'Text ends with the value.',
  exists: 'Field has a non-null value. No value needed.',
  not_exists: 'Field is null or missing. No value needed.',
  array_contains: 'List field contains this item.',
  array_not_contains: 'List field does not contain this item.',
};
const OP_OPTIONS = Object.keys(OP_HELP);

// Determine which operators are valid for a given field type
const ARRAY_FIELDS = new Set(['tags', 'affected_ips', 'affected_hosts', 'affected_users', 'mitre_tactics', 'mitre_techniques']);
const NUMERIC_FIELDS = new Set(['confidence', 'priority']);

const getValidOperators = (field: string): string[] => {
  if (ARRAY_FIELDS.has(field)) {
    // Array fields: array_contains, array_not_contains, in, not_in, exists, not_exists
    return ['array_contains', 'array_not_contains', 'in', 'not_in', 'exists', 'not_exists'];
  }
  if (NUMERIC_FIELDS.has(field)) {
    // Numeric fields: all operators except text-based ones
    return ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'not_in', 'exists', 'not_exists'];
  }
  // Text/generic fields: all operators
  return OP_OPTIONS;
};

const toRuleFormState = (rule: AutomationRule): RuleFormState => ({
  name: rule.name,
  description: rule.description ?? '',
  trigger_type: rule.trigger_type,
  conditions: rule.conditions.map((condition) => ({
    field: condition.field,
    op: condition.op,
    value: condition.value,
  })),
  action_slug: rule.action_slug,
  autonomy_level: rule.autonomy_level,
  dry_run: rule.dry_run,
  enabled: rule.enabled,
  priority: rule.priority,
  subject_type: rule.subject_type || 'alert',
  playbook_ref: rule.playbook_ref ?? '',
  docs_ref: rule.docs_ref ?? '',
  owner_team: rule.owner_team ?? '',
});

/** A label with its description and default value attached, never hidden. */
const FieldLabel: FC<{
  label: string;
  help: string;
  hint?: string;
  required?: boolean;
}> = ({ label, help, hint, required }) => (
  <span className="mb-1 flex items-center gap-1 text-xs text-slate-400">
    {label}
    {required && <span className="text-red-400">*</span>}
    <span title={help} aria-label={help} className="inline-flex shrink-0 cursor-help">
      <Info className="h-3 w-3 text-slate-600" />
    </span>
    {hint && <span className="text-[10px] text-slate-600">· {hint}</span>}
  </span>
);

const RuleForm: FC<{
  initial: RuleFormState;
  onSave: (data: RuleFormState) => Promise<void>;
  onCancel: () => void;
  saving: boolean;
  actionOptions: Array<{ value: string; label: string; group: string; available?: boolean }>;
}> = ({ initial, onSave, onCancel, saving, actionOptions }) => {
  const [form, setForm] = useState<RuleFormState>(initial);
  const [attempted, setAttempted] = useState(false);
  const [preview, setPreview] = useState<RuleDraftPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [autonomyMenuOpen, setAutonomyMenuOpen] = useState(false);
  const [actionMenuOpen, setActionMenuOpen] = useState(false);
  const [playbookOptions, setPlaybookOptions] = useState<Array<{ id: string; name: string; description: string }>>([]);
  const [playbookMenuOpen, setPlaybookMenuOpen] = useState(false);
  const [playbookLoadError, setPlaybookLoadError] = useState<string | null>(null);

  // Show columns for all conditions that have a field, even if they don't have a value yet.
  // The backend extracts values from matched records for all fields listed here.
  const previewConditionFields = useMemo(() => {
    const seen = new Set<string>();
    form.conditions.forEach((condition) => {
      if (condition.field) {
        seen.add(condition.field);
      }
    });
    return Array.from(seen);
  }, [form.conditions]);

  const formatPreviewValue = (value: unknown) => {
    if (value === null || value === undefined || value === '') return '—';
    if (Array.isArray(value)) return value.map((entry) => String(entry)).join(', ');
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  };

  // Match against real alerts while the rule is being written. The alternative —
  // save, then press Test in the list — made the editor a guess-and-check form.
  const conditionsKey = JSON.stringify(form.conditions);
  const previewKey = `${conditionsKey}|${form.action_slug}|${form.autonomy_level}|${form.dry_run}|${form.subject_type}`;

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      if (!form.action_slug) return;
      setPreviewLoading(true);
      setPreviewError(null);
      try {
        const response = await fetch('/api/v1/runbook/automation-rules/preview', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          signal: controller.signal,
          body: JSON.stringify({
            subject_type: form.subject_type,
            conditions: form.conditions,
            action_slug: form.action_slug,
            autonomy_level: form.autonomy_level,
            dry_run: form.dry_run,
          }),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        setPreview((await response.json()) as RuleDraftPreview);
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') return;
        setPreviewError(err instanceof Error ? err.message : 'Preview failed');
      } finally {
        setPreviewLoading(false);
      }
    }, 450);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
    // `previewKey` is the debounced identity of everything the preview reads.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    // `previewKey` is the debounced identity of everything the preview reads.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewKey]);

  // Load available playbooks on component mount
  useEffect(() => {
    const fetchPlaybooks = async () => {
      try {
        setPlaybookLoadError(null);
        const response = await fetch('/api/v1/runbook/playbooks');
        if (!response.ok) {
          throw new Error(`Failed to load playbooks: HTTP ${response.status}`);
        }
        const data = (await response.json()) as Array<{ id: string; name: string; description: string }>;
        setPlaybookOptions(data);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to load playbooks';
        setPlaybookLoadError(message);
        // Still allow form to function, just with no playbook dropdown
        setPlaybookOptions([]);
      }
    };
    fetchPlaybooks();
  }, []);

  const set = <K extends keyof RuleFormState>(k: K, v: RuleFormState[K]) =>
    setForm((prev) => ({ ...prev, [k]: v }));

  const addCondition = () =>
    set('conditions', [...form.conditions, { field: 'severity', op: 'eq', value: '' }]);

  const updateCondition = (i: number, partial: Partial<Condition>) => {
    const updated = { ...form.conditions[i], ...partial };
    // If field changed and current operator is no longer valid, reset operator
    if (partial.field && partial.field !== form.conditions[i].field) {
      const validOps = getValidOperators(partial.field);
      if (!validOps.includes(updated.op)) {
        // Pick sensible default based on field type
        if (ARRAY_FIELDS.has(partial.field)) {
          updated.op = 'array_contains';
        } else if (NUMERIC_FIELDS.has(partial.field)) {
          updated.op = 'eq';
        } else {
          updated.op = 'eq';
        }
      }
    }
    set('conditions', form.conditions.map((c, idx) => (idx === i ? updated : c)));
  };

  const removeCondition = (i: number) =>
    set('conditions', form.conditions.filter((_, idx) => idx !== i));

  const handleSave = () => {
    setAttempted(true);
    if (!form.name.trim()) return;
    onSave(form);
  };

  const nameInvalid = attempted && !form.name.trim();
  const actionGroups = actionOptions.reduce<Record<string, typeof actionOptions>>((acc, a) => {
    acc[a.group] = [...(acc[a.group] ?? []), a];
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <FieldLabel
            label="Name"
            required
            help="Operator-facing name. Shown in the rule list and in the ledger's actor label."
          />
          <input
            type="text"
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
            placeholder="e.g. Close low-confidence alerts"
            className={`w-full bg-slate-800/60 border rounded px-2.5 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50 ${
              nameInvalid ? 'border-red-500/60' : 'border-slate-700/60'
            }`}
          />
          {nameInvalid && (
            <p className="text-[10px] text-red-400 mt-1">Name is required</p>
          )}
        </div>
        <div className="col-span-2">
          <FieldLabel
            label="Description"
            help="Optional note for the next analyst. Stored only — it does not affect execution."
            hint="default: empty"
          />
          <textarea
            value={form.description}
            onChange={(e) => set('description', e.target.value)}
            placeholder="Optional operator-facing note for this rule"
            rows={2}
            className="w-full bg-slate-800/60 border border-slate-700/60 rounded px-2.5 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50 resize-none"
          />
        </div>
        <div>
          <FieldLabel
            label="Trigger"
            help={TRIGGER_META[form.trigger_type]?.help ?? 'When the executor runs this rule.'}
            hint="default: alert.created"
          />
          <select
            value={form.trigger_type}
            onChange={(e) => set('trigger_type', e.target.value)}
            className="w-full bg-slate-800/60 border border-slate-700/60 rounded px-2.5 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500/50"
          >
            {TRIGGER_OPTIONS.map((t) => (
              <option
                key={t}
                value={t}
                title={TRIGGER_META[t]?.help}
              >
                {TRIGGER_META[t]?.label ?? TRIGGER_LABELS[t] ?? t}
              </option>
            ))}
          </select>
          {INERT_TRIGGERS.has(form.trigger_type) && (
            <p className="mt-1 text-[10px] text-amber-400/90">
              No code path emits this trigger yet — the rule will be saved but never fires.
            </p>
          )}
        </div>
        <div>
          <FieldLabel
            label="Action"
            help="Governed action the rule proposes. Every action is gated: read actions can run automatically, containment actions stop at the autonomy ceiling."
            hint="default: close_alert"
          />
          <div className="relative">
            <button
              type="button"
              onClick={() => setActionMenuOpen((open) => !open)}
              className="flex w-full items-center justify-between rounded border border-slate-700/60 bg-slate-800/60 px-2.5 py-1.5 text-left text-sm text-slate-200 focus:outline-none focus:border-blue-500/50"
              aria-expanded={actionMenuOpen}
              aria-haspopup="listbox"
              title={`Current action: ${actionOptions.find(a => a.value === form.action_slug)?.label ?? form.action_slug}`}
            >
              <span>{actionOptions.find(a => a.value === form.action_slug)?.label ?? form.action_slug}</span>
              <span className="text-slate-400">▾</span>
            </button>

            {actionMenuOpen && (
              <div
                role="listbox"
                aria-label="Action options"
                className="absolute z-20 mt-1 w-full overflow-hidden rounded border border-slate-700/60 bg-slate-900/95 shadow-xl max-h-64 overflow-y-auto"
              >
                {Object.entries(actionGroups).map(([group, options]) => (
                  <div key={group}>
                    <div className="px-3 py-2 text-xs font-semibold text-slate-400 bg-slate-800/50 sticky top-0">
                      {group}
                    </div>
                    {options.map((a) => {
                      const isSelected = form.action_slug === a.value;
                      const isUnavailable = a.available === false;
                      return (
                        <button
                          key={a.value}
                          type="button"
                          role="option"
                          aria-selected={isSelected}
                          onClick={() => {
                            set('action_slug', a.value);
                            setActionMenuOpen(false);
                          }}
                          disabled={isUnavailable}
                          className={`w-full px-3 py-2 text-left text-sm flex items-center justify-between transition-colors ${
                            isSelected
                              ? 'bg-blue-500/30 text-blue-200 font-medium'
                              : isUnavailable
                                ? 'text-slate-500 cursor-not-allowed opacity-60'
                                : 'text-slate-200 hover:bg-slate-800/60'
                          }`}
                          title={isUnavailable ? 'Action unavailable — required connector not configured' : ''}
                        >
                          <span>{a.label}</span>
                          {isUnavailable && <span className="ml-2 text-amber-400">⚠️</span>}
                        </button>
                      );
                    })}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
        <div>
          <FieldLabel
            label="Autonomy ceiling"
            help="The stricter of this ceiling and the platform policy wins. A rule capped at L0 always waits for an analyst, even when the policy would allow L4."
            hint="default: L2"
          />
          <div className="relative">
            <button
              type="button"
              onClick={() => setAutonomyMenuOpen((open) => !open)}
              className="flex w-full items-center justify-between rounded border border-slate-700/60 bg-slate-800/60 px-2.5 py-1.5 text-left text-sm text-slate-200 focus:outline-none focus:border-blue-500/50"
              aria-expanded={autonomyMenuOpen}
              aria-haspopup="listbox"
              title={AUTONOMY_DESCRIPTIONS[form.autonomy_level] ?? AUTONOMY_LABELS[form.autonomy_level]}
            >
              <span>{AUTONOMY_OPTION_LABELS[form.autonomy_level]}</span>
              <span className="text-slate-400">▾</span>
            </button>

            {autonomyMenuOpen && (
              <div
                role="listbox"
                aria-label="Autonomy ceiling options"
                className="absolute z-20 mt-1 w-full overflow-hidden rounded border border-slate-700/60 bg-slate-900/95 shadow-xl"
              >
                {AUTONOMY_OPTIONS.map((level) => {
                  const selected = form.autonomy_level === level;
                  return (
                    <button
                      key={level}
                      type="button"
                      role="option"
                      aria-selected={selected}
                      onClick={() => {
                        set('autonomy_level', level);
                        setAutonomyMenuOpen(false);
                      }}
                      className={[
                        'w-full border-b border-slate-800/60 px-2.5 py-2 text-left last:border-b-0 transition-colors',
                        selected ? 'bg-blue-500/10' : 'bg-slate-900/95 hover:bg-slate-800/80',
                      ].join(' ')}
                    >
                      <div className="flex items-start gap-2">
                        <span className="inline-flex min-w-[2.2rem] items-center justify-center rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-semibold text-slate-100">
                          {level}
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="text-[10px] font-medium leading-snug text-slate-100">
                            {AUTONOMY_LABELS[level]}
                          </div>
                          <div className="mt-0.5 text-[9px] leading-snug text-slate-400">
                            {AUTONOMY_DESCRIPTIONS[level]}
                          </div>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
          <p className="text-[10px] text-slate-600 mt-1">
            {AUTONOMY_DESCRIPTIONS[form.autonomy_level]}
          </p>
        </div>
        <div>
          <FieldLabel
            label="Priority"
            help="Rules are evaluated lowest number first, up to 50 rules per event. Use it to order overlapping rules."
            hint="default: 100 · 1–9999"
          />
          <input
            type="number"
            value={form.priority}
            min={1}
            max={9999}
            onChange={(e) => set('priority', Number(e.target.value))}
            className="w-full bg-slate-800/60 border border-slate-700/60 rounded px-2.5 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500/50"
          />
        </div>
        <div className="col-span-2 flex items-center gap-4">
          <label
            className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer"
            title="Dry run records the governed decision in the ledger without calling the vendor. Turn it off only once the tenancy has real credentials plumbed; otherwise the action would be logged as executed while nothing happened."
          >
            <input
              type="checkbox"
              checked={form.dry_run}
              onChange={(e) => set('dry_run', e.target.checked)}
              className="accent-blue-500"
            />
            Dry run (simulated)
            <span className="text-[10px] text-slate-600">default: on</span>
          </label>
          <label
            className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer"
            title="Disabled rules stay in the list and keep their history, but the executor never evaluates them."
          >
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => set('enabled', e.target.checked)}
              className="accent-blue-500"
            />
            Enabled
            <span className="text-[10px] text-slate-600">default: on</span>
          </label>
        </div>

        {/* Governance & Contracts (collapsible) */}
        <details className="col-span-2 border-t border-slate-800/40 pt-3">
          <summary className="text-xs font-medium text-slate-400 cursor-pointer select-none hover:text-slate-200 transition-colors">
            Governance &amp; Contracts ▸
          </summary>
          <div className="mt-3 grid grid-cols-2 gap-3">
            <div>
              <FieldLabel
                label="Subject type"
                help="Which event stream this rule is allowed to fire on. Enforced in the executor's rule query, not just here."
                hint="default: alert"
              />
              <select
                value={form.subject_type}
                onChange={(e) => set('subject_type', e.target.value)}
                title={SUBJECT_TYPE_HELP[form.subject_type]}
                className="w-full bg-slate-800/60 border border-slate-700/60 rounded px-2.5 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500/50"
              >
                {SUBJECT_TYPE_OPTIONS.map((t) => (
                  <option key={t} value={t} title={SUBJECT_TYPE_HELP[t]}>{t}</option>
                ))}
              </select>
              <p className="mt-1 text-[10px] text-slate-600">{SUBJECT_TYPE_HELP[form.subject_type]}</p>
            </div>
            <div>
              <FieldLabel
                label="Owner team"
                help="Optional label for who owns this rule. Reference only — it does not route anything."
                hint="default: empty"
              />
              <input
                type="text"
                value={form.owner_team}
                onChange={(e) => set('owner_team', e.target.value)}
                placeholder="e.g. tier1-soc"
                className="w-full bg-slate-800/60 border border-slate-700/60 rounded px-2.5 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50"
              />
            </div>
            <div className="col-span-2">
              <FieldLabel
                label="Linked Playbook"
                help="Select an existing playbook to run when this rule matches. The playbook will execute before the rule's action (if approved by governance)."
                hint="optional"
              />
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setPlaybookMenuOpen((open) => !open)}
                  className="flex w-full items-center justify-between rounded border border-slate-700/60 bg-slate-800/60 px-2.5 py-1.5 text-left text-sm text-slate-200 focus:outline-none focus:border-blue-500/50"
                  aria-expanded={playbookMenuOpen}
                  aria-haspopup="listbox"
                  title={playbookOptions.find(p => p.id === form.playbook_ref)?.name || form.playbook_ref || 'Select a playbook'}
                >
                  <span>
                    {form.playbook_ref
                      ? playbookOptions.find(p => p.id === form.playbook_ref)?.name || form.playbook_ref
                      : 'No playbook selected'}
                  </span>
                  <span className="text-slate-400">▾</span>
                </button>

                {playbookMenuOpen && (
                  <div
                    role="listbox"
                    aria-label="Playbook options"
                    className="absolute z-20 mt-1 w-full overflow-hidden rounded border border-slate-700/60 bg-slate-900/95 shadow-xl max-h-64 overflow-y-auto"
                  >
                    {playbookOptions.length === 0 ? (
                      <div className="px-3 py-2 text-sm text-slate-500">
                        {playbookLoadError
                          ? `Error loading playbooks: ${playbookLoadError}`
                          : 'No playbooks found'}
                      </div>
                    ) : (
                      <>
                        {/* Option to clear selection */}
                        <button
                          type="button"
                          role="option"
                          onClick={() => {
                            set('playbook_ref', '');
                            setPlaybookMenuOpen(false);
                          }}
                          className={`w-full px-3 py-2 text-left text-sm transition-colors ${
                            form.playbook_ref === ''
                              ? 'bg-blue-500/30 text-blue-200 font-medium'
                              : 'text-slate-200 hover:bg-slate-800/60'
                          }`}
                        >
                          None
                        </button>
                        {playbookOptions.map((playbook) => (
                          <button
                            key={playbook.id}
                            type="button"
                            role="option"
                            onClick={() => {
                              set('playbook_ref', playbook.id);
                              setPlaybookMenuOpen(false);
                            }}
                            className={`w-full px-3 py-2 text-left text-sm transition-colors ${
                              form.playbook_ref === playbook.id
                                ? 'bg-blue-500/30 text-blue-200 font-medium'
                                : 'text-slate-200 hover:bg-slate-800/60'
                            }`}
                            title={playbook.description || playbook.name}
                          >
                            <div className="font-medium">{playbook.name}</div>
                            {playbook.description && (
                              <div className="text-xs text-slate-400">{playbook.description}</div>
                            )}
                          </button>
                        ))}
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
            <div className="col-span-2">
              <FieldLabel
                label="Runbook Doc path"
                help="Optional path to the human runbook for this condition, e.g. docs/operations/runbooks/lsass-dump.md. Displayed on the rule only."
                hint="default: empty"
              />
              <input
                type="text"
                value={form.docs_ref}
                onChange={(e) => set('docs_ref', e.target.value)}
                placeholder="docs/operations/runbooks/..."
                className="w-full bg-slate-800/60 border border-slate-700/60 rounded px-2.5 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50"
              />
            </div>
            <div className="col-span-2 text-[10px] text-slate-600 bg-slate-900/40 rounded px-3 py-2 space-y-1">
              <p>Data Contract, Failure Contract, and Cost Budget are defined per action slug in the{' '}
                <Link
                  href="/runbook?tab=governance"
                  className="text-blue-400 hover:text-blue-300 underline"
                >
                  Governance catalog →
                </Link>
                {' '}— they apply platform-wide and are not editable per-rule in v1.
              </p>
              <p>
                These settings are based on your platform defaults.{' '}
                <span className="text-slate-500">
                  To raise or lower autonomy thresholds, visit Governance.
                </span>
              </p>
            </div>
          </div>
        </details>
      </div>

      {/* Conditions */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <span
            className="flex items-center gap-1 text-xs font-medium text-slate-400"
            title="All conditions must match (AND). No conditions matches every subject of the chosen type."
          >
            Conditions (AND)
            <Info className="h-3 w-3 text-slate-600" aria-hidden />
          </span>
          <button
            type="button"
            onClick={addCondition}
            title="Add another AND condition. The rule only fires when every condition matches."
            className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
          >
            <Plus className="h-3 w-3" /> Add
          </button>
        </div>
        {form.conditions.length === 0 && (
          <div className="flex items-start gap-2 rounded border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-[10px] text-amber-400">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
            <span>
              No conditions — this rule will run against{' '}
              <strong>every {form.subject_type}</strong>.
              Add at least one condition to limit scope.
            </span>
          </div>
        )}
        {form.conditions.map((cond, i) => {
          const selectedField = FIELD_HELP[cond.field];
          const exampleValue = ['in', 'not_in'].includes(cond.op)
            ? '["critical","high"]'
            : selectedField?.example ?? 'value';

          return (
            <div key={i} className="mb-3">
              <div className="flex items-center gap-2">
                <select
                  value={cond.field}
                  onChange={(e) => updateCondition(i, { field: e.target.value })}
                  title={FIELD_HELP[cond.field]?.help}
                  aria-label={`Condition ${i + 1} field`}
                  className="bg-slate-800/60 border border-slate-700/60 rounded px-2 py-1 text-xs text-slate-200 focus:outline-none"
                >
                  {FIELD_OPTIONS.map((f) => (
                    <option key={f} value={f} title={FIELD_HELP[f]?.help}>{f}</option>
                  ))}
                </select>
                <select
                  value={cond.op}
                  onChange={(e) => updateCondition(i, { op: e.target.value })}
                  title={OP_HELP[cond.op]}
                  aria-label={`Condition ${i + 1} operator`}
                  className="bg-slate-800/60 border border-slate-700/60 rounded px-2 py-1 text-xs text-slate-200 focus:outline-none"
                >
                  {getValidOperators(cond.field).map((o) => (
                    <option key={o} value={o} title={OP_HELP[o]}>{o}</option>
                  ))}
                </select>
                {!['exists', 'not_exists'].includes(cond.op) && (
                  <input
                    type="text"
                    value={String(cond.value ?? '')}
                    onChange={(e) => updateCondition(i, { value: e.target.value })}
                    aria-label={`Condition ${i + 1} value`}
                    placeholder={exampleValue}
                    title={
                      ['in', 'not_in'].includes(cond.op)
                        ? 'A JSON list of accepted values.'
                        : `Value compared against ${cond.field}.`
                    }
                    className="flex-1 bg-slate-800/60 border border-slate-700/60 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-600 focus:outline-none"
                  />
                )}
                <button
                  type="button"
                  onClick={() => removeCondition(i)}
                  className="text-slate-600 hover:text-red-400"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Live match preview — the same evaluator and gate the executor uses. */}
      <div className="rounded border border-slate-800/60 bg-slate-950/30 p-3">
        <div className="flex items-center justify-between gap-2">
          <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            {previewLoading ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <Search className="h-3 w-3" />
            )}
            Live preview
          </span>
          <span className="text-[10px] text-slate-600">
            against the {preview?.evaluated ?? 0} most recent alerts
          </span>
        </div>

        {previewError && (
          <p className="mt-2 text-[11px] text-red-400">Preview unavailable: {previewError}</p>
        )}

        {preview && preview.errors.length > 0 && (
          <ul className="mt-2 space-y-1">
            {preview.errors.map((message) => (
              <li key={message} className="text-[11px] text-red-400">
                {message}
              </li>
            ))}
          </ul>
        )}

        {preview && preview.errors.length === 0 && (
          <>
            <p className="mt-2 text-[11px] text-slate-400">
              {preview.matched === 0 ? (
                <>
                  Matches <span className="font-semibold text-slate-300">none</span> of the
                  last {preview.evaluated} alerts — it would stay idle until an alert fits.
                </>
              ) : (
                <>
                  Matches{' '}
                  <span className="font-semibold text-emerald-300">{preview.matched}</span> of
                  the last {preview.evaluated} alerts.
                </>
              )}
            </p>
            {preview.matches.length > 0 && (
              <div className="mt-3 overflow-x-auto">
                <div
                  className="grid gap-1"
                  style={{
                    gridTemplateColumns:
                      previewConditionFields.length > 0
                        ? `minmax(160px, 1.6fr) repeat(${previewConditionFields.length}, minmax(100px, 1fr)) minmax(80px, 0.8fr)`
                        : 'minmax(160px, 1fr) minmax(80px, 0.8fr)',
                  }}
                >
                  <div className="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                    alert
                  </div>
                  {previewConditionFields.map((field) => (
                    <div
                      key={field}
                      className="text-[10px] font-medium uppercase tracking-wider text-slate-500"
                    >
                      {field}
                    </div>
                  ))}
                  <div className="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                    status
                  </div>

                  {preview.matches.map((match) => (
                    <div key={match.alert_id} className="contents">
                      <div className="truncate text-[11px] text-slate-300" title={match.title}>
                        {match.title}
                      </div>
                      {previewConditionFields.map((field) => (
                        <div
                          key={`${match.alert_id}-${field}`}
                          className="truncate text-[11px] text-slate-300"
                          title={formatPreviewValue(match.condition_values?.[field])}
                        >
                          {formatPreviewValue(match.condition_values?.[field])}
                        </div>
                      ))}
                      <span
                        className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] ${
                          match.status === 'denied'
                            ? 'bg-red-500/10 text-red-300'
                            : match.status === 'recorded'
                              ? 'bg-amber-500/10 text-amber-300'
                              : 'bg-emerald-500/10 text-emerald-300'
                        }`}
                        title={match.reason ?? 'Would be recorded with this outcome'}
                      >
                        {match.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {form.subject_type !== 'alert' && form.subject_type !== 'all' && (
              <p className="mt-2 text-[10px] text-amber-400/80">
                Preview runs against alert rows only; this rule is scoped to{' '}
                {form.subject_type}.
              </p>
            )}
          </>
        )}
      </div>

      <div className="flex justify-end gap-2 pt-2 border-t border-slate-800/40">
        <button
          type="button"
          onClick={onCancel}
          className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          title="Persists this rule to the tenant and records the governance decision once the trigger matches."
          className="px-3 py-1.5 text-xs bg-blue-600/80 hover:bg-blue-600 text-white rounded transition-colors disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save rule'}
        </button>
      </div>
    </div>
  );
};

// ── Rule row ──────────────────────────────────────────────────────────────────

const RuleRow: FC<{
  rule: AutomationRule;
  onToggle: (id: string, enabled: boolean) => void;
  onEdit: (rule: AutomationRule) => void;
  onDelete: (id: string) => void;
  onTest: (rule: AutomationRule) => void;
  onClone: (rule: AutomationRule) => void;
}> = ({ rule, onToggle, onEdit, onDelete, onTest, onClone }) => {
  const [expanded, setExpanded] = useState(false);
  const levelColor = AUTONOMY_COLORS[rule.autonomy_level] ?? 'text-slate-400 bg-slate-500/10';

  const conditionSummary = rule.conditions.length > 0
    ? rule.conditions
        .map((c) => `${c.field} ${c.op}${['exists', 'not_exists'].includes(c.op) ? '' : ` ${JSON.stringify(c.value)}`}`)
        .join(' · ')
    : null;

  return (
    <div className={`border border-slate-800/60 rounded-lg overflow-hidden transition-opacity ${!rule.enabled ? 'opacity-55' : ''}`}>
      <div className={`flex items-center gap-3 px-4 py-3 ${!rule.enabled ? 'bg-slate-900/20' : 'bg-slate-900/40'}`}>
        <button
          type="button"
          onClick={() => onToggle(rule.id, !rule.enabled)}
          title={rule.enabled ? 'Disable rule' : 'Enable rule'}
          className={`shrink-0 ${rule.enabled ? 'text-emerald-400 hover:text-emerald-300' : 'text-slate-600 hover:text-slate-400'}`}
        >
          {rule.enabled ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
        </button>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-slate-200 truncate">{rule.name}</span>
            <span className="text-[10px] text-slate-500 shrink-0">
              {TRIGGER_LABELS[rule.trigger_type] ?? rule.trigger_type}
            </span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium shrink-0 ${levelColor}`}>
              {rule.autonomy_level}
            </span>
            {rule.dry_run && (
              <span className="text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded shrink-0">
                dry run
              </span>
            )}
            <span className="text-[10px] text-slate-600 shrink-0 font-mono">
              {rule.action_slug}
            </span>
          </div>
          {/* inline condition summary */}
          {conditionSummary && (
            <p className="text-[10px] text-slate-500 mt-0.5 font-mono truncate max-w-lg" title={conditionSummary}>
              If: {conditionSummary}
            </p>
          )}
          {/* stats row */}
          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
            {rule.last_triggered_at && (
              <span className="text-[10px] text-slate-600">
                last {new Date(rule.last_triggered_at).toLocaleString()} · {rule.trigger_count}×
              </span>
            )}
            {(rule.success_count > 0 || rule.failed_count > 0 || rule.denied_count > 0) && (
              <span className="text-[10px] text-slate-600">
                <span className="text-emerald-600">{rule.success_count} ok</span>
                {' / '}
                <span className="text-red-600">{rule.failed_count} fail</span>
                {' / '}
                <span className="text-slate-600">{rule.denied_count} denied</span>
              </span>
            )}
            {rule.playbook_ref && (
              <span className="text-[10px] text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded">
                📋 playbook
              </span>
            )}
            {rule.docs_ref && (
              <span className="text-[10px] text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded">
                📖 {rule.docs_ref.split('/').pop() ?? 'doc'}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            onClick={() => onTest(rule)}
            aria-label="Test rule on selected alerts"
            title="Test this rule against existing alerts in the tenant to see which ones match and what the dry-run result would be."
            className="px-2 py-1 text-[10px] rounded border border-slate-700 bg-slate-800/60 text-slate-300 hover:border-blue-500/40 hover:text-blue-200"
          >
            Test
          </button>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="p-1 text-slate-500 hover:text-slate-300"
          >
            {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
          <button
            type="button"
            onClick={() => onClone(rule)}
            aria-label="Clone rule"
            title="Duplicate this rule as a new draft"
            className="p-1 text-slate-500 hover:text-emerald-400"
          >
            <Copy className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={() => onEdit(rule)}
            aria-label="Edit rule"
            className="p-1 text-slate-500 hover:text-blue-400"
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={() => onDelete(rule.id)}
            className="p-1 text-slate-600 hover:text-red-400"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {expanded && (
        <div className="px-4 py-3 bg-slate-950/20 border-t border-slate-800/40 space-y-2">
          {rule.description && (
            <p className="text-xs text-slate-400">{rule.description}</p>
          )}
          <div>
            <p className="text-[10px] font-medium text-slate-500 mb-1 uppercase tracking-wider">Conditions</p>
            {rule.conditions.length === 0 ? (
              <p className="text-xs text-slate-600 italic">None — matches every subject</p>
            ) : (
              <ul className="space-y-1">
                {rule.conditions.map((c, i) => (
                  <li key={i} className="text-xs font-mono text-slate-400">
                    {c.field} {c.op} {['exists', 'not_exists'].includes(c.op) ? '' : JSON.stringify(c.value)}
                  </li>
                ))}
              </ul>
            )}
          </div>
          {(rule.playbook_ref || rule.docs_ref || rule.owner_team) && (
            <div className="flex flex-wrap gap-3 pt-1 border-t border-slate-800/40">
              {rule.owner_team && (
                <span className="text-[10px] text-slate-500">
                  Owner: <span className="text-slate-300">{rule.owner_team}</span>
                </span>
              )}
              {rule.playbook_ref && (
                <a
                  href={`/playbooks?id=${rule.playbook_ref}`}
                  className="text-[10px] text-purple-400 hover:text-purple-300 underline"
                >
                  View Playbook →
                </a>
              )}
              {rule.docs_ref && (
                <span className="text-[10px] text-blue-400">
                  📖 {rule.docs_ref}
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ── Main view ─────────────────────────────────────────────────────────────────

export const AutomationRulesView: FC = () => {
  const [rules, setRules] = useState<AutomationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [cloneBase, setCloneBase] = useState<RuleFormState | null>(null);
  const [saving, setSaving] = useState(false);
  const [testRuleId, setTestRuleId] = useState<string | null>(null);
  const [testAlertOptions, setTestAlertOptions] = useState<AlertPreviewItem[]>([]);
  const [selectedTestAlertIds, setSelectedTestAlertIds] = useState<string[]>([]);
  const [testResults, setTestResults] = useState<RulePreviewResult[]>([]);
  const [runningRuleTest, setRunningRuleTest] = useState(false);
  const [search, setSearch] = useState('');
  const [actionOptions, setActionOptions] = useState<Array<{ value: string; label: string; group: string; available?: boolean }>>([]);
  const importRef = useRef<HTMLInputElement>(null);

  // Fetch action catalog from API
  useEffect(() => {
    (async () => {
      try {
        const actions = await request('/api/v1/runbook/actions', { method: 'GET' });
        if (Array.isArray(actions)) {
          setActionOptions(
            actions.map((a: { name: string; label: string; category: string }) => ({
              value: a.name,
              label: a.label,
              group: a.category || 'Other',
            }))
          );
        }
      } catch (err) {
        console.error('Failed to load actions:', err);
        // Fall back to showing nothing if API fails; existing hardcoded list removed below
      }
    })();
  }, []);

  /**
   * One haystack per rule covering everything an operator would plausibly type:
   * the name, the action, the trigger, the owner, the refs, and the conditions
   * themselves (searching "critical" should find the rule that filters on it).
   */
  const filteredRules = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return rules;

    return rules.filter((rule) => {
      const haystack = [
        rule.name,
        rule.description ?? '',
        rule.action_slug,
        TRIGGER_LABELS[rule.trigger_type] ?? rule.trigger_type,
        rule.autonomy_level,
        rule.owner_team ?? '',
        rule.playbook_ref ?? '',
        rule.docs_ref ?? '',
        ...rule.conditions.map((c) => `${c.field} ${c.op} ${JSON.stringify(c.value ?? '')}`),
      ]
        .join(' ')
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [rules, search]);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await request<AutomationRule[]>('/api/v1/runbook/automation-rules');
      setRules(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (form: RuleFormState) => {
    setSaving(true);
    try {
      await request('/api/v1/runbook/automation-rules', {
        method: 'POST',
        body: JSON.stringify(form),
      });
      setCreating(false);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create rule');
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = async (form: RuleFormState) => {
    if (!editingRuleId) return;
    setSaving(true);
    try {
      const updated = await request<AutomationRule>(`/api/v1/runbook/automation-rules/${editingRuleId}`, {
        method: 'PATCH',
        body: JSON.stringify(form),
      });
      setRules((prev) => prev.map((rule) => (rule.id === editingRuleId ? updated : rule)));
      setEditingRuleId(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update rule');
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (id: string, enabled: boolean) => {
    try {
      await request(`/api/v1/runbook/automation-rules/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled }),
      });
      setRules((prev) => prev.map((r) => (r.id === id ? { ...r, enabled } : r)));
    } catch {
      await load();
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this automation rule?')) return;
    try {
      await request(`/api/v1/runbook/automation-rules/${id}`, { method: 'DELETE' });
      setRules((prev) => prev.filter((r) => r.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule');
    }
  };

  const handleClone = (rule: AutomationRule) => {
    const base = toRuleFormState(rule);
    setCloneBase({ ...base, name: `${base.name} (copy)`, enabled: false });
    setCreating(true);
    setEditingRuleId(null);
  };

  const handleExportYaml = useCallback(() => {
    const lines = ['# AiSOC Automation Rules Export', `# ${new Date().toISOString()}`, 'rules:'];
    rules.forEach((r) => {
      lines.push(`  - name: ${JSON.stringify(r.name)}`);
      lines.push(`    trigger_type: ${r.trigger_type}`);
      lines.push(`    action_slug: ${r.action_slug}`);
      lines.push(`    autonomy_level: ${r.autonomy_level}`);
      lines.push(`    dry_run: ${r.dry_run}`);
      lines.push(`    enabled: ${r.enabled}`);
      lines.push(`    priority: ${r.priority}`);
      if (r.description) lines.push(`    description: ${JSON.stringify(r.description)}`);
      if (r.conditions.length > 0) {
        lines.push('    conditions:');
        r.conditions.forEach((c) => {
          lines.push(`      - field: ${c.field}`);
          lines.push(`        op: ${c.op}`);
          if (!['exists', 'not_exists'].includes(c.op)) lines.push(`        value: ${JSON.stringify(c.value)}`);
        });
      }
    });
    const blob = new Blob([lines.join('\n')], { type: 'text/yaml' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `automation-rules-${Date.now()}.yaml`;
    a.click();
    URL.revokeObjectURL(a.href);
  }, [rules]);

  const handleImportYaml = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setError('YAML import: paste individual rules into the form (full YAML batch import coming in v8.1).');
    };
    reader.readAsText(file);
    if (importRef.current) importRef.current.value = '';
  };

  const handleRuleTestOpen = async (rule: AutomationRule) => {
    try {
      const preview = await request<RulePreviewResponse>(`/api/v1/runbook/automation-rules/${rule.id}/test`, {
        method: 'POST',
        body: JSON.stringify({ alert_ids: [] }),
      });
      const matchedIds = new Set(
        preview.results.filter((item) => item.matched).map((item) => item.alert_id),
      );
      const alertResponse = await request<{ items: AlertPreviewItem[] }>('/api/v1/alerts', {
        params: { page: 1, page_size: 200 },
      });

      const matchedAlerts = (alertResponse.items ?? []).filter((item) => matchedIds.has(item.id));
      setTestRuleId(rule.id);
      setSelectedTestAlertIds([]);
      setTestResults([]);
      setTestAlertOptions(matchedAlerts);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load matched alerts for rule test');
    }
  };

  const runRuleTest = async () => {
    if (!testRuleId) return;
    setRunningRuleTest(true);
    try {
      const response = await request<RulePreviewResponse>(`/api/v1/runbook/automation-rules/${testRuleId}/test`, {
        method: 'POST',
        body: JSON.stringify({ alert_ids: selectedTestAlertIds }),
      });
      setTestResults(response.results ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to test rule on existing alerts');
    } finally {
      setRunningRuleTest(false);
    }
  };

  const editingRule = rules.find((rule) => rule.id === editingRuleId) ?? null;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-blue-400" />
          <h2 className="text-sm font-semibold text-slate-200">Automation Rules</h2>
          <span className="text-xs text-slate-500">
            Trigger-based governed actions — all gated by the autonomy policy
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <input
            ref={importRef}
            type="file"
            accept=".yaml,.yml"
            onChange={handleImportYaml}
            className="hidden"
          />
          <button
            type="button"
            onClick={() => importRef.current?.click()}
            title="Import rules from YAML"
            className="flex items-center gap-1 px-2 py-1.5 text-[10px] text-slate-400 hover:text-slate-200 border border-slate-700/60 hover:border-slate-600 rounded transition-colors"
          >
            <FileUp className="h-3 w-3" />
            Import
          </button>
          {rules.length > 0 && (
            <button
              type="button"
              onClick={handleExportYaml}
              title="Export all rules as YAML"
              className="flex items-center gap-1 px-2 py-1.5 text-[10px] text-slate-400 hover:text-slate-200 border border-slate-700/60 hover:border-slate-600 rounded transition-colors"
            >
              <FileDown className="h-3 w-3" />
              Export YAML
            </button>
          )}
          <button
            type="button"
            onClick={() => { setCloneBase(null); setCreating(true); }}
            title="Create a new trigger-based governed action."
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-blue-600/80 hover:bg-blue-600 text-white rounded transition-colors"
          >
            <Plus className="h-3.5 w-3.5" /> New rule
          </button>
        </div>
      </div>

      {/* Search stays visible even with a handful of rules: the list grows with
          every cloned default, and scanning names was the only way to find one. */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search name, action, condition, owner…"
            aria-label="Search automation rules"
            className="w-full rounded border border-slate-700/60 bg-slate-800/60 py-1.5 pl-7 pr-2 text-xs text-slate-200 placeholder-slate-600 focus:border-blue-500/50 focus:outline-none"
          />
        </div>
        {!loading && search.trim() && (
          <span className="text-[10px] text-slate-500">
            {filteredRules.length} of {rules.length} rules
          </span>
        )}
      </div>

      {error && (
        <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded px-3 py-2">
          {error}
        </div>
      )}

      {/* Authoring lives in a modal: an inline form pushed the rule list down the
          page and made editing feel like a navigation. */}
      <RunbookModal
        open={creating || editingRule !== null}
        onClose={() => {
          setCreating(false);
          setEditingRuleId(null);
          setCloneBase(null);
        }}
        title={editingRule ? 'Edit automation rule' : 'New automation rule'}
        subtitle="Conditions are ANDed. Every action is gated by the autonomy policy."
        size="lg"
      >
        {(creating || editingRule) && (
          <RuleForm
            key={editingRule?.id ?? cloneBase?.name ?? 'new'}
            initial={editingRule ? toRuleFormState(editingRule) : (cloneBase ?? BLANK_FORM)}
            onSave={editingRule ? handleEdit : handleCreate}
            onCancel={() => {
              setCreating(false);
              setEditingRuleId(null);
              setCloneBase(null);
            }}
            saving={saving}
            actionOptions={actionOptions}
          />
        )}
      </RunbookModal>

      {/* Rule testing also opens in a modal — the same inline-at-top pattern. */}
      <RunbookModal
        open={testRuleId !== null}
        onClose={() => {
          setTestRuleId(null);
          setSelectedTestAlertIds([]);
          setTestResults([]);
        }}
        title="Test rule against existing alerts"
        subtitle="Dry-run preview: shows which alerts match and what would be recorded."
        size="lg"
      >
        <div className="space-y-4">
          <div className="space-y-2 max-h-72 overflow-auto">
            {testAlertOptions.length === 0 && (
              <p className="text-xs text-slate-500">No matched alerts for this rule in the current tenant.</p>
            )}
            {testAlertOptions.map((alert) => (
              <label
                key={alert.id}
                className="flex items-center gap-3 rounded border border-slate-800/60 bg-slate-900/40 px-3 py-2 text-xs text-slate-300"
              >
                <input
                  type="checkbox"
                  aria-label={alert.title}
                  checked={selectedTestAlertIds.includes(alert.id)}
                  onChange={(e) => {
                    setSelectedTestAlertIds((prev) =>
                      e.target.checked
                        ? [...prev, alert.id]
                        : prev.filter((id) => id !== alert.id),
                    );
                  }}
                  className="accent-blue-500"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-200 truncate">{alert.title}</span>
                    <span className="text-[10px] uppercase tracking-wide text-slate-500">{alert.severity}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-[10px] text-slate-500">
                    <span>confidence: {alert.confidence ?? 0}</span>
                    <span>•</span>
                    <span>{alert.status}</span>
                  </div>
                </div>
              </label>
            ))}
          </div>

          <div className="flex items-center justify-between gap-3 border-t border-slate-800/50 pt-3">
            <span className="text-[10px] text-slate-500">
              {selectedTestAlertIds.length} selected
            </span>
            <button
              type="button"
              onClick={runRuleTest}
              disabled={selectedTestAlertIds.length === 0 || runningRuleTest}
              className="px-3 py-1.5 text-xs bg-blue-600/80 hover:bg-blue-600 text-white rounded disabled:opacity-50"
            >
              {runningRuleTest ? 'Running…' : 'Run test'}
            </button>
          </div>

          {testResults.length > 0 && (
            <div className="space-y-3 border-t border-slate-800/50 pt-3">
              {/* preview results */}
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Preview results</p>
              {testResults.map((result) => (
                <div key={result.alert_id} className="rounded border border-slate-800/60 bg-slate-900/35 p-3 text-xs text-slate-300 space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-200 font-mono">{result.alert_id.slice(0, 8)}…</span>
                    <span className={result.matched ? 'text-emerald-400' : 'text-slate-500'}>
                      {result.matched ? '✓ matched' : '✗ not matched'}
                    </span>
                  </div>
                  {result.matched && (
                    <div className="rounded border border-slate-700/40 bg-slate-950/40 p-2 space-y-1">
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1.5">
                        Will write to ledger
                      </p>
                      <div className="space-y-0.5 font-mono text-[10px]">
                        <div className="flex gap-2">
                          <span className="text-slate-600 w-24 shrink-0">stage:</span>
                          <span className="text-slate-300">respond</span>
                        </div>
                        <div className="flex gap-2">
                          <span className="text-slate-600 w-24 shrink-0">kind:</span>
                          <span className="text-slate-300">action</span>
                        </div>
                        <div className="flex gap-2">
                          <span className="text-slate-600 w-24 shrink-0">action_slug:</span>
                          <span className="text-slate-200">{result.action_slug}</span>
                        </div>
                        <div className="flex gap-2">
                          <span className="text-slate-600 w-24 shrink-0">status:</span>
                          <span className="text-amber-400">{result.status}</span>
                        </div>
                      </div>
                    </div>
                  )}
                  {result.reason && (
                    <p className="text-[11px] text-slate-500 italic">{result.reason}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </RunbookModal>

      {loading && (
        <p className="text-xs text-slate-500">Loading rules…</p>
      )}

      {!loading && rules.length === 0 && !creating && editingRule === null && (
        <div className="rounded-lg border border-slate-800/60 bg-slate-950/20 p-6 text-center space-y-2">
          <p className="text-sm text-slate-400">No automation rules yet.</p>
          <p className="text-xs text-slate-600">
            Rules fire automatically on alert or case events, evaluate conditions,
            and record governed actions in the ledger — all in dry-run mode by default.
          </p>
        </div>
      )}

      {!loading && rules.length > 0 && filteredRules.length === 0 && (
        <div className="rounded-lg border border-slate-800/60 bg-slate-950/20 p-6 text-center">
          <p className="text-sm text-slate-400">No rule matches “{search.trim()}”</p>
          <p className="mt-1 text-xs text-slate-600">
            Search covers the name, description, action, trigger, autonomy, owner and
            the conditions themselves.
          </p>
          <button
            type="button"
            onClick={() => setSearch('')}
            className="mt-2 rounded border border-slate-700/60 px-2 py-1 text-[10px] text-slate-400 hover:text-slate-200"
          >
            Clear search
          </button>
        </div>
      )}

      <div className="space-y-2">
        {filteredRules.map((rule) => (
          <RuleRow
            key={rule.id}
            rule={rule}
            onToggle={handleToggle}
            onEdit={(selectedRule) => {
              setCreating(false);
              setCloneBase(null);
              setEditingRuleId(selectedRule.id);
            }}
            onDelete={handleDelete}
            onClone={handleClone}
            onTest={handleRuleTestOpen}
          />
        ))}
      </div>
    </div>
  );
};
