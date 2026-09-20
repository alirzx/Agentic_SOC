'use client';

import { useState } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import toast from 'react-hot-toast';
import {
  alertsApi,
  agentsApi,
  ledgerApi,
  feedbackApi,
  type Alert,
  type AgentInvestigation,
  type ConfidenceFactor,
  type ConfidenceLabel,
  type AnalystVerdict,
  type RedispositionCandidate,
} from '@/lib/api';
import { format, isValid } from 'date-fns';
import { clsx } from 'clsx';
import { ContextualActions } from '@/components/copilot/ContextualActions';
import { ExplainDrawer } from '@/components/alerts/ExplainDrawer';
import { CreateCaseModal } from '@/components/alerts/CreateCaseModal';
import { ErrorState } from '@/components/ui/ErrorState';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', badge: 'bg-red-500/10 text-red-400 ring-red-500/20', dot: 'bg-red-500' },
  high: { label: 'High', badge: 'bg-orange-500/10 text-orange-400 ring-orange-500/20', dot: 'bg-orange-500' },
  medium: { label: 'Medium', badge: 'bg-yellow-500/10 text-yellow-400 ring-yellow-500/20', dot: 'bg-yellow-500' },
  low: { label: 'Low', badge: 'bg-brand-500/10 text-brand-400 ring-brand-500/20', dot: 'bg-brand-500' },
  info: { label: 'Info', badge: 'bg-gray-500/10 text-gray-400 ring-gray-500/20', dot: 'bg-gray-500' },
} as const;

const STATUS_CONFIG = {
  new: { label: 'New', badge: 'bg-brand-500/10 text-brand-400 ring-brand-500/20' },
  triaged: { label: 'Triaged', badge: 'bg-purple-500/10 text-purple-400 ring-purple-500/20' },
  investigating: { label: 'Investigating', badge: 'bg-yellow-500/10 text-yellow-400 ring-yellow-500/20' },
  resolved: { label: 'Resolved', badge: 'bg-green-500/10 text-green-400 ring-green-500/20' },
  false_positive: { label: 'False Positive', badge: 'bg-gray-500/10 text-gray-400 ring-gray-500/20' },
} as const;

const CONFIDENCE_CONFIG: Record<ConfidenceLabel, { label: string; badge: string; dot: string; description: string }> = {
  high: {
    label: 'High Confidence',
    badge: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/20',
    dot: 'bg-emerald-500',
    description: 'Multiple corroborating signals; low risk of false positive.',
  },
  medium: {
    label: 'Medium Confidence',
    badge: 'bg-amber-500/10 text-amber-400 ring-amber-500/20',
    dot: 'bg-amber-500',
    description: 'Mixed signals; review supporting evidence before action.',
  },
  low: {
    label: 'Low Confidence',
    badge: 'bg-slate-500/10 text-slate-300 ring-slate-500/20',
    dot: 'bg-slate-400',
    description: 'Weak or partial signal; likely needs analyst validation.',
  },
};

function formatAlertTime(raw: string | undefined, pattern: string): string {
  if (!raw) return '—';
  const cleaned = raw.replace(/([+-]\d{2}:\d{2})Z$/, '$1');
  const date = new Date(cleaned);
  if (!isValid(date)) return '—';
  try {
    return format(date, pattern);
  } catch {
    return '—';
  }
}

// ─── Sections ─────────────────────────────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-dark-60 border border-[#374151]/60 rounded-xl p-5">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">{title}</h3>
      {children}
    </div>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-4">
      <span className="text-xs text-gray-500 w-32 shrink-0 pt-0.5">{label}</span>
      <span className="text-sm text-gray-200">{value}</span>
    </div>
  );
}

function IOCBadge({ type, value, malicious }: { type: string; value: string; malicious?: boolean }) {
  return (
    <div className={clsx(
      'flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-mono',
      malicious
        ? 'bg-red-500/10 border border-red-500/20 text-red-300'
        : 'bg-dark-20/60 border border-[#333A47]/60 text-gray-300'
    )}>
      <span className={clsx(
        'px-1.5 py-0.5 rounded text-xs font-bold uppercase',
        malicious ? 'bg-red-500/20 text-red-400' : 'bg-gray-700 text-gray-400'
      )}>
        {type}
      </span>
      <span className="truncate max-w-xs">{value}</span>
      {malicious && <span className="ml-auto text-red-400 shrink-0 text-[10px] font-semibold uppercase tracking-wide">malicious</span>}
    </div>
  );
}

// ─── Detection Confidence ─────────────────────────────────────────────────────

function ConfidenceChip({ label, score }: { label: ConfidenceLabel; score?: number }) {
  const cfg = CONFIDENCE_CONFIG[label];
  const pct = typeof score === 'number' ? Math.round(score * 100) : null;
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded ring-1 ring-inset',
        cfg.badge,
      )}
      title={cfg.description}
    >
      <span className={clsx('w-2 h-2 rounded-full', cfg.dot)} />
      {cfg.label}
      {pct !== null && <span className="opacity-70 font-mono">· {pct}%</span>}
    </span>
  );
}

function ConfidenceFactorBar({ factor }: { factor: ConfidenceFactor }) {
  const pct = Math.max(0, Math.min(1, factor.contribution / Math.max(factor.weight, 0.001)));
  const widthPct = Math.round(pct * 100);
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3 mb-1">
        <span className="text-sm text-gray-200">{factor.label}</span>
        <span className="text-xs font-mono text-gray-500 shrink-0">
          +{factor.contribution.toFixed(2)} / {factor.weight.toFixed(2)}
        </span>
      </div>
      <div className="h-1.5 bg-dark-20 rounded overflow-hidden">
        <div
          className="h-full bg-emerald-500/70"
          style={{ width: `${widthPct}%` }}
          aria-hidden="true"
        />
      </div>
      <div className="text-[10px] text-gray-600 uppercase tracking-wider mt-1 font-mono">
        {factor.factor}
      </div>
    </div>
  );
}

function ConfidenceExplainability({
  label,
  score,
  rationale,
  ledgerRunId,
}: {
  label: ConfidenceLabel;
  score?: number;
  rationale: ConfidenceFactor[];
  ledgerRunId?: string;
}) {
  const cfg = CONFIDENCE_CONFIG[label];
  const sortedRationale = [...rationale].sort((a, b) => b.contribution - a.contribution);

  return (
    <Section title="Detection Confidence">
      <div className="space-y-4">
        <div className="flex items-start gap-3">
          <span className={clsx('w-2.5 h-2.5 rounded-full mt-1.5 shrink-0', cfg.dot)} />
          <div className="flex-1">
            <div className="flex items-baseline gap-3">
              <span className="text-sm font-semibold text-gray-100">{cfg.label}</span>
              {typeof score === 'number' && (
                <span className="text-xs font-mono text-gray-500">
                  score {score.toFixed(2)} ({Math.round(score * 100)}%)
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500 mt-0.5">{cfg.description}</p>
          </div>
        </div>

        {sortedRationale.length > 0 && (
          <div className="space-y-3 pt-2 border-t border-[#374151]/60">
            <p className="text-xs font-medium text-gray-400">
              Why this score
            </p>
            <div className="space-y-3">
              {sortedRationale.map((factor) => (
                <ConfidenceFactorBar key={factor.factor} factor={factor} />
              ))}
            </div>
          </div>
        )}

        {ledgerRunId && (
          <div className="pt-3 border-t border-[#374151]/60">
            <LedgerEvidenceChain runId={ledgerRunId} />
          </div>
        )}
      </div>
    </Section>
  );
}

function LedgerEvidenceChain({ runId }: { runId: string }) {
  const { data, error, isLoading } = useSWR(
    ['ledger-events', runId],
    () => ledgerApi.listEvents(runId, { limit: 8 }),
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-gray-400">Investigation Ledger evidence chain</p>
        <Link
          href={`/investigations/${runId}`}
          className="text-xs text-brand-400 hover:text-brand-300"
        >
          Open full ledger →
        </Link>
      </div>

      {isLoading && (
        <p className="text-xs text-gray-600">Loading evidence chain…</p>
      )}

      {error && !data && (
        <p className="text-xs text-gray-500">
          Evidence chain not yet available for this alert.
        </p>
      )}

      {data && data.items.length === 0 && (
        <p className="text-xs text-gray-500">
          No ledger events recorded yet — start an investigation to populate the chain.
        </p>
      )}

      {data && data.items.length > 0 && (
        <ol className="space-y-2">
          {data.items.map((event) => (
            <li key={event.id} className="flex gap-3">
              <div className="flex flex-col items-center shrink-0 pt-1">
                <span className="w-1.5 h-1.5 bg-brand-500 rounded-full" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-2">
                  <span className="text-[10px] font-mono text-gray-600 shrink-0">
                    #{event.seq}
                  </span>
                  <span className="text-xs font-mono text-brand-400 shrink-0">
                    {event.kind}
                  </span>
                  <span className="text-xs text-gray-200 truncate">
                    {event.summary}
                  </span>
                </div>
                <div className="text-[10px] text-gray-600 mt-0.5" suppressHydrationWarning>
                  {event.agent} · {formatAlertTime(event.ts, 'HH:mm:ss')}
                </div>
              </div>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

// ─── AI Investigation Panel ───────────────────────────────────────────────────

function AIInvestigation({ alertId }: { alertId: string }) {
  const [investigation, setInvestigation] = useState<AgentInvestigation | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const startInvestigation = async () => {
    setIsRunning(true);
    try {
      const result = await agentsApi.investigate(alertId);
      setInvestigation(result);
    } catch (err) {
      toast.error(
        err instanceof Error
          ? err.message
          : 'Investigation failed — no demo report is shown.',
      );
    } finally {
      setIsRunning(false);
    }
  };

  if (!investigation) {
    return (
      <div className="text-center py-8">
        <p className="text-sm text-gray-400 mb-1">Agent investigation</p>
        <p className="text-xs text-gray-600 mb-4">Run the agent on this alert to produce a markdown report, MITRE mapping, and a list of recommended actions. Every step is recorded in the case ledger.</p>
        <button
          onClick={startInvestigation}
          disabled={isRunning}
          className="bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium px-6 py-2 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isRunning ? (
            <span className="flex items-center gap-2">
              <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Investigating...
            </span>
          ) : (
            'Start AI Investigation'
          )}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={clsx(
            'w-2 h-2 rounded-full',
            investigation.status === 'completed' ? 'bg-green-500' :
            investigation.status === 'running' ? 'bg-brand-500 animate-pulse' :
            'bg-red-500'
          )} />
          <span className="text-xs text-gray-400 capitalize">{investigation.status}</span>
        </div>
        <button
          onClick={startInvestigation}
          className="text-xs text-brand-400 hover:text-brand-300"
        >
          Re-investigate
        </button>
      </div>

      {/* Findings */}
      {investigation.findings && (
        <div className="bg-dark-80/60 rounded-lg p-4 text-xs text-gray-300 font-mono leading-relaxed whitespace-pre-wrap max-h-64 overflow-y-auto">
          {investigation.findings}
        </div>
      )}

      {/* Recommendations */}
      {investigation.recommendations && investigation.recommendations.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-gray-400">Recommended Actions</p>
          {investigation.recommendations.map((rec, i) => (
            <div key={i} className="flex items-start gap-2 text-xs text-gray-300">
              <span className="text-brand-400 shrink-0 mt-0.5">→</span>
              {rec}
            </div>
          ))}
        </div>
      )}

      {/* Actions */}
      {investigation.actions && investigation.actions.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-gray-400">Automated Actions Available</p>
          {investigation.actions.map((action, i) => (
            <div key={i} className="flex items-center justify-between bg-dark-20/60 rounded-lg px-3 py-2">
              <div className="flex items-center gap-2">
                <span className="text-xs text-brand-400 font-mono">{action.type}</span>
                <span className="text-xs text-gray-500">→</span>
                <span className="text-xs text-gray-300 font-mono">{action.target}</span>
              </div>
              <button className="text-xs bg-brand-600/20 text-brand-400 hover:bg-brand-600/40 px-2 py-1 rounded transition-colors">
                Execute
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Analyst Override Panel — Tier 1.5 feedback loop ────────────────────────
//
// When the AI agent gets a verdict wrong, the analyst clicks the corrected
// verdict here. The override:
//   1. updates the alert's ``disposition`` server-side
//   2. is persisted to ``aisoc_institutional_memory`` so future investigations
//      of similar alerts pull this up
//   3. surfaces *retroactive candidates* — past alerts that share the same
//      coarse signature (category + connector + primary MITRE technique) and
//      would now flip disposition. The analyst can bulk-apply with one click.
//
// This is the single highest-leverage learning loop in the platform: every
// override = one teaching moment that re-grades the past *and* improves the
// future. Without this UI, the backend pipeline is invisible to the SOC.

const VERDICT_OPTIONS: Array<{
  value: AnalystVerdict;
  label: string;
  description: string;
  badge: string;
}> = [
  {
    value: 'true_positive',
    label: 'True Positive',
    description: 'Real threat — the AI got it right or under-called it',
    badge: 'bg-red-500/10 text-red-300 ring-red-500/30',
  },
  {
    value: 'false_positive',
    label: 'False Positive',
    description: 'Not a threat — the AI over-called it',
    badge: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
  },
  {
    value: 'benign',
    label: 'Benign',
    description: 'Expected behaviour — suppress for the same signature in future',
    badge: 'bg-sky-500/10 text-sky-300 ring-sky-500/30',
  },
  {
    value: 'escalate',
    label: 'Escalate',
    description: 'Needs human follow-up beyond what the agent can do',
    badge: 'bg-amber-500/10 text-amber-300 ring-amber-500/30',
  },
];

const VERDICT_LABEL: Record<AnalystVerdict, string> = {
  true_positive: 'True Positive',
  false_positive: 'False Positive',
  benign: 'Benign',
  escalate: 'Escalate',
};

function AnalystOverridePanel({
  alert,
  onMutate,
}: {
  alert: Alert;
  onMutate: () => void;
}) {
  const currentDisposition = alert.disposition ?? null;
  const [verdict, setVerdict] = useState<AnalystVerdict | null>(null);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [candidates, setCandidates] = useState<RedispositionCandidate[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [applying, setApplying] = useState(false);
  const [memoryKey, setMemoryKey] = useState<string | null>(null);

  const submit = async () => {
    if (!verdict) return;
    setSubmitting(true);
    try {
      const resp = await feedbackApi.submitOverride({
        alert_id: alert.id,
        // We record the AI's confidence band as the original_verdict — it's
        // the most honest summary of what the AI thought before the analyst
        // intervened. Falls back to "unverified" when the AI never produced
        // a labelled output.
        original_verdict:
          currentDisposition ??
          alert.confidenceLabel ??
          'unverified',
        corrected_verdict: verdict,
        reason: reason.trim() || undefined,
      });
      setCandidates(resp.redisposition_candidates);
      setMemoryKey(resp.memory_key);
      // Pre-select every candidate; the analyst opts *out* by unchecking.
      setSelectedIds(new Set(resp.redisposition_candidates.map((c) => c.alert_id)));
      toast.success(
        resp.redisposition_candidates.length > 0
          ? `Recorded — ${resp.redisposition_candidates.length} similar past alerts found`
          : 'Recorded — institutional memory updated',
      );
      onMutate();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to submit override');
    } finally {
      setSubmitting(false);
    }
  };

  const applyAll = async () => {
    if (!verdict || selectedIds.size === 0) return;
    setApplying(true);
    try {
      const resp = await feedbackApi.applyRedisposition({
        alert_ids: Array.from(selectedIds),
        new_disposition: verdict,
      });
      toast.success(
        `Re-dispositioned ${resp.updated} past alert${resp.updated === 1 ? '' : 's'}`,
      );
      // Drop applied candidates from the panel so we don't bulk-apply twice.
      setCandidates((prev) =>
        prev.filter((c) => !selectedIds.has(c.alert_id)),
      );
      setSelectedIds(new Set());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to apply re-disposition');
    } finally {
      setApplying(false);
    }
  };

  const toggle = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    setSelectedIds(new Set(candidates.map((c) => c.alert_id)));
  };
  const clearAll = () => setSelectedIds(new Set());

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium text-gray-300">
            Was the AI right?
          </p>
          <p className="text-[11px] text-gray-500 mt-0.5">
            Your correction is written to institutional memory and re-grades
            similar past alerts.
          </p>
        </div>
        {currentDisposition && (
          <span className="text-[10px] uppercase tracking-wider text-gray-500 shrink-0">
            current ·{' '}
            <span className="text-gray-300">
              {VERDICT_LABEL[currentDisposition as AnalystVerdict] ??
                currentDisposition}
            </span>
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2">
        {VERDICT_OPTIONS.map((opt) => {
          const active = verdict === opt.value;
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => setVerdict(opt.value)}
              className={clsx(
                'text-left p-2.5 rounded-md ring-1 transition-colors',
                active
                  ? `${opt.badge} ring-inset`
                  : 'bg-dark-70/80 text-gray-300 ring-gray-800 hover:bg-dark-70/80 hover:ring-gray-700',
              )}
            >
              <div className="text-xs font-medium">{opt.label}</div>
              <div
                className={clsx(
                  'text-[10px] mt-0.5 leading-snug',
                  active ? 'opacity-90' : 'text-gray-500',
                )}
              >
                {opt.description}
              </div>
            </button>
          );
        })}
      </div>

      <div>
        <label className="text-[11px] text-gray-500 block mb-1">
          Reason (optional, surfaced in institutional memory)
        </label>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="e.g. matches our weekly vuln-scanner sweep — known benign"
          rows={2}
          className="w-full bg-dark-60 border border-[#374151] rounded-md px-2.5 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-brand-500 resize-none"
        />
      </div>

      <button
        type="button"
        onClick={submit}
        disabled={!verdict || submitting}
        className={clsx(
          'w-full text-sm font-medium px-3 py-2 rounded-md transition-colors',
          !verdict || submitting
            ? 'bg-dark-20 text-gray-500 cursor-not-allowed'
            : 'bg-brand-600 hover:bg-brand-500 text-white',
        )}
      >
        {submitting ? 'Recording…' : 'Record correction'}
      </button>

      {memoryKey && (
        <p className="text-[10px] text-gray-500 font-mono break-all">
          memory key · {memoryKey}
        </p>
      )}

      {candidates.length > 0 && (
        <div className="space-y-2 pt-3 border-t border-[#374151]">
          <div className="flex items-center justify-between gap-2">
            <div>
              <p className="text-xs font-medium text-amber-300">
                {candidates.length} past alert
                {candidates.length === 1 ? '' : 's'} match this signature
              </p>
              <p className="text-[10px] text-gray-500 mt-0.5">
                Apply &ldquo;{verdict ? VERDICT_LABEL[verdict] : ''}&rdquo; to
                everything still selected.
              </p>
            </div>
            <div className="flex items-center gap-1.5 text-[10px]">
              <button
                type="button"
                onClick={selectAll}
                className="text-brand-400 hover:text-brand-300"
              >
                all
              </button>
              <span className="text-gray-700">·</span>
              <button
                type="button"
                onClick={clearAll}
                className="text-gray-400 hover:text-gray-300"
              >
                none
              </button>
            </div>
          </div>

          <div className="max-h-56 overflow-y-auto space-y-1 pr-1">
            {candidates.map((c) => {
              const checked = selectedIds.has(c.alert_id);
              return (
                <label
                  key={c.alert_id}
                  className={clsx(
                    'flex items-start gap-2 p-2 rounded-md ring-1 cursor-pointer transition-colors',
                    checked
                      ? 'bg-brand-500/5 ring-brand-500/40'
                      : 'bg-dark-70/80 ring-gray-800 hover:bg-dark-70/80',
                  )}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggle(c.alert_id)}
                    className="mt-0.5 accent-blue-500"
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[10px] uppercase tracking-wider text-gray-500">
                        {c.severity}
                      </span>
                      <span className="text-[10px] text-gray-600">·</span>
                      <span className="text-[10px] text-gray-500" suppressHydrationWarning>
                        {format(new Date(c.event_time), 'MMM d, HH:mm')}
                      </span>
                      {c.current_disposition && (
                        <>
                          <span className="text-[10px] text-gray-600">·</span>
                          <span className="text-[10px] text-gray-500">
                            was{' '}
                            <span className="text-gray-300">
                              {VERDICT_LABEL[
                                c.current_disposition as AnalystVerdict
                              ] ?? c.current_disposition}
                            </span>
                          </span>
                        </>
                      )}
                    </div>
                    <Link
                      href={`/alerts/${c.alert_id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="text-xs text-gray-200 hover:text-brand-300 line-clamp-2 leading-snug block"
                    >
                      {c.title}
                    </Link>
                  </div>
                </label>
              );
            })}
          </div>

          <button
            type="button"
            onClick={applyAll}
            disabled={selectedIds.size === 0 || applying}
            className={clsx(
              'w-full text-xs font-medium px-3 py-2 rounded-md transition-colors',
              selectedIds.size === 0 || applying
                ? 'bg-dark-20 text-gray-500 cursor-not-allowed'
                : 'bg-amber-500/20 text-amber-200 hover:bg-amber-500/30 ring-1 ring-amber-500/30',
            )}
          >
            {applying
              ? 'Applying…'
              : `Re-disposition ${selectedIds.size} alert${
                  selectedIds.size === 1 ? '' : 's'
                }`}
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export function AlertDetailView({ alertId }: { alertId: string }) {
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'raw'>('overview');
  // Side drawer for the "Explain this alert" structured walkthrough
  // (`POST /api/v1/explain`). Kept local to the detail view because it
  // only makes sense while a single alert is on screen.
  const [explainOpen, setExplainOpen] = useState(false);
  // Alert→case promotion modal (issue #293). Opened from the header
  // "Create Case" affordance; lets the analyst spin up a new case or attach
  // the alert to an existing one before running a playbook.
  const [createCaseOpen, setCreateCaseOpen] = useState(false);

  const { data: alert, error, isLoading, mutate } = useSWR(
    ['alert', alertId],
    () => alertsApi.get(alertId),
  );

  const handleStatusChange = async (newStatus: Alert['status']) => {
    try {
      await alertsApi.update(alertId, { status: newStatus });
      mutate();
    } catch {
      toast.error('Could not update alert status');
    }
  };

  if (isLoading && !alert) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500 animate-pulse">
        Loading alert...
      </div>
    );
  }

  if (error || !alert) {
    return (
      <ErrorState
        title="Alert not found"
        description="This ID is not in the live alert store for the current tenant. No demo alert is shown — open the Alerts list for Splunk notables."
        error={error}
        onRetry={() => mutate()}
        action={
          <Link
            href="/alerts"
            className="rounded-md border border-[#374151] bg-dark-60 px-4 py-2 text-sm font-medium text-gray-200 hover:bg-dark-20"
          >
            Back to alerts
          </Link>
        }
      />
    );
  }

  const sevCfg =
    SEVERITY_CONFIG[alert.severity as keyof typeof SEVERITY_CONFIG] ??
    SEVERITY_CONFIG.info;
  const stsCfg = STATUS_CONFIG[alert.status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.new;

  return (
    <div className="space-y-5 max-w-6xl">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-xs text-gray-500">
        <Link href="/alerts" className="hover:text-gray-300">Alerts</Link>
        <span>›</span>
        <span className="text-gray-300">{alert.id}</span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1 flex-wrap">
            <span className={clsx('inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded ring-1 ring-inset', sevCfg.badge)}>
              <span className={clsx('w-2 h-2 rounded-full', sevCfg.dot)} />
              {sevCfg.label}
            </span>
            <span className={clsx('inline-flex px-2.5 py-1 text-xs font-medium rounded ring-1 ring-inset', stsCfg.badge)}>
              {stsCfg.label}
            </span>
            {alert.confidenceLabel && (
              <ConfidenceChip
                label={alert.confidenceLabel}
                score={alert.confidenceScore}
              />
            )}
            <span className="text-xs text-gray-500">Risk Score: <span className="text-white font-bold">{alert.riskScore}</span></span>
          </div>
          <h1 className="text-lg font-semibold text-gray-100">{alert.title}</h1>
          <p className="text-sm text-gray-500 mt-1" suppressHydrationWarning>{alert.source} · {formatAlertTime(alert.createdAt, 'MMM d, yyyy HH:mm:ss')}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <select
            value={alert.status}
            onChange={(e) => handleStatusChange(e.target.value as Alert['status'])}
            className="bg-dark-20 border border-[#333A47] text-sm text-gray-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-brand-500"
          >
            {Object.entries(STATUS_CONFIG).map(([key, cfg]) => (
              <option key={key} value={key}>{cfg.label}</option>
            ))}
          </select>
          {/*
            Primary L1/L2 affordance: open the structured "What happened
            and what should I do?" drawer. Placed in the header so it's
            the first thing a triaging analyst sees, ahead of the heavier
            Create Case action.
          */}
          <button
            type="button"
            onClick={() => setExplainOpen(true)}
            className="bg-purple-600/90 hover:bg-purple-500 text-white text-sm font-medium px-4 py-1.5 rounded-lg transition-colors inline-flex items-center gap-1.5"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M12 2a7 7 0 0 0-4 12.74V17a2 2 0 0 0 2 2h4a2 2 0 0 0 2-2v-2.26A7 7 0 0 0 12 2z" />
              <line x1="9" y1="22" x2="15" y2="22" />
            </svg>
            Explain
          </button>
          <button
            type="button"
            onClick={() => setCreateCaseOpen(true)}
            className="bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium px-4 py-1.5 rounded-lg transition-colors"
          >
            Create Case
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-[#374151]">
        {(['overview', 'timeline', 'raw'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={clsx(
              'px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px',
              activeTab === tab
                ? 'text-brand-400 border-blue-400'
                : 'text-gray-500 border-transparent hover:text-gray-300'
            )}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Content */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-3 gap-4">
          {/* Left column - 2/3 */}
          <div className="col-span-2 space-y-4">
            {/*
              Ambient Copilot — quick contextual AI buttons. Backed by the
              `services/agents` `/api/v1/contextual` endpoints. We pass a
              compact snapshot of the alert (no rawEvent blob) so the LLM has
              grounding without ballooning token usage.
            */}
            <ContextualActions
              page="alerts"
              entityId={alert.id}
              entity={{
                title: alert.title,
                description: alert.description,
                severity: alert.severity,
                status: alert.status,
                source: alert.source,
                source_ref: alert.sourceRef,
                risk_score: alert.riskScore,
                tags: alert.tags,
                mitre_attack: alert.mitreAttack,
                iocs: alert.iocs,
                created_at: alert.createdAt,
              }}
              eyebrow="Ask AiSOC about this alert"
            />

            <Section title="Description">
              <p className="text-sm text-gray-300 leading-relaxed">{alert.description}</p>
            </Section>

            {alert.confidenceLabel && (
              <ConfidenceExplainability
                label={alert.confidenceLabel}
                score={alert.confidenceScore}
                rationale={alert.confidenceRationale ?? []}
                ledgerRunId={alert.ledgerRunId}
              />
            )}

            <Section title="Details">
              <div className="space-y-3">
                <Field label="Source" value={alert.source} />
                <Field label="Source Ref" value={alert.sourceRef || '—'} />
                <Field label="Tenant" value={alert.tenantId} />
                <Field label="Assignee" value={alert.assignee || <span className="text-gray-500">Unassigned</span>} />
                <Field label="Created" value={<span suppressHydrationWarning>{formatAlertTime(alert.createdAt, 'MMM d, yyyy HH:mm:ss')}</span>} />
                {alert.resolvedAt && (
                  <Field label="Resolved" value={<span suppressHydrationWarning>{formatAlertTime(alert.resolvedAt, 'MMM d, yyyy HH:mm:ss')}</span>} />
                )}
                {alert.tags && alert.tags.length > 0 && (
                  <Field label="Tags" value={
                    <div className="flex flex-wrap gap-1">
                      {alert.tags.map((tag) => (
                        <span key={tag} className="px-2 py-0.5 bg-dark-20 text-gray-300 text-xs rounded">{tag}</span>
                      ))}
                    </div>
                  } />
                )}
              </div>
            </Section>

            {/* MITRE ATT&CK */}
            {alert.mitreAttack && alert.mitreAttack.length > 0 && (
              <Section title="MITRE ATT&CK">
                <div className="space-y-2">
                  {alert.mitreAttack.map((m, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 bg-purple-500/5 border border-purple-500/20 rounded-lg">
                      <span className="text-xs font-mono text-purple-400 bg-purple-500/10 px-2 py-1 rounded">{m.techniqueId}</span>
                      <div>
                        <div className="text-sm text-gray-200">{m.technique}</div>
                        <div className="text-xs text-gray-500">Tactic: {m.tactic}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </Section>
            )}

            {/* IOCs */}
            {alert.iocs && alert.iocs.length > 0 && (
              <Section title="Indicators of Compromise">
                <div className="space-y-2">
                  {alert.iocs.map((ioc, i) => (
                    <IOCBadge key={i} {...ioc} />
                  ))}
                </div>
              </Section>
            )}
          </div>

          {/* Right column - 1/3 */}
          <div className="space-y-4">
            <Section title="AI Investigation">
              <AIInvestigation alertId={alertId} />
            </Section>

            <Section title="Verdict & feedback">
              <AnalystOverridePanel alert={alert} onMutate={mutate} />
            </Section>
          </div>
        </div>
      )}

      {activeTab === 'timeline' && (
        <Section title="Event Timeline">
          <div className="space-y-4">
            {[
              { time: alert.createdAt, type: 'alert_created', title: 'Alert Created', desc: `Alert ingested from ${alert.source}` },
              { time: alert.updatedAt, type: 'status_change', title: 'Status Updated', desc: `Status changed to ${alert.status}` },
            ].map((event, i) => (
              <div key={i} className="flex gap-4">
                <div className="flex flex-col items-center">
                  <div className="w-2 h-2 bg-brand-500 rounded-full mt-1.5 shrink-0" />
                  {i < 1 && <div className="w-px flex-1 bg-dark-20 mt-1" />}
                </div>
                <div className="pb-4">
                  <div className="text-sm font-medium text-gray-200">{event.title}</div>
                  <div className="text-xs text-gray-500 mt-0.5">{event.desc}</div>
                  <div className="text-xs text-gray-600 mt-1" suppressHydrationWarning>{formatAlertTime(event.time, 'MMM d, yyyy HH:mm:ss')}</div>
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {activeTab === 'raw' && (
        <Section title="Raw Event Data">
          <pre className="text-xs text-gray-400 font-mono bg-dark-80/60 rounded-lg p-4 overflow-x-auto">
            {JSON.stringify(alert.rawEvent || { message: 'Raw event data not available for this alert.' }, null, 2)}
          </pre>
        </Section>
      )}

      {/*
        Explain drawer is mounted at the root of the detail view so it
        can overlay tabs without unmounting on tab switch. It only fires
        a network call when `open` flips true (see useEffect inside).
      */}
      <ExplainDrawer
        open={explainOpen}
        onClose={() => setExplainOpen(false)}
        alert={alert}
        onRunPlaybook={(pid) => {
          toast.success(`Queued playbook ${pid}`);
          setExplainOpen(false);
        }}
      />

      <CreateCaseModal
        open={createCaseOpen}
        onClose={() => setCreateCaseOpen(false)}
        alert={alert}
      />
    </div>
  );
}
