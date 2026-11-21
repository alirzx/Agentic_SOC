'use client';

import { clsx } from 'clsx';
import { format } from 'date-fns';
import type { CandidateCard, CandidateTriage } from '@/hooks/useCaseCandidates';
import { MAX_PEAK_SCORE } from './CandidateFilterBar';

interface CandidateCardProps {
  candidate: CandidateCard;
  onInspect?: (key: string) => void;
  onCreateCase?: (key: string) => void;
  onDismiss?: (key: string) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
};

function ScoreBar({ score }: { score: number }) {
  /**
   * Peak pair score, scaled to what this build can actually produce (12).
   * It used to be divided by a hard-coded 30 while the API sent the evidence
   * total — on a real 101-alert candidate that rendered 3128/30, i.e. always
   * full. The bar is now proportional to the number it shows.
   */
  const percentage = Math.min((score / MAX_PEAK_SCORE) * 100, 100);

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-dark-40 rounded-full overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 transition-all"
          style={{ width: `${percentage}%` }}
          title={`Peak link score: ${score} / ${MAX_PEAK_SCORE} (merge threshold θ = 3)`}
        />
      </div>
      <span className="text-sm font-semibold text-gray-300 w-10 text-right tabular-nums">
        {score}
        <span className="text-[10px] font-normal text-gray-600">/{MAX_PEAK_SCORE}</span>
      </span>
    </div>
  );
}

/**
 * Verdict summary for a candidate's member alerts.
 *
 * The queue only showed a score, so an analyst could not tell a campaign backed
 * by a confirmed true positive from one nobody has triaged. Auto-closed FP and
 * benign alerts never reach this list (the engine drops them before correlating),
 * so the chips are evidence strength, not a verdict the engine scored with.
 */
function TriageSummary({ triage }: { triage?: CandidateTriage | null }) {
  if (!triage) return null;

  const chips: Array<{ key: string; label: string; count: number; className: string; title: string }> = [
    {
      key: 'true_positive',
      label: 'TP',
      count: triage.true_positive ?? 0,
      className: 'bg-red-500/15 text-red-300 border-red-500/30',
      title: 'Alerts auto-triage confirmed as true positives',
    },
    {
      key: 'likely_tp',
      label: 'Likely TP',
      count: triage.likely_tp ?? 0,
      className: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      title: 'Alerts auto-triage judged likely true positives',
    },
    {
      key: 'needs_review',
      label: 'Needs review',
      count: triage.needs_review ?? 0,
      className: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
      title: 'Alerts auto-triage could not decide without a human',
    },
    {
      key: 'escalate',
      label: 'Escalated',
      count: triage.escalate ?? 0,
      className: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
      title: 'Alerts an analyst forced to escalate',
    },
    {
      key: 'unreviewed',
      label: 'Untriaged',
      count: triage.unreviewed ?? 0,
      className: 'bg-gray-500/15 text-gray-400 border-gray-500/25',
      title: 'Alerts auto-triage has not classified yet',
    },
  ].filter((chip) => chip.count > 0);

  if (chips.length === 0) return null;

  const confidence =
    typeof triage.max_confidence === 'number'
      ? `Peak triage confidence ${triage.max_confidence}%${
          typeof triage.avg_confidence === 'number' ? ` · mean ${triage.avg_confidence}%` : ''
        }`
      : 'Triage confidence not recorded for these alerts';

  return (
    <div className="mb-3 flex flex-wrap items-center gap-1.5" title={confidence}>
      <span className="text-[10px] uppercase tracking-wide text-gray-500">Triage</span>
      {chips.map((chip) => (
        <span
          key={chip.key}
          title={chip.title}
          className={clsx(
            'rounded border px-1.5 py-0.5 text-[10px] font-medium tabular-nums',
            chip.className
          )}
        >
          {chip.label}
          {chip.key !== 'unreviewed' || chip.count > 1 ? ` ×${chip.count}` : ''}
        </span>
      ))}
    </div>
  );
}

export function CandidateCardComponent({
  candidate,
  onInspect,
  onCreateCase,
  onDismiss,
}: CandidateCardProps) {
  const severity = candidate.severity ?? 'info';
  const severityConfig = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;

  const timeStart = format(new Date(candidate.time_first), 'HH:mm:ss');
  const timeEnd = format(new Date(candidate.time_last), 'HH:mm:ss');
  const dateLine = format(new Date(candidate.time_first), 'MMM d, yyyy');

  return (
    <div className="bg-dark-60 border border-[#374151]/60 rounded-lg p-4 hover:border-[#333A47] hover:bg-dark-70/80 transition-all group">
      {/* Header: Theme + Severity Badge */}
      <div className="flex justify-between items-start mb-3">
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-gray-200 group-hover:text-white truncate">
            {candidate.campaign_theme}
          </h3>
          <p className="text-xs text-gray-500 mt-0.5">
            {candidate.candidate_key}
          </p>
        </div>
        <span
          className={clsx(
            'ml-2 px-2.5 py-1 rounded border text-xs font-medium whitespace-nowrap',
            severityConfig
          )}
        >
          {severity.charAt(0).toUpperCase() + severity.slice(1)}
        </span>
      </div>

      {/* Score Bar */}
      <div className="mb-3">
        <div className="mb-1 flex items-baseline justify-between gap-2 text-[10px] text-gray-500">
          <span>Peak link score</span>
          <span className="tabular-nums">
            Σ {candidate.evidence_score ?? 0} over {candidate.pair_count ?? 0} pair
            {(candidate.pair_count ?? 0) === 1 ? '' : 's'}
          </span>
        </div>
        <ScoreBar score={candidate.score} />
      </div>

      {/* Entity Summary Chips */}
      <div className="flex flex-wrap gap-2 mb-3">
        {candidate.entity_summary.hosts > 0 && (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-purple-500/10 text-purple-300 border border-purple-500/20 rounded text-xs font-medium">
            {candidate.entity_summary.hosts} host{candidate.entity_summary.hosts !== 1 ? 's' : ''}
          </span>
        )}
        {candidate.entity_summary.users > 0 && (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-blue-500/10 text-blue-300 border border-blue-500/20 rounded text-xs font-medium">
            {candidate.entity_summary.users} user{candidate.entity_summary.users !== 1 ? 's' : ''}
          </span>
        )}
        {candidate.entity_summary.ips > 0 && (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-green-500/10 text-green-300 border border-green-500/20 rounded text-xs font-medium">
            {candidate.entity_summary.ips} IP{candidate.entity_summary.ips !== 1 ? 's' : ''}
          </span>
        )}
        {candidate.entity_summary.domains > 0 && (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 rounded text-xs font-medium">
            {candidate.entity_summary.domains} domain{candidate.entity_summary.domains !== 1 ? 's' : ''}
          </span>
        )}
        {candidate.entity_summary.techniques > 0 && (
          <span className="inline-flex items-center gap-1 px-2 py-1 bg-red-500/10 text-red-300 border border-red-500/20 rounded text-xs font-medium">
            {candidate.entity_summary.techniques} technique{candidate.entity_summary.techniques !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      <TriageSummary triage={candidate.triage} />

      {/* Metadata: Alert Count, Time Span */}
      <div className="text-xs text-gray-500 space-y-1 mb-3">
        <p>
          <span className="font-medium">{candidate.alert_count}</span> alert{candidate.alert_count !== 1 ? 's' : ''}
        </p>
        <p>
          {dateLine} {timeStart} → {timeEnd}
        </p>
      </div>

      {/* Actions */}
      <div className="flex gap-2 pt-3 border-t border-dark-40">
        <button
          onClick={(e) => {
            e.preventDefault();
            onInspect?.(candidate.candidate_key);
          }}
          className="flex-1 px-3 py-2 rounded border border-blue-500/30 bg-blue-500/10 text-blue-300 text-xs font-medium hover:bg-blue-500/20 hover:border-blue-500/50 transition-colors"
        >
          Inspect
        </button>
        <button
          onClick={(e) => {
            e.preventDefault();
            onCreateCase?.(candidate.candidate_key);
          }}
          className="flex-1 px-3 py-2 rounded border border-green-500/30 bg-green-500/10 text-green-300 text-xs font-medium hover:bg-green-500/20 hover:border-green-500/50 transition-colors"
        >
          Create Case
        </button>
        <button
          onClick={(e) => {
            e.preventDefault();
            onDismiss?.(candidate.candidate_key);
          }}
          title="Snooze this candidate for 24h"
          className="px-3 py-2 rounded border border-gray-500/20 bg-gray-500/10 text-gray-400 hover:text-gray-300 hover:bg-gray-500/20 transition-colors"
        >
          ✕
        </button>
      </div>
    </div>
  );
}
