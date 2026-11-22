'use client';

import { useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { format } from 'date-fns';
import { browserAuthHeaders, safeFetcher } from '@/lib/fetcher';

interface SuggestionCard {
  alert_id: string;
  title: string;
  severity: string;
  score: number;
  entity_overlap: number;
  technique_overlap: number;
  created_at: string;
  reason: string;
}

interface SuggestionsPanelProps {
  caseId: string;
  onAlertAttached?: (alertId: string) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
};

export function SuggestionsPanel({
  caseId,
  onAlertAttached,
}: SuggestionsPanelProps) {
  const [isAttaching, setIsAttaching] = useState<string | null>(null);

  const { data: suggestions, isLoading, error, mutate } = useSWR<
    SuggestionCard[]
  >(caseId ? `/api/v1/cases/${caseId}/suggestions` : null, safeFetcher);

  const handlePreviewImpact = async (alertId: string) => {
    try {
      const res = await fetch(
        `/api/v1/cases/${caseId}/suggestions/${alertId}/impact`,
        { headers: browserAuthHeaders() }
      );
      if (!res.ok) throw new Error('Failed to preview impact');

      const data = await res.json();
      toast.success(
        `Score impact: +${data.delta} (${data.current_score} → ${data.new_score})`
      );
    } catch (err) {
      toast.error('Failed to preview impact');
    }
  };

  const handleAttach = async (alertId: string) => {
    setIsAttaching(alertId);
    try {
      const res = await fetch(`/api/v1/cases/${caseId}/alerts/attach`, {
        method: 'POST',
        headers: browserAuthHeaders(),
        body: JSON.stringify({ alert_ids: [alertId] }),
      });

      if (!res.ok) throw new Error('Failed to attach alert');

      toast.success('Alert attached to case');
      onAlertAttached?.(alertId);

      // Refetch suggestions
      mutate();
    } catch (err) {
      toast.error('Failed to attach alert');
    } finally {
      setIsAttaching(null);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-3">
        {[...Array(3)].map((_, i) => (
          <div
            key={i}
            className="bg-dark-60 border border-[#374151]/60 rounded-lg p-3 animate-pulse"
          >
            <div className="h-5 bg-dark-40 rounded mb-2 w-3/4" />
            <div className="h-4 bg-dark-40 rounded mb-3 w-1/2" />
            <div className="flex gap-2">
              <div className="flex-1 h-8 bg-dark-40 rounded" />
              <div className="flex-1 h-8 bg-dark-40 rounded" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-sm text-red-300">
        Failed to load suggestions
      </div>
    );
  }

  if (!suggestions || suggestions.length === 0) {
    return (
      <div className="bg-dark-60 border border-[#374151]/60 rounded-lg p-4 text-center text-gray-500">
        <p className="text-sm">No related alerts found</p>
        <p className="text-xs text-gray-600 mt-1">
          All available alerts are already in this case
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-500 font-medium">
        {suggestions.length} related alert{suggestions.length !== 1 ? 's' : ''}{' '}
        found
      </p>

      {suggestions.map((sugg) => {
        const severity = sugg.severity ?? 'info';
        const severityConfig = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
        const createdAt = format(
          new Date(sugg.created_at),
          'MMM d, HH:mm:ss'
        );

        return (
          <div
            key={sugg.alert_id}
            className="bg-dark-60 border border-[#374151]/60 rounded-lg p-3 hover:border-[#333A47] hover:bg-dark-70/80 transition-all"
          >
            <div className="flex justify-between items-start mb-2 gap-2">
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-200 truncate">
                  {sugg.title}
                </p>
                <p className="text-xs text-gray-500 mt-0.5 truncate">
                  {sugg.reason}
                </p>
              </div>
              <div className="flex items-center gap-2 ml-2 flex-shrink-0">
                <span
                  className={clsx(
                    'px-2.5 py-1 rounded border text-xs font-medium whitespace-nowrap',
                    severityConfig
                  )}
                >
                  {severity.charAt(0).toUpperCase() + severity.slice(1)}
                </span>
                <span className="text-lg font-semibold text-orange-400 w-8 text-right">
                  {sugg.score}
                </span>
              </div>
            </div>

            <div className="text-xs text-gray-500 mb-3">
              <p>
                {sugg.entity_overlap} entit
                {sugg.entity_overlap !== 1 ? 'ies' : 'y'} • {sugg.technique_overlap}{' '}
                technique{sugg.technique_overlap !== 1 ? 's' : ''}
              </p>
              <p>{createdAt}</p>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => handlePreviewImpact(sugg.alert_id)}
                disabled={isAttaching === sugg.alert_id}
                className="flex-1 px-2.5 py-1.5 text-xs rounded border border-blue-500/30 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 hover:border-blue-500/50 transition-colors disabled:opacity-50"
              >
                Preview
              </button>
              <button
                onClick={() => handleAttach(sugg.alert_id)}
                disabled={isAttaching !== null}
                className="flex-1 px-2.5 py-1.5 text-xs rounded border border-green-500/30 bg-green-500/10 text-green-300 hover:bg-green-500/20 hover:border-green-500/50 transition-colors disabled:opacity-50"
              >
                {isAttaching === sugg.alert_id ? 'Attaching...' : 'Attach'}
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
