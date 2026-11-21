'use client';

/**
 * Candidate inspection surface.
 *
 * A thin wrapper over the shared correlation modal. It owns the analyst alert
 * scope (excluded ids + `llm_payload` filters) and re-fetches the candidate with
 * that scope, so the graph, the pair scores and the timeline are recomputed
 * server-side from the surviving evidence — never filtered client-side. The
 * same scope travels to the promotion call, so the case that gets created
 * claims exactly the alerts the analyst approved.
 */

import { useState } from 'react';
import {
  useCaseCandidateDetail,
  type AlertScope,
  type GraphObservationMode,
} from '@/hooks/useCaseCandidates';
import { CorrelationInspectModal } from '@/components/correlation/CorrelationInspectModal';

interface CandidateInspectModalProps {
  candidateKey: string | null;
  onClose: () => void;
  /** Promote the candidate, excluding the alerts the analyst crossed out. */
  onCreateCase: (candidateKey: string, scope: AlertScope) => void;
  /** True while the promotion request is in flight. */
  creatingCase?: boolean;
  /** Why the last promotion attempt failed, shown inline. */
  createError?: string | null;
}

const EMPTY_SCOPE: AlertScope = { excluded_alert_ids: [], filters: [] };

export function CandidateInspectModal({
  candidateKey,
  onClose,
  onCreateCase,
  creatingCase = false,
  createError = null,
}: CandidateInspectModalProps) {
  const [scope, setScope] = useState<AlertScope>(EMPTY_SCOPE);
  // Undefined = the server default (env flag); an explicit choice re-fetches.
  const [observationMode, setObservationMode] = useState<GraphObservationMode | undefined>();

  // Opening another candidate must not inherit the previous one's exclusions.
  const [renderedKey, setRenderedKey] = useState(candidateKey);
  if (candidateKey !== renderedKey) {
    setRenderedKey(candidateKey);
    setScope(EMPTY_SCOPE);
    setObservationMode(undefined);
  }

  const { candidate, loading, error } = useCaseCandidateDetail(
    candidateKey,
    scope,
    observationMode
  );

  if (!candidateKey) return null;

  // Determine the empty message based on error or no payload
  let emptyMessage: string | undefined;
  if (error) {
    if (error.status === 503 || error.message?.includes('connect')) {
      emptyMessage =
        'Could not load the correlation graph.\n\nThe graph is built from correlated observations. Check that:\n• The correlation service is running\n• The worker has processed these alerts (check logs)\n• Alerts meet the correlation threshold (θ ≥ 3)';
    } else {
      emptyMessage =
        `Could not load the correlation graph. Check the API service health or wait for the worker to process these alerts. (error: ${error?.message ?? 'unknown'})`;
    }
  } else if (!candidate) {
    emptyMessage =
      'No graph available yet. The worker builds the graph by analyzing alert relationships on each cycle.';
  }

  const excludeAlert = (alertId: string) => {
    setScope((current) =>
      current.excluded_alert_ids.includes(alertId)
        ? current
        : { ...current, excluded_alert_ids: [...current.excluded_alert_ids, alertId] }
    );
  };

  const scoped = scope.excluded_alert_ids.length > 0 || scope.filters.length > 0;

  return (
    <CorrelationInspectModal
      detail={candidate ?? null}
      loading={loading}
      onClose={onClose}
      observationMode={observationMode}
      onToggleObservationMode={setObservationMode}
      eyebrow="Graph correlation"
      eyebrowNote="candidate"
      scope={scope}
      onScopeChange={setScope}
      onExcludeAlert={excludeAlert}
      emptyMessage={emptyMessage}
      actions={
        <>
          {createError && (
            <span
              role="alert"
              title={`Case not created — ${createError}.`}
              className="max-w-[180px] truncate text-[11px] text-red-300"
            >
              Case not created — {createError}
            </span>
          )}
          <button
            onClick={onClose}
            className="rounded-md border border-gray-500/30 bg-gray-500/10 px-2.5 py-1 text-xs font-medium text-gray-300 transition-colors hover:bg-gray-500/20"
          >
            Close
          </button>
          <button
            onClick={() => onCreateCase(candidateKey, scope)}
            disabled={creatingCase}
            title={
              scoped
                ? 'Create a case from these alerts using the scope you applied.'
                : 'Create a case from these alerts.'
            }
            className="rounded-md border border-green-500/30 bg-green-500/10 px-2.5 py-1 text-xs font-medium text-green-300 transition-colors hover:bg-green-500/20 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {creatingCase ? 'Creating case…' : 'Create case'}
          </button>
        </>
      }
    />
  );
}
