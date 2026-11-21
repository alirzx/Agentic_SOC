'use client';

/**
 * Correlation view for a case.
 *
 * Graph-engine cases deserve the same explanation surface a candidate gets: the
 * scored graph, the L1/L2/L3 reasoning, the timeline, and the MITRE /
 * kill-chain coverage. Rather than a second renderer, this reuses
 * {@link CorrelationInspectModal} against `GET /cases/{id}/correlation`, which
 * rebuilds the component from the case's own alerts through the correlation
 * engine.
 *
 * The one case-only capability is *saving* the scope: a case outlives the
 * session, so "this scan alert is noise" has to persist. Saving does not delete
 * evidence — the alerts remain case members; they are only removed from the
 * correlation analysis and everything derived from it.
 */

import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  EMPTY_ALERT_SCOPE,
  useCaseCorrelation,
  type AlertScope,
  type CandidateScopeEcho,
  type GraphObservationMode,
} from '@/hooks/useCaseCandidates';
import { CorrelationInspectModal } from '@/components/correlation/CorrelationInspectModal';

interface CaseCorrelationModalProps {
  caseId: string;
  /** Case title — shown as the heading; the API's theme is the same string. */
  caseTitle?: string | null;
  caseNumber?: string | null;
  onClose: () => void;
}

export function CaseCorrelationModal({
  caseId,
  caseTitle,
  caseNumber,
  onClose,
}: CaseCorrelationModalProps) {
  const [scope, setScope] = useState<AlertScope>(EMPTY_ALERT_SCOPE);
  const [saving, setSaving] = useState(false);
  // Undefined = the server default (env flag); an explicit choice re-fetches.
  const [observationMode, setObservationMode] = useState<GraphObservationMode | undefined>();
  // Scope as it exists on the server — what "saved" means right now.
  const [savedScope, setSavedScope] = useState<AlertScope>(EMPTY_ALERT_SCOPE);

  const { detail, loading, error, mutate } = useCaseCorrelation(
    caseId,
    scope,
    observationMode
  );

  // The API applies the *saved* scope before the client sends anything, so the
  // first response is the source of truth for what is currently excluded.
  // Without this sync the scope bar would show an empty scope over a graph that
  // is already filtered, and the restore chips would be missing.
  const [initialised, setInitialised] = useState(false);
  if (!initialised && detail?.scope) {
    const restored: AlertScope = {
      excluded_alert_ids: detail.scope.excluded_alert_ids ?? [],
      filters: detail.scope.filters ?? [],
    };
    setInitialised(true);
    // An analyst who started excluding before the response landed keeps their
    // edit; only an untouched scope is seeded from the server.
    if (scope.excluded_alert_ids.length === 0 && scope.filters.length === 0) {
      setScope(restored);
    }
    setSavedScope(restored);
  }

  const dirty = !sameScope(scope, savedScope);

  const excludeAlert = (alertId: string) => {
    setScope((current) =>
      current.excluded_alert_ids.includes(alertId)
        ? current
        : { ...current, excluded_alert_ids: [...current.excluded_alert_ids, alertId] }
    );
  };

  const saveScope = async () => {
    setSaving(true);
    const toastId = toast.loading('Saving alert scope…');
    try {
      const response = await fetch(`/api/v1/cases/${encodeURIComponent(caseId)}/correlation/scope`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          excluded_alert_ids: scope.excluded_alert_ids,
          filters: scope.filters,
        }),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        const reason =
          typeof payload?.detail === 'string'
            ? payload.detail
            : payload?.detail?.reason ?? payload?.detail?.error ?? `HTTP ${response.status}`;
        throw new Error(String(reason));
      }
      const echo = (await response.json()) as CandidateScopeEcho;
      setSavedScope({
        excluded_alert_ids: echo.excluded_alert_ids ?? scope.excluded_alert_ids,
        filters: echo.filters ?? scope.filters,
      });
      await mutate();
      const droppedCount = (echo.dropped ?? []).length;
      toast.success(
        droppedCount === 0
          ? 'Scope cleared — every alert is back in the analysis'
          : `${droppedCount} alert(s) excluded from this case's analysis`,
        { id: toastId }
      );
    } catch (error) {
      toast.error(`Could not save the scope: ${(error as Error).message}`, { id: toastId });
    } finally {
      setSaving(false);
    }
  };

  // Get distinct rules (rule_names) from the case detail
  const [searchNames, setSearchNames] = useState<string[]>([]);
  const [searchNamesLoading, setSearchNamesLoading] = useState(true);
  useEffect(() => {
    if (detail?.campaign_theme) {
      setSearchNamesLoading(false);
    } else {
      // Fetch rules (rule_names) from the case detail endpoint
      fetch(`/api/v1/cases/${encodeURIComponent(caseId)}`)
        .then((res) => res.json())
        .then((data) => {
          setSearchNames(data.rules ?? []);
          setSearchNamesLoading(false);
        })
        .catch(() => {
          setSearchNamesLoading(false);
        });
    }
  }, [caseId, detail?.campaign_theme]);

  return (
    <CorrelationInspectModal
      detail={detail ?? null}
      observationMode={observationMode}
      onToggleObservationMode={setObservationMode}
      loading={loading}
      onClose={onClose}
      eyebrow="Case correlation"
      eyebrowNote="case"
      title={caseTitle ?? detail?.campaign_theme ?? null}
      subtitle={caseNumber ?? `case:${caseId}`}
      caseId={caseId}
      scope={scope}
      onScopeChange={setScope}
      onExcludeAlert={excludeAlert}
      emptyMessage={
        error
          ? error.status === 503 || error.message?.includes('connect')
            ? 'Could not load the correlation graph.\n\nThe graph is built from correlated observations. Check that:\n• The correlation service is running\n• The worker has processed these alerts (check logs)\n• Alerts meet the correlation threshold (θ ≥ 3)'
            : `This case's correlation payload could not be loaded. Check the API service health or wait for the worker to process the case alerts. (error: ${error?.message ?? 'unknown'})`
          : undefined
      }
      actions={
        <>
          <button
            onClick={onClose}
            // Same neutral chrome as the rest of the modal: the old grey-on-grey
            // pill read as a disabled control once the light theme was in use.
            className="rounded-md border border-[#374151] bg-dark-40 px-2.5 py-1 text-xs font-medium text-gray-200 transition-colors hover:border-gray-500 hover:text-gray-100"
          >
            Close
          </button>
          <button
            onClick={() => void saveScope()}
            // Clearing every exclusion is a legitimate save (it removes the
            // saved scope), so only "nothing changed" disables the button.
            disabled={saving || !dirty}
            title={
              dirty
                ? 'Scope changed — save it to keep this exclusion for everyone reading the case.'
                : 'Persist this scope for the case.'
            }
            className="rounded-md border border-teal-500/30 bg-teal-500/10 px-2.5 py-1 text-xs font-medium text-teal-200 transition-colors hover:bg-teal-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save scope'}
          </button>
        </>
      }
    />
  );
}

function sameScope(a: AlertScope, b: AlertScope): boolean {
  // Order-insensitive: the server sorts excluded ids and de-duplicates filters,
  // so a positional compare would report "unsaved changes" after a save.
  const left = [...a.excluded_alert_ids].sort().join('\n');
  const right = [...b.excluded_alert_ids].sort().join('\n');
  const leftFilters = [...a.filters].sort().join('\n');
  const rightFilters = [...b.filters].sort().join('\n');
  return left === right && leftFilters === rightFilters;
}
