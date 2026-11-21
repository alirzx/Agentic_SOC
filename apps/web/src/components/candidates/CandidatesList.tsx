'use client';

import { useState } from 'react';
import { CandidateCardComponent } from './CandidateCard';
import {
  CandidateFilterBar,
  DEFAULT_CANDIDATE_FILTERS,
  describeFilters,
  type CandidateFilters,
} from './CandidateFilterBar';
import { CandidateInspectModal } from './CandidateInspectModal';
import { useCaseCandidates, type AlertScope } from '@/hooks/useCaseCandidates';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import toast from 'react-hot-toast';

interface CandidatesListProps {
  /**
   * Promote a candidate into a case. Returns ``false`` (or rejects) when the
   * promotion failed, so the inspect modal can stay open instead of closing on
   * an error and losing the analyst's context.
   */
  onCreateCase?: (
    candidateKey: string,
    theme: string,
    scope: AlertScope
  ) => Promise<{ ok: boolean; message?: string }> | void;
}

const EMPTY_SCOPE: AlertScope = { excluded_alert_ids: [], filters: [] };

export function CandidatesList({ onCreateCase }: CandidatesListProps) {
  const [filters, setFilters] = useState<CandidateFilters>(DEFAULT_CANDIDATE_FILTERS);

  const [selectedCandidateKey, setSelectedCandidateKey] = useState<string | null>(
    null
  );

  const { candidates, loading, error, mutate } = useCaseCandidates(filters);

  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const handleCreateCase = async (candidateKey: string, scope: AlertScope) => {
    if (creating) return;
    const theme = candidates.find((c) => c.candidate_key === candidateKey)
      ?.campaign_theme;

    if (!onCreateCase) {
      setCreateError('Case creation is not available on this screen');
      return;
    }

    setCreating(true);
    setCreateError(null);
    try {
      const result = await onCreateCase(candidateKey, theme || 'Unknown Campaign', scope);
      if (result && result.ok === false) {
        // Keep the modal open: the analyst needs the candidate context to
        // decide what to do after a failed promotion.
        setCreateError(result.message ?? 'Could not create the case');
        return;
      }
      // The promoted alerts are now case members, so this candidate is gone.
      await mutate();
      setSelectedCandidateKey(null);
    } finally {
      setCreating(false);
    }
  };

  const handleDismiss = async (candidateKey: string) => {
    try {
      const res = await fetch(
        `/api/v1/cases/candidates/${encodeURIComponent(candidateKey)}/dismiss`,
        { method: 'POST' }
      );
      if (res.ok) {
        toast.success('Candidate dismissed for 24 hours');
        // The card must disappear immediately; otherwise the button looks dead
        // until a focus revalidation.
        await mutate();
      }
    } catch (err) {
      toast.error('Failed to dismiss candidate');
    }
  };

  // Check if any non-default filters are active
  const hasActiveFilters = Object.keys(filters).some(
    (k) =>
      (k !== 'limit' && k !== 'offset') &&
      (filters as any)[k] !== (DEFAULT_CANDIDATE_FILTERS as any)[k]
  );

  return (
    <div className="space-y-4">
      {/* Filters */}
      <CandidateFilterBar
        filters={filters}
        onFiltersChange={setFilters}
        resultCount={candidates.length}
      />

      {/* Results */}
      {loading ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              className="bg-dark-60 border border-[#374151]/60 rounded-lg p-4 animate-pulse"
            >
              <div className="h-6 bg-dark-40 rounded mb-3 w-48" />
              <div className="h-2 bg-dark-40 rounded mb-3" />
              <div className="flex gap-2 mb-3">
                {[...Array(3)].map((_, j) => (
                  <div key={j} className="h-6 bg-dark-40 rounded w-20" />
                ))}
              </div>
              <div className="h-12 bg-dark-40 rounded" />
            </div>
          ))}
        </div>
      ) : error ? (
        <div className="flex h-full items-center justify-center px-8 text-center">
          <div>
            <p className="text-sm text-gray-400">Could not load candidates.</p>
            <p className="mt-1 text-xs text-gray-500">
              The candidates list is built by the correlation service. Check that:
            </p>
            <ul className="mt-2 text-xs text-gray-500 space-y-1">
              <li>• The correlation service is running</li>
              <li>• The worker has processed recent alerts (check logs)</li>
              <li>• Alerts meet the correlation threshold (θ ≥ 3)</li>
            </ul>
          </div>
        </div>
      ) : candidates.length === 0 ? (
        <div className="flex h-full items-center justify-center px-8 text-center">
          <div>
            {hasActiveFilters ? (
              <>
                <p className="text-sm text-gray-400">No candidates match these filters.</p>
                <p className="mt-1 text-xs text-gray-500">
                  Active filters — {describeFilters(filters).join(' · ')}. Widen the time window, lower the link score, or clear the search.
                </p>
                <button
                  type="button"
                  onClick={() => setFilters({ ...DEFAULT_CANDIDATE_FILTERS })}
                  className="mt-3 rounded-lg border border-orange-500/40 bg-orange-500/10 px-3 py-2 text-xs font-medium text-orange-300 transition-colors hover:bg-orange-500/20"
                >
                  Clear all filters
                </button>
              </>
            ) : (
              <>
                <p className="text-sm text-gray-400">No correlation candidates yet.</p>
                <p className="mt-1 text-xs text-gray-500">
                  The candidates list is built from correlated observations. Check that:
                </p>
                <ul className="mt-2 text-xs text-gray-500 space-y-1">
                  <li>• The correlation service is running</li>
                  <li>• The worker has processed these alerts (check logs)</li>
                  <li>• Alerts meet the correlation threshold (θ ≥ 3)</li>
                </ul>
              </>
            )}
          </div>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {candidates.map((candidate) => (
              <CandidateCardComponent
                key={candidate.candidate_key}
                candidate={candidate}
                onInspect={(key) => setSelectedCandidateKey(key)}
                // The card is a shortcut: promote everything, no exclusions yet.
                onCreateCase={(key) => handleCreateCase(key, EMPTY_SCOPE)}
                onDismiss={handleDismiss}
              />
            ))}
          </div>
        </>
      )}

      {/* Inspect Modal — owns its own scope-aware detail fetch */}
      <CandidateInspectModal
        candidateKey={selectedCandidateKey}
        onClose={() => {
          setSelectedCandidateKey(null);
          setCreateError(null);
        }}
        onCreateCase={handleCreateCase}
        creatingCase={creating}
        createError={createError}
      />
    </div>
  );
}
