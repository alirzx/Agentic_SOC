/**
 * Tier-2 Adaptive Investigation UI helpers.
 *
 * Supports the eight-stage adaptive runbook while remaining backward-compatible
 * with the legacy five-step IP-pivot action names.
 */

export type Tier2StepStatus =
  | 'pending'
  | 'executed'
  | 'recorded'
  | 'completed'
  | 'partial'
  | 'skipped'
  | 'failed'
  | 'not_available'
  | 'no_results';

export type Tier2StepView = {
  action_name: string;
  label: string;
  status: string;
  summary: string;
  detail?: string | null;
  has_result?: boolean;
};

export type Tier2EntityView = {
  entity_type: string;
  normalized_value: string;
  original_value?: string;
  source_field?: string;
  source_location?: string;
  confidence?: number;
  is_observed?: boolean;
  is_inferred?: boolean;
};

export type Tier2AdaptiveMeta = {
  profiles?: string[];
  case_decision?: {
    action?: string;
    reason?: string;
    correlation_score?: number | null;
  };
  report?: {
    final_assessment?: string;
    confidence?: number;
    findings?: Array<{ title?: string; assessment?: string }>;
    limitations?: string[];
    related_alerts?: Array<{ id?: string; title?: string }>;
    investigation_steps?: Array<{
      step_name?: string;
      status?: string;
      summary?: string;
      profile?: string;
    }>;
    entity_provenance?: Tier2EntityView[];
    extracted_entities?: Tier2EntityView[];
    correlation_results?: Array<{
      candidate_alert_id?: string;
      total_score?: number;
      decision?: string;
      correlation_reasons?: Array<{ type?: string; value?: string; weight?: number }>;
    }>;
    timeline?: Array<{ ts?: string; kind?: string; label?: string }>;
  };
  entity_counts?: Record<string, number>;
  correlation?: {
    results?: Array<{
      candidate_alert_id?: string;
      total_score?: number;
      decision?: string;
    }>;
  };
};

/** Canonical eight-stage adaptive catalog. */
export const TIER2_ADAPTIVE_PLACEHOLDER_STEPS: Tier2StepView[] = [
  { action_name: 'tier2_alert_context', label: '1. Alert Context', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_entity_extraction', label: '2. Entity Extraction', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_domain_classification', label: '3. Domain Classification', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_related_discovery', label: '4. Related Alert Discovery', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_correlation_analysis', label: '5. Correlation Analysis', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_case_management', label: '6. Case Management', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_investigation', label: '7. Investigation', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_final_report', label: '8. Final Report', status: 'pending', summary: 'Waiting for first run…' },
];

/** Legacy five-step catalog (backward compatible). */
export const TIER2_LEGACY_PLACEHOLDER_STEPS: Tier2StepView[] = [
  { action_name: 'tier2_extract_ips', label: '1. Extract src_ip / dest_ip', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_find_related', label: '2. Find related alerts (24h / dest_ip)', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_aggregate_case', label: '3. Aggregate into one Case', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_investigate', label: '4. Investigate on Case', status: 'pending', summary: 'Waiting for first run…' },
  { action_name: 'tier2_case_report', label: '5. Case report scope', status: 'pending', summary: 'Waiting for first run…' },
];

const LEGACY_TO_ADAPTIVE: Record<string, string> = {
  tier2_extract_ips: 'tier2_entity_extraction',
  tier2_find_related: 'tier2_related_discovery',
  tier2_aggregate_case: 'tier2_case_management',
  tier2_investigate: 'tier2_investigation',
  tier2_case_report: 'tier2_final_report',
};

export function isAdaptiveStepCatalog(steps: Tier2StepView[]): boolean {
  return steps.some((s) => s.action_name === 'tier2_alert_context' || s.action_name === 'tier2_entity_extraction');
}

export function resolveTier2Placeholders(steps?: Tier2StepView[] | null): Tier2StepView[] {
  if (steps && steps.length > 0) {
    return steps;
  }
  return TIER2_ADAPTIVE_PLACEHOLDER_STEPS;
}

export function tier2StatusTone(status: string): string {
  if (status === 'executed' || status === 'recorded' || status === 'completed') {
    return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
  }
  if (status === 'partial' || status === 'no_results') {
    return 'border-sky-500/30 bg-sky-500/10 text-sky-200';
  }
  if (status === 'not_available' || status === 'skipped') {
    return 'border-amber-500/30 bg-amber-500/10 text-amber-200';
  }
  if (status === 'failed') {
    return 'border-red-500/30 bg-red-500/10 text-red-300';
  }
  return 'border-slate-700/50 bg-slate-900/40 text-slate-400';
}

export function tier2StatusLabel(status: string): string {
  switch (status) {
    case 'executed':
    case 'recorded':
    case 'completed':
      return 'Completed';
    case 'partial':
      return 'Partial';
    case 'no_results':
      return 'No Results';
    case 'not_available':
      return 'Not Available';
    case 'skipped':
      return 'Skipped';
    case 'failed':
      return 'Failed';
    default:
      return 'Pending';
  }
}

export function groupEntitiesByType(entities: Tier2EntityView[]): Record<string, Tier2EntityView[]> {
  const out: Record<string, Tier2EntityView[]> = {};
  for (const ent of entities) {
    const key = ent.entity_type || 'unknown';
    if (!out[key]) out[key] = [];
    out[key].push(ent);
  }
  return out;
}

export function adaptLegacyStepsIfNeeded(steps: Tier2StepView[]): Tier2StepView[] {
  if (isAdaptiveStepCatalog(steps)) {
    return steps;
  }
  // Keep legacy steps as-is for API compatibility when adaptive flag is off.
  return steps.map((step) => ({
    ...step,
    // Expose alias for tooling that expects adaptive names.
    action_name: step.action_name,
    label: step.label,
  }));
}

export function legacyAliasFor(actionName: string): string | undefined {
  return Object.entries(LEGACY_TO_ADAPTIVE).find(([, v]) => v === actionName)?.[0];
}

export function extractEntitiesFromAdaptive(meta?: Tier2AdaptiveMeta | null): Tier2EntityView[] {
  if (!meta?.report) return [];
  const provenance = meta.report.entity_provenance;
  if (provenance && provenance.length > 0) return provenance;
  return meta.report.extracted_entities || [];
}

export function isMultiAlertInvestigation(meta?: Tier2AdaptiveMeta | null): boolean {
  const related = meta?.report?.related_alerts || [];
  return related.length > 1;
}

export function formatCaseDecision(meta?: Tier2AdaptiveMeta | null): string {
  const decision = meta?.case_decision;
  if (!decision?.action) return 'No case decision yet';
  const score =
    decision.correlation_score != null ? ` (score ${decision.correlation_score})` : '';
  return `${decision.action}${score}: ${decision.reason || ''}`.trim();
}

export function correlationExplanations(meta?: Tier2AdaptiveMeta | null): string[] {
  const results = meta?.report?.correlation_results || meta?.correlation?.results || [];
  return results.slice(0, 8).map((r) => {
    const reasons =
      'correlation_reasons' in r && Array.isArray(r.correlation_reasons)
        ? r.correlation_reasons.map((x) => x.type || '').filter(Boolean).join(', ')
        : r.decision || '';
    return `${r.candidate_alert_id || '?'} · score=${r.total_score ?? '—'} · ${reasons}`;
  });
}
