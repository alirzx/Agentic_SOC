import { describe, expect, it } from 'vitest';
import {
  TIER2_ADAPTIVE_PLACEHOLDER_STEPS,
  TIER2_LEGACY_PLACEHOLDER_STEPS,
  adaptLegacyStepsIfNeeded,
  correlationExplanations,
  extractEntitiesFromAdaptive,
  formatCaseDecision,
  groupEntitiesByType,
  isAdaptiveStepCatalog,
  isMultiAlertInvestigation,
  resolveTier2Placeholders,
  tier2StatusLabel,
  type Tier2AdaptiveMeta,
  type Tier2StepView,
} from './tier2-adaptive';

describe('tier2-adaptive UI helpers', () => {
  it('exposes all eight adaptive stages', () => {
    expect(TIER2_ADAPTIVE_PLACEHOLDER_STEPS).toHaveLength(8);
    expect(TIER2_ADAPTIVE_PLACEHOLDER_STEPS.map((s) => s.action_name)).toEqual([
      'tier2_alert_context',
      'tier2_entity_extraction',
      'tier2_domain_classification',
      'tier2_related_discovery',
      'tier2_correlation_analysis',
      'tier2_case_management',
      'tier2_investigation',
      'tier2_final_report',
    ]);
  });

  it('groups entities by type with provenance fields', () => {
    const grouped = groupEntitiesByType([
      {
        entity_type: 'hostname',
        normalized_value: 'cao01vw013.cao.ir',
        source_field: 'Computer',
        confidence: 0.95,
      },
      {
        entity_type: 'hostname',
        normalized_value: 'sh2',
        source_field: 'extracted_host',
        confidence: 0.9,
      },
      {
        entity_type: 'user_sid',
        normalized_value: 'S-1-5-21-1-2-3-4',
        source_field: 'user_id',
      },
    ]);
    expect(grouped.hostname).toHaveLength(2);
    expect(grouped.user_sid).toHaveLength(1);
  });

  it('formats profiles / case decision / correlation explanations', () => {
    const meta: Tier2AdaptiveMeta = {
      profiles: ['endpoint', 'identity'],
      case_decision: {
        action: 'create',
        reason: 'high_severity_standalone_sufficient_evidence',
        correlation_score: null,
      },
      report: {
        correlation_results: [
          {
            candidate_alert_id: 'a2',
            total_score: 72,
            decision: 'eligible',
            correlation_reasons: [
              { type: 'exact_hostname', value: 'h1' },
              { type: 'exact_user_sid', value: 'S-1-5-21-1' },
            ],
          },
        ],
        related_alerts: [{ id: 'a1' }, { id: 'a2' }],
        entity_provenance: [
          { entity_type: 'hostname', normalized_value: 'h1', source_field: 'Computer' },
        ],
        investigation_steps: [
          { step_name: 'inspect_host', status: 'completed', summary: 'ok', profile: 'endpoint' },
          { step_name: 'query_edr_telemetry', status: 'not_available', summary: 'n/a', profile: 'endpoint' },
        ],
      },
    };
    expect(formatCaseDecision(meta)).toContain('create');
    expect(correlationExplanations(meta)[0]).toContain('exact_hostname');
    expect(isMultiAlertInvestigation(meta)).toBe(true);
    expect(extractEntitiesFromAdaptive(meta)).toHaveLength(1);
  });

  it('supports single-alert and empty evidence', () => {
    expect(isMultiAlertInvestigation({ report: { related_alerts: [{ id: 'only' }] } })).toBe(false);
    expect(extractEntitiesFromAdaptive(null)).toEqual([]);
    expect(resolveTier2Placeholders(null)).toHaveLength(8);
    expect(tier2StatusLabel('not_available')).toBe('Not Available');
    expect(tier2StatusLabel('skipped')).toBe('Skipped');
  });

  it('keeps legacy five-step API compatibility', () => {
    expect(TIER2_LEGACY_PLACEHOLDER_STEPS).toHaveLength(5);
    const legacy = adaptLegacyStepsIfNeeded(TIER2_LEGACY_PLACEHOLDER_STEPS);
    expect(isAdaptiveStepCatalog(legacy)).toBe(false);
    expect(legacy[0].action_name).toBe('tier2_extract_ips');
    const adaptive: Tier2StepView[] = TIER2_ADAPTIVE_PLACEHOLDER_STEPS;
    expect(isAdaptiveStepCatalog(adaptive)).toBe(true);
  });

  it('labels investigation statuses without treating missing IP as error', () => {
    expect(tier2StatusLabel('not_available')).not.toBe('Failed');
    expect(tier2StatusLabel('no_results')).toBe('No Results');
    expect(tier2StatusLabel('partial')).toBe('Partial');
    expect(tier2StatusLabel('completed')).toBe('Completed');
  });
});
