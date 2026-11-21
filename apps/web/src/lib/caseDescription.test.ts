import { describe, expect, it } from 'vitest';

import { summariseCaseDescription } from './caseDescription';

const LEGACY = [
  'Created by the graph correlation engine (normalizer v2.0.0, θ=3).',
  '',
  'Correlation score: 5 (L1 entity overlap + L2 context + L3 graph path)',
  'Observations merged: 7',
  'Roles: general:intrusion, privilege_escalation:msi',
  'Primary entity: host:quadra',
  '',
  'Observations:',
  '- 2026-11-12T14:48:12+03:30 [general:intrusion] ESCU - Windows .Key File Creation in Root Directory - Rule (1 alert(s), first_event)',
  '- 2026-11-12T14:48:32+03:30 [general:intrusion] ESCU - Windows CrowdStrike Agent Registry Key Removal - Rule (1 alert(s), first_event)',
  '- 2026-11-12T14:49:32+03:30 [privilege_escalation:msi] ESCU - Windows Potato Privilege Escalation Tool Execution - Rule (1 alert(s), first_event)',
].join('\n');

const CURRENT = [
  'Graph correlation grouped 7 observation(s) from 7 alert(s) on host:quadra into one campaign, 2026-11-12 14:48 → 14:52.',
  '',
  'Correlation score: 5 (L1 entity overlap + L2 context + L3 graph path)',
  'Observations merged: 7',
  'Roles: general:intrusion, privilege_escalation:msi',
  'Primary entity: host:quadra',
  '',
  'Rules (2 distinct):',
  '- ESCU - Windows .Key File Creation in Root Directory - Rule',
  '- ESCU - Windows Potato Privilege Escalation Tool Execution - Rule (×2)',
  '',
  'Created by the graph correlation engine (normalizer v2.0.0, θ=3). Per-observation detail, alert ids and timings live in the Observations tab.',
].join('\n');

describe('summariseCaseDescription', () => {
  it('reconstructs a count-free headline from the legacy observation dump', () => {
    const summary = summariseCaseDescription(LEGACY);

    expect(summary.headline).toBe('Graph-correlated campaign on host:quadra.');
    // The 8000-character observation list is counted, never rendered.
    expect(summary.observationCount).toBe(3);
    expect(summary.details).not.toContain('[general:intrusion]');
    expect(summary.details).toContain('Created by the graph correlation engine');
    expect(summary.isEngine).toBe(true);
    // No engine number survives: the header gets its counts from the alerts
    // store, and the campaign window is unknown in the legacy shape.
    expect(summary.facts).toEqual([]);
    expect(summary.headline).not.toMatch(/\d+/);
  });

  it('keeps the campaign window but drops the engine counts from the headline', () => {
    const summary = summariseCaseDescription(CURRENT);

    expect(summary.headline).toBe(
      'Graph-correlated campaign on host:quadra, 2026-11-12 14:48 → 14:52.',
    );
    expect(summary.headline).not.toMatch(/\d+ observation/);
    expect(summary.headline).not.toMatch(/\d+ alert/);
    expect(summary.facts).toEqual(['2026-11-12 14:48 → 14:52']);
    expect(summary.observationCount).toBe(0);
    // The engine's rule roll-up is dropped: it counted rule occurrences per
    // observation, which is not the rules the case's alerts carry.
    expect(summary.details).not.toContain('Rules (2 distinct)');
    expect(summary.details).not.toContain('×2');
    // No frozen counts anywhere: not in the headline, not in the facts, not in
    // the details pane. The header counts alerts and rules live.
    expect(summary.details).not.toContain('Observations merged');
    expect(summary.details).not.toContain('7 observation');
  });

  it('passes an analyst-written description through as the headline', () => {
    const summary = summariseCaseDescription(
      'Analyst note: confirmed lateral movement from FIN-WS-04 to the DC.\nScope limited to two hosts.',
    );

    expect(summary.headline).toBe(
      'Analyst note: confirmed lateral movement from FIN-WS-04 to the DC.',
    );
    expect(summary.details).toBe('Scope limited to two hosts.');
    expect(summary.facts).toEqual([]);
    expect(summary.isEngine).toBe(false);
  });

  it('returns nothing for an empty or missing description', () => {
    expect(summariseCaseDescription(undefined).headline).toBe('');
    expect(summariseCaseDescription('   ').headline).toBe('');
  });

  it('clips a single run-on line instead of dumping it into the header', () => {
    const summary = summariseCaseDescription(`Graph correlation ${'x'.repeat(2000)}`);
    expect(summary.headline.length).toBeLessThanOrEqual(301);
    expect(summary.headline.endsWith('…')).toBe(true);
  });
});
