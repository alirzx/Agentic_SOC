import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { KnowledgeCoverageView, TkgHistoryView } from './TkgHistoryView';

describe('historical TKG presentation', () => {
  it('distinguishes an accepted pending receipt from a materialized delivery', () => {
    const html = renderToStaticMarkup(<KnowledgeCoverageView coverage={{
      alerts: 3, eligible_alerts: 3, configured_bindings: 1, enabled_bindings: 1, covered_bindings: 1,
      accepted_receipts: 3, recoverable_receipts: 1,
      delivery_counts: { pending_materialization: 2, bound: 1 }, last_updated: null,
    }} />);
    expect(html).toMatch(/Pending materialization<\/dt><dd[^>]*>2/);
    expect(html).toMatch(/Materialized<\/dt><dd[^>]*>1/);
    expect(html).toContain('Recoverable receipt failure');
  });

  it('renders only the selected run and supports older runs without data', () => {
    const html = renderToStaticMarkup(<TkgHistoryView run={{
      run_id: 'run-older', run_status: 'completed', started_at: '2026-11-25T00:00:00Z', history: null,
    }} />);
    expect(html).toContain('This run has no saved historical result');
    expect(html).not.toContain('Observed fact');
  });

  it('separates recorded tool outcomes, conflicting facts and unverified Search results', () => {
    const html = renderToStaticMarkup(<TkgHistoryView run={{
      run_id: 'run-selected', run_status: 'completed', started_at: '2026-11-25T00:00:00Z', history: {
        profile: 'standard', historical_status: 'partial', stop_reason: 'tool_budget', coverage: {}, limits: {},
        tool_calls: 1, tool_requests: 1, llm_calls: 2, provider_calls: 2, reserved_tokens_charged: 400,
        estimated_cost_usd: 0.001, truncated: true, entities: [], claims: [],
        tools: [{ tool: 'tkg.get_timeline', status: 'partial', seed_id: null, duration_ms: 32, fact_count: 1, truncated: true }],
        facts: [{ id: 'fact-one', kb_id: 'base-one', contested: true, stale: false, inferred: false,
          valid_from: '2026-10-01', recorded_at: '2026-11-10', sources: [{ document_id: 'doc-one', chunk_id: 'chunk-one' }] }],
        candidates: [{ kb_id: 'base-one', document_id: 'doc-candidate', chunk_id: 'chunk-candidate' }],
      },
    }} />);
    for (const value of ['tool budget', '32 ms', 'Conflicting evidence', 'Unverified search candidates', 'Valid from',
      'Recorded time', '2026-10-01', '2026-11-10', 'doc-one']) expect(html).toContain(value);
  });
});
