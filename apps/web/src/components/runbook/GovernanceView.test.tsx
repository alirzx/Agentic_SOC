import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const requestMock = vi.fn();

vi.mock('@/lib/api', () => ({
  request: (...args: unknown[]) => requestMock(...args),
}));

import { GovernanceView } from './GovernanceView';

const entry = (overrides: Record<string, unknown>) => ({
  name: 'close_alert',
  label: 'Close alert',
  category: 'case',
  blast_radius: 'low',
  always_requires_approval: false,
  dry_run_default: true,
  thresholds: { auto: 0.9, review: 0.7, escalation: 0.95 },
  audit: { record_ledger: true, audit_log: true, include_input: true, include_output: true },
  data_safety: { allowed_fields: ['id'], max_payload_bytes: 4096, allow_pii: false },
  failure: { max_attempts: 3, backoff_seconds: 2, timeout_seconds: 10, on_failure: 'abort' },
  cost: { max_usd_per_run: null, max_tokens: null, max_wall_ms: null },
  ...overrides,
});

describe('GovernanceView', () => {
  beforeEach(() => {
    requestMock.mockReset();
  });

  it('searches the catalog by label, slug, category and blast radius', async () => {
    requestMock.mockResolvedValue([
      entry({}),
      entry({
        name: 'isolate_host',
        label: 'Isolate host from network',
        category: 'containment',
        blast_radius: 'high',
      }),
    ]);

    render(<GovernanceView />);

    await waitFor(() =>
      expect(screen.getByText('Isolate host from network')).toBeInTheDocument(),
    );

    const search = screen.getByLabelText(/search governed actions/i);

    // By label.
    await userEvent.type(search, 'isolate');
    await waitFor(() => expect(screen.queryByText('Close alert')).not.toBeInTheDocument());
    expect(screen.getByText('1 of 2 actions')).toBeInTheDocument();

    // By slug.
    await userEvent.clear(search);
    await userEvent.type(search, 'close_alert');
    await waitFor(() =>
      expect(screen.queryByText('Isolate host from network')).not.toBeInTheDocument(),
    );

    // By blast radius.
    await userEvent.clear(search);
    await userEvent.type(search, 'high');
    await waitFor(() =>
      expect(screen.getByText('Isolate host from network')).toBeInTheDocument(),
    );
  });

  it('keeps the category filter and search composed, and says when nothing matches', async () => {
    requestMock.mockResolvedValue([entry({})]);

    render(<GovernanceView />);

    await waitFor(() => expect(screen.getByText('Close alert')).toBeInTheDocument());

    await userEvent.type(screen.getByLabelText(/search governed actions/i), 'nothing-here');

    await waitFor(() =>
      expect(screen.getByText(/No action matches/)).toBeInTheDocument(),
    );
    expect(screen.getByRole('button', { name: /clear search/i })).toBeInTheDocument();
  });
});
