import { render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const boardMock = vi.fn();

vi.mock('@/lib/api', () => ({
  socFunnelApi: {
    board: (...args: unknown[]) => boardMock(...args),
    backfill: vi.fn(),
    dedupeExact: vi.fn(),
    reenrichSplunk: vi.fn(),
  },
}));

import { SocFunnelBoardView } from './SocFunnelBoardView';

/** Fresh SWR cache per test — otherwise one test's cached board leaks into the next. */
function renderBoard() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <SocFunnelBoardView />
    </SWRConfig>,
  );
}

const ALERT_ID = '11111111-1111-4111-8111-111111111111';

const payload = {
  window_hours: 24,
  alerts_total: 9,
  stages: [
    { id: 'ingested', label: 'Ingested', count: 4, open_tasks: 0 },
    { id: 'triaged', label: 'Triaged', count: 5, open_tasks: 2 },
  ],
  samples_by_stage: {
    ingested: [],
    triaged: [
      {
        id: ALERT_ID,
        title: 'Impossible travel from two countries',
        severity: 'medium',
        status: 'new',
        disposition: null,
        funnel_stage: 'triaged',
        confidence: 61,
        case_id: null,
        created_at: '2026-10-29T10:00:00Z',
        same_title_count: 1,
        open_tasks: [
          { task_type: 'manual_review', title: 'Verify Alert Triage', status: 'pending' },
          { task_type: 'approval_gate', title: 'Approve Action: isolate_host', status: 'pending' },
        ],
      },
    ],
  },
  ratios: { suppression_rate: 0.1, ready_for_jira_rate: 0.2 },
};

describe('SocFunnelBoardView', () => {
  beforeEach(() => {
    boardMock.mockReset();
    boardMock.mockResolvedValue(payload);
  });

  it('says how many alerts in a stage are waiting on an analyst', async () => {
    renderBoard();

    await waitFor(() => expect(screen.getByText('2 waiting on an analyst')).toBeInTheDocument());
  });

  it('shows the task behind a stuck alert and links to its Runbook', async () => {
    renderBoard();

    await waitFor(() => expect(screen.getByText('needs review')).toBeInTheDocument());
    expect(screen.getByText('approval')).toBeInTheDocument();

    const runbookLink = screen.getByRole('link', { name: 'Runbook →' });
    expect(runbookLink).toHaveAttribute('href', `/runbook/alert/${ALERT_ID}`);

    // The card title still opens the alert itself.
    expect(
      screen.getByRole('link', { name: /Impossible travel from two countries/ }),
    ).toHaveAttribute('href', `/alerts/${ALERT_ID}`);
  });

  it('offers a way into the analyst queue from the header', async () => {
    renderBoard();

    const link = await screen.findByRole('link', { name: /open runbook/i });
    expect(link).toHaveAttribute('href', '/runbook?tab=action-plan');
  });
});
