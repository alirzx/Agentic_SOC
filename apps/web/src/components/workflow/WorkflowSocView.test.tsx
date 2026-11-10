import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it } from 'vitest';

import { WorkflowSocView } from './WorkflowSocView';

/**
 * The lifecycle page is a diagram. Its only obligation to the rest of the app is
 * that the stages which own a real queue point at that queue — so these tests
 * pin the two destinations and the ?stage= round trip the Runbook uses.
 */
describe('WorkflowSocView', () => {
  beforeEach(() => {
    // Nothing to stub: the view is presentational.
  });

  it('links the detect stage to the detect & fuse activity', async () => {
    render(<WorkflowSocView initialStage="detect" />);

    const link = await screen.findByRole('link', { name: /detect & fuse activity/i });
    expect(link).toHaveAttribute('href', '/runbook?tab=detect');
  });

  it('links the copilot stage to the manual-review queue', async () => {
    render(<WorkflowSocView initialStage="decide" />);

    const link = await screen.findByRole('link', { name: /manual-review queue/i });
    expect(link).toHaveAttribute('href', '/runbook?tab=action-plan&task_type=manual_review');
  });

  it('links the response stage to the approval gates', async () => {
    render(<WorkflowSocView initialStage="respond" />);

    const link = await screen.findByRole('link', { name: /approval gates/i });
    expect(link).toHaveAttribute('href', '/runbook?tab=action-plan&task_type=approval_gate');
  });

  it('opens the requested stage instead of the first one', () => {
    render(<WorkflowSocView initialStage="jira" />);

    // The header names the active stage, so this is the observable contract.
    expect(screen.getAllByText('Jira Ticket').length).toBeGreaterThan(0);
    expect(screen.getByText(/Active stage:/)).toHaveTextContent('Jira Ticket');
  });

  it('shows a stage link after clicking its card', async () => {
    render(<WorkflowSocView />);

    const cards = await screen.findAllByRole('button', { name: /approved response/i });
    await userEvent.click(cards[0]);

    await waitFor(() =>
      expect(screen.getByRole('link', { name: /approval gates/i })).toBeInTheDocument(),
    );
  });
});
