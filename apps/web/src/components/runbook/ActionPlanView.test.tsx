import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const submitOverrideMock = vi.fn();
const ticketMock = vi.fn();

vi.mock('@/lib/api', () => ({
  feedbackApi: {
    submitOverride: (...args: unknown[]) => submitOverrideMock(...args),
  },
  realtimeApi: {
    ticket: (...args: unknown[]) => ticketMock(...args),
  },
}));

import { ActionPlanView } from './ActionPlanView';

const ALERT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

const gateTask = {
  id: '11111111-1111-4111-8111-111111111111',
  task_type: 'approval_gate',
  title: 'Approve Action: isolate_host',
  description: 'AI recommends isolate_host but autonomy is capped at L2.',
  alert_id: ALERT_ID,
  case_id: null,
  assigned_to: null,
  status: 'pending',
  due_at: null,
  completed_at: null,
  resolution: null,
  feedback_to_llm: null,
  created_by: 'system',
  created_at: '2026-10-29T10:00:00Z',
};

describe('ActionPlanView', () => {
  beforeEach(() => {
    submitOverrideMock.mockReset();
    ticketMock.mockReset();
    // Realtime is optional; reject so the component stays on the HTTP path.
    ticketMock.mockRejectedValue(new Error('no realtime in tests'));
  });

  it('scopes the task query to the selected subject', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => [] });
    vi.stubGlobal('fetch', fetchMock);

    render(<ActionPlanView subject_type="alert" subject_id={ALERT_ID} />);

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(fetchMock.mock.calls[0][0]).toBe(
      `/api/v1/runbook/tasks?alert_id=${ALERT_ID}`,
    );
  });

  it('approves a gate task without requiring model feedback', async () => {
    const fetchMock = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: async () => ({ ...gateTask, status: 'completed', resolution: 'Approved by analyst' }),
        });
      }
      return Promise.resolve({ ok: true, json: async () => [gateTask] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<ActionPlanView />);

    await waitFor(() => expect(screen.getByText('Approve Action: isolate_host')).toBeInTheDocument());

    await userEvent.click(screen.getByRole('button', { name: /review/i }));
    await userEvent.click(screen.getByRole('button', { name: /approve action/i }));

    await waitFor(() => {
      const post = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST');
      expect(post?.[0]).toBe(`/api/v1/runbook/tasks/${gateTask.id}/complete`);
      const body = JSON.parse(String(post?.[1]?.body));
      expect(body.feedback_to_llm).toBeNull();
      expect(body.resolution).toBe('Approved by analyst');
    });

    // A governance decision must not touch the model-feedback path.
    expect(submitOverrideMock).not.toHaveBeenCalled();
  });

  it('sends an explicit decision when releasing a playbook gate', async () => {
    const playbookGate = {
      ...gateTask,
      id: '33333333-3333-4333-8333-333333333333',
      title: 'Approve Playbook: containment → Isolate host',
      playbook_run_id: '44444444-4444-4444-8444-444444444444',
      resume_applied: null,
    };
    const fetchMock = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: async () => ({ ...playbookGate, status: 'completed', resume_applied: true }),
        });
      }
      return Promise.resolve({ ok: true, json: async () => [playbookGate] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<ActionPlanView />);

    await waitFor(() => expect(screen.getByText(playbookGate.title)).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /review/i }));

    // The label says what the button will actually do to the run.
    await userEvent.click(screen.getByRole('button', { name: /approve & resume run/i }));

    await waitFor(() => {
      const post = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST');
      const body = JSON.parse(String(post?.[1]?.body));
      expect(body.decision).toBe('approve');
    });
  });

  it('shows when an approval did not actually resume the run', async () => {
    const completed = {
      ...gateTask,
      status: 'completed',
      completed_at: '2026-10-29T11:00:00Z',
      playbook_run_id: '44444444-4444-4444-8444-444444444444',
      resume_applied: false,
    };
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => [completed] });
    vi.stubGlobal('fetch', fetchMock);

    render(<ActionPlanView />);

    await waitFor(() => expect(screen.getByText(/completed \(1\)/i)).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /completed \(1\)/i }));

    // A recorded decision that moved nothing is the interesting case, and it
    // must not read as a success.
    await waitFor(() =>
      expect(screen.getByText(/run not resumed/i)).toBeInTheDocument(),
    );
  });

  it('records the analyst verdict for a manual_review task', async () => {
    const reviewTask = {
      ...gateTask,
      id: '22222222-2222-4222-8222-222222222222',
      task_type: 'manual_review',
      title: 'Verify Alert Triage (Low AI Confidence)',
    };
    submitOverrideMock.mockResolvedValue({});
    const fetchMock = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: async () => ({ ...reviewTask, status: 'completed' }),
        });
      }
      return Promise.resolve({ ok: true, json: async () => [reviewTask] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<ActionPlanView />);

    await waitFor(() => expect(screen.getByText(reviewTask.title)).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /review/i }));
    await userEvent.click(screen.getByRole('button', { name: /mark false positive/i }));

    await waitFor(() => {
      expect(submitOverrideMock).toHaveBeenCalledWith(
        expect.objectContaining({
          alert_id: ALERT_ID,
          original_verdict: 'needs_review',
          corrected_verdict: 'false_positive',
        }),
      );
    });
  });

  it('scopes the queue to a task type and says so', async () => {
    // The Workflow SOC "Verdict & Copilot" stage links here with a type filter.
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => [] });
    vi.stubGlobal('fetch', fetchMock);

    render(<ActionPlanView task_type="approval_gate" />);

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/runbook/tasks?task_type=approval_gate');
    // A filtered empty queue must not read as "everything is clear".
    await waitFor(() =>
      expect(screen.getByText('No approval gate tasks waiting')).toBeInTheDocument(),
    );
    expect(screen.getByText(/Other task types may still be waiting/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /show all/i }));
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([url]) => url === '/api/v1/runbook/tasks')).toBe(true),
    );
  });

  it('shows how many completions actually moved an outcome prior', async () => {
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url === '/api/v1/runbook/stats') {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            tasks_total: 9,
            tasks_pending: 4,
            tasks_completed: 5,
            completions_with_feedback: 5,
            priors_updated: 3,
            feedback_unapplied: 2,
          }),
        });
      }
      return Promise.resolve({ ok: true, json: async () => [gateTask] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<ActionPlanView />);

    await waitFor(() => expect(screen.getByText('3/5')).toBeInTheDocument());
    expect(screen.getByText(/updated an outcome prior/)).toBeInTheDocument();
    // The unapplied remainder must be visible, not rounded away.
    expect(screen.getByText('2 not applied')).toBeInTheDocument();
  });

  it('renders a failed completion inline instead of alerting', async () => {
    const fetchMock = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        return Promise.resolve({ ok: false, status: 500, json: async () => ({}) });
      }
      return Promise.resolve({ ok: true, json: async () => [gateTask] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<ActionPlanView />);

    await waitFor(() => expect(screen.getByText('Approve Action: isolate_host')).toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: /review/i }));
    await userEvent.click(screen.getByRole('button', { name: /approve action/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/HTTP 500/);
    });
  });
});
