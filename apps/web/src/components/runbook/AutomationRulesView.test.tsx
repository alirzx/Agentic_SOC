import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi, beforeEach } from 'vitest';

const requestMock = vi.fn();

vi.mock('@/lib/api', () => ({
  request: (...args: unknown[]) => requestMock(...args),
}));

import { AutomationRulesView } from './AutomationRulesView';

describe('AutomationRulesView', () => {
  beforeEach(() => {
    requestMock.mockReset();
    // Default mock for /api/v1/runbook/actions endpoint
    requestMock.mockImplementation((url: string) => {
      if (url === '/api/v1/runbook/actions') {
        return Promise.resolve([
          { name: 'close_alert', label: 'Close alert', category: 'Case' },
          { name: 'add_alert_tag', label: 'Tag alert', category: 'Case' },
          { name: 'isolate_host', label: 'Isolate host', category: 'Containment' },
          { name: 'lookup_ip', label: 'Look up IP', category: 'Read' },
        ]);
      }
      return Promise.resolve([]);
    });
  });

  it('allows editing an existing automation rule', async () => {
    const seededRule = {
      id: '11111111-1111-4111-8111-111111111111',
      name: 'High-risk alerts -> tag',
      description: 'Existing rule',
      trigger_type: 'alert.created',
      conditions: [{ field: 'severity', op: 'eq', value: 'high' }],
      action_slug: 'add_alert_tag',
      action_params: { tag: 'high-risk' },
      autonomy_level: 'L2',
      dry_run: true,
      enabled: true,
      priority: 10,
      trigger_count: 0,
      last_triggered_at: null,
      created_at: '2026-10-01T00:00:00Z',
      updated_at: '2026-10-01T00:00:00Z',
    };

    requestMock.mockImplementation((url: string) => {
      if (url === '/api/v1/runbook/automation-rules') {
        return Promise.resolve([seededRule]);
      }
      return Promise.resolve({ ...seededRule, name: 'High-risk alerts -> tag + review' });
    });

    render(<AutomationRulesView />);

    await waitFor(() => {
      expect(screen.getByText('High-risk alerts -> tag')).toBeInTheDocument();
    });

    await userEvent.click(screen.getByRole('button', { name: /edit rule/i }));

    const nameInput = screen.getByDisplayValue('High-risk alerts -> tag');
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, 'High-risk alerts -> tag + review');
    await userEvent.click(screen.getByRole('button', { name: /save rule/i }));

    await waitFor(() => {
      expect(requestMock).toHaveBeenCalledWith(
        '/api/v1/runbook/automation-rules/11111111-1111-4111-8111-111111111111',
        expect.objectContaining({ method: 'PATCH' }),
      );
    });

    const patchPayload = JSON.parse(requestMock.mock.calls.at(-1)?.[1]?.body as string);
    expect(patchPayload.name).toBe('High-risk alerts -> tag + review');
  });

  it('filters rules by name, action and conditions', async () => {
    const rules = [
      {
        id: '33333333-3333-4333-8333-333333333333',
        name: 'Contain compromised hosts',
        description: null,
        trigger_type: 'alert.created',
        conditions: [{ field: 'severity', op: 'eq', value: 'critical' }],
        action_slug: 'isolate_host',
        action_params: {},
        autonomy_level: 'L2',
        dry_run: true,
        enabled: true,
        priority: 10,
        trigger_count: 0,
        last_triggered_at: null,
        created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-01T00:00:00Z',
        subject_type: 'alert',
        playbook_ref: null,
        docs_ref: null,
        owner_team: 'tier2-soc',
        success_count: 0,
        failed_count: 0,
        denied_count: 0,
      },
      {
        id: '44444444-4444-4444-8444-444444444444',
        name: 'Close low-confidence alerts',
        description: 'Noise reduction',
        trigger_type: 'alert.created',
        conditions: [{ field: 'confidence', op: 'lt', value: 30 }],
        action_slug: 'close_alert',
        action_params: {},
        autonomy_level: 'L1',
        dry_run: true,
        enabled: true,
        priority: 50,
        trigger_count: 0,
        last_triggered_at: null,
        created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-01T00:00:00Z',
        subject_type: 'alert',
        playbook_ref: null,
        docs_ref: null,
        owner_team: 'tier1-soc',
        success_count: 0,
        failed_count: 0,
        denied_count: 0,
      },
    ];

    requestMock.mockResolvedValue(rules);

    render(<AutomationRulesView />);

    await waitFor(() => expect(screen.getByText('Contain compromised hosts')).toBeInTheDocument());

    // The action slug is searchable even though it is not the row title.
    await userEvent.type(screen.getByLabelText(/search automation rules/i), 'isolate');

    await waitFor(() =>
      expect(screen.queryByText('Close low-confidence alerts')).not.toBeInTheDocument(),
    );
    expect(screen.getByText('Contain compromised hosts')).toBeInTheDocument();
    expect(screen.getByText('1 of 2 rules')).toBeInTheDocument();

    // Conditions are part of the haystack too.
    await userEvent.clear(screen.getByLabelText(/search automation rules/i));
    await userEvent.type(screen.getByLabelText(/search automation rules/i), 'confidence');
    await waitFor(() =>
      expect(screen.queryByText('Contain compromised hosts')).not.toBeInTheDocument(),
    );
  });

  it('previews what a draft matches without saving it first', async () => {
    requestMock.mockResolvedValue([]);
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        evaluated: 3,
        matched: 1,
        action_slug: 'close_alert',
        evaluated_against: 'alert',
        errors: [],
        matches: [
          {
            alert_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            title: 'Concurrent sign-ins from two countries',
            severity: 'medium',
            confidence: 41,
            status: 'simulated',
            action_slug: 'close_alert',
            reason: 'dry run',
          },
        ],
      }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<AutomationRulesView />);

    await userEvent.click(screen.getByRole('button', { name: /new rule/i }));

    await waitFor(
      () => expect(screen.getByText(/Matches/)).toBeInTheDocument(),
      { timeout: 3000 },
    );
    expect(screen.getByText(/of the last 3 alerts/)).toBeInTheDocument();
    expect(
      screen.getByText('Concurrent sign-ins from two countries'),
    ).toBeInTheDocument();
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/runbook/automation-rules/preview');

    vi.unstubAllGlobals();
  });

  it('marks a trigger that no code path emits', async () => {
    requestMock.mockResolvedValue([]);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          evaluated: 0,
          matched: 0,
          action_slug: 'close_alert',
          evaluated_against: 'alert',
          errors: [],
          matches: [],
        }),
      }),
    );

    render(<AutomationRulesView />);
    await userEvent.click(screen.getByRole('button', { name: /new rule/i }));

    await userEvent.selectOptions(screen.getByDisplayValue('Alert created'), 'case.created');

    await waitFor(() =>
      expect(
        screen.getByText(/No code path emits this trigger yet/),
      ).toBeInTheDocument(),
    );

    vi.unstubAllGlobals();
  });

  it('opens an autonomy dropdown with descriptive tiers and explanations', async () => {
    requestMock.mockResolvedValue([]);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          evaluated: 0,
          matched: 0,
          action_slug: 'close_alert',
          evaluated_against: 'alert',
          errors: [],
          matches: [],
        }),
      }),
    );

    render(<AutomationRulesView />);
    await userEvent.click(screen.getByRole('button', { name: /new rule/i }));

    const autonomyButton = screen.getByRole('button', { name: /L2 — Executes after analyst review/i });
    await userEvent.click(autonomyButton);

    expect(screen.getByText(/Always requires analyst approval/i)).toBeInTheDocument();
    expect(screen.getByText(/Blocks the action until a human approves it/i)).toBeInTheDocument();
    expect(screen.getByText(/Fully autonomous — no approval needed/i)).toBeInTheDocument();
    expect(screen.getByText(/Fully autonomous — no approval step is required/i)).toBeInTheDocument();
    expect(screen.queryByText(/Tier guide/i)).not.toBeInTheDocument();

    vi.unstubAllGlobals();
  });

  it('shows the selected condition fields as live preview columns', async () => {
    requestMock.mockResolvedValue([]);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          evaluated: 3,
          matched: 1,
          action_slug: 'close_alert',
          evaluated_against: 'alert',
          errors: [],
          matches: [
            {
              alert_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              title: 'Concurrent sign-ins from two countries',
              severity: 'medium',
              confidence: 41,
              status: 'simulated',
              action_slug: 'close_alert',
              reason: 'dry run',
              condition_values: {
                status: 'new',
                affected_ips: '10.0.0.9',
                title: 'Concurrent sign-ins from two countries',
              },
            },
          ],
        }),
      }),
    );

    render(<AutomationRulesView />);
    await userEvent.click(screen.getByRole('button', { name: /new rule/i }));
    await userEvent.click(screen.getByRole('button', { name: /add/i }));
    await userEvent.click(screen.getByRole('button', { name: /add/i }));
    await userEvent.click(screen.getByRole('button', { name: /add/i }));

    await userEvent.selectOptions(screen.getByLabelText(/Condition 1 field/i), 'status');
    await userEvent.selectOptions(screen.getByLabelText(/Condition 1 operator/i), 'eq');
    await userEvent.clear(screen.getByLabelText(/Condition 1 value/i));
    await userEvent.type(screen.getByLabelText(/Condition 1 value/i), 'new');

    await userEvent.selectOptions(screen.getByLabelText(/Condition 2 field/i), 'affected_ips');
    await userEvent.selectOptions(screen.getByLabelText(/Condition 2 operator/i), 'array_contains');
    await userEvent.clear(screen.getByLabelText(/Condition 2 value/i));
    await userEvent.type(screen.getByLabelText(/Condition 2 value/i), '10.0.0.9');

    await userEvent.selectOptions(screen.getByLabelText(/Condition 3 field/i), 'title');
    await userEvent.selectOptions(screen.getByLabelText(/Condition 3 operator/i), 'contains');
    await userEvent.clear(screen.getByLabelText(/Condition 3 value/i));
    await userEvent.type(screen.getByLabelText(/Condition 3 value/i), 'sign-in');

    await waitFor(() => {
      // Verify the preview table exists and has the condition columns
      const gridHeaders = screen.getAllByText(/^status$/i);
      // Should have status in the column headers area (the div with uppercase tracking-wider class)
      expect(gridHeaders.some((el) => el.className.includes('tracking-wider'))).toBe(true);
      expect(screen.getAllByText(/^affected_ips$/i).length).toBeGreaterThan(0);
      expect(screen.getAllByText(/^title$/i).length).toBeGreaterThan(0);
      // Condition values should appear in the grid
      expect(screen.getByText('10.0.0.9')).toBeInTheDocument();
    });

    vi.unstubAllGlobals();
  });

  it('shows columns for empty-value conditions but does not filter matches', async () => {
    requestMock.mockResolvedValue([]);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          evaluated: 3,
          matched: 3,
          action_slug: 'close_alert',
          evaluated_against: 'alert',
          errors: [],
          matches: [
            {
              alert_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
              title: 'Alert 1',
              severity: 'medium',
              confidence: 41,
              status: 'simulated',
              action_slug: 'close_alert',
              reason: 'dry run',
              condition_values: {
                severity: 'high',
                affected_ips: '10.0.0.1, 10.0.0.2',
              },
            },
            {
              alert_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
              title: 'Alert 2',
              severity: 'medium',
              confidence: 50,
              status: 'simulated',
              action_slug: 'close_alert',
              reason: 'dry run',
              condition_values: {
                severity: 'medium',
                affected_ips: '10.0.0.3',
              },
            },
            {
              alert_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
              title: 'Alert 3',
              severity: 'medium',
              confidence: 60,
              status: 'simulated',
              action_slug: 'close_alert',
              reason: 'dry run',
              condition_values: {
                severity: 'low',
                affected_ips: '10.0.0.4, 10.0.0.5, 10.0.0.6',
              },
            },
          ],
        }),
      }),
    );

    render(<AutomationRulesView />);
    await userEvent.click(screen.getByRole('button', { name: /new rule/i }));
    await userEvent.click(screen.getByRole('button', { name: /add/i }));
    await userEvent.click(screen.getByRole('button', { name: /add/i }));

    // Add first condition with value (severity = high)
    await userEvent.selectOptions(screen.getByLabelText(/Condition 1 field/i), 'severity');
    await userEvent.selectOptions(screen.getByLabelText(/Condition 1 operator/i), 'eq');
    await userEvent.clear(screen.getByLabelText(/Condition 1 value/i));
    await userEvent.type(screen.getByLabelText(/Condition 1 value/i), 'high');

    // Add second condition WITHOUT value (affected_ips field empty)
    await userEvent.selectOptions(screen.getByLabelText(/Condition 2 field/i), 'affected_ips');
    await userEvent.selectOptions(screen.getByLabelText(/Condition 2 operator/i), 'array_contains');
    // Do NOT enter a value for this condition

    await waitFor(() => {
      // All 3 alerts should be shown (not filtered because 2nd condition has no value)
      expect(screen.getByText('Alert 1')).toBeInTheDocument();
      expect(screen.getByText('Alert 2')).toBeInTheDocument();
      expect(screen.getByText('Alert 3')).toBeInTheDocument();
      // Both condition columns should be visible
      const gridHeaders = screen.getAllByText(/^severity$/i);
      expect(gridHeaders.some((el) => el.className.includes('tracking-wider'))).toBe(true);
      const ipHeaders = screen.getAllByText(/^affected_ips$/i);
      expect(ipHeaders.some((el) => el.className.includes('tracking-wider'))).toBe(true);
      // Values should be shown for both columns
      expect(screen.getByText('10.0.0.1, 10.0.0.2')).toBeInTheDocument();
    });

    vi.unstubAllGlobals();
  });

  it('shows only matched alert candidates before the user runs the rule test', async () => {
    const seededRule = {
      id: '22222222-2222-4222-8222-222222222222',
      name: 'Critical alerts -> case',
      description: 'Open a case for critical alerts',
      trigger_type: 'alert.created',
      conditions: [{ field: 'severity', op: 'eq', value: 'critical' }],
      action_slug: 'create_case',
      action_params: { template: 'critical-alert' },
      autonomy_level: 'L2',
      dry_run: true,
      enabled: true,
      priority: 20,
      trigger_count: 0,
      last_triggered_at: null,
      created_at: '2026-10-01T00:00:00Z',
      updated_at: '2026-10-01T00:00:00Z',
    };

    const alerts = [
      {
        id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        title: 'Credential theft detected',
        severity: 'critical',
        confidence: 92,
        status: 'new',
        source: 'identity',
        tags: [],
      },
      {
        id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        title: 'Routine login',
        severity: 'low',
        confidence: 20,
        status: 'closed',
        source: 'identity',
        tags: [],
      },
    ];

    requestMock.mockImplementation((url: string) => {
      if (url === '/api/v1/runbook/automation-rules') {
        return Promise.resolve([seededRule]);
      }
      if (url === '/api/v1/runbook/automation-rules/22222222-2222-4222-8222-222222222222/test') {
        return Promise.resolve({
          rule_id: seededRule.id,
          results: [
            { alert_id: alerts[0].id, matched: true, status: 'simulated', action_slug: 'create_case' },
            { alert_id: alerts[1].id, matched: false, status: 'not_matched', action_slug: 'create_case' },
          ],
        });
      }
      if (url === '/api/v1/alerts') {
        return Promise.resolve({ items: alerts, total: alerts.length, page: 1, page_size: 25, pages: 1 });
      }
      return Promise.resolve({
        ...seededRule,
        name: 'Critical alerts -> case',
      });
    });

    render(<AutomationRulesView />);

    await waitFor(() => {
      expect(screen.getByText('Critical alerts -> case')).toBeInTheDocument();
    });

    await userEvent.click(screen.getByRole('button', { name: /test rule on selected alerts/i }));

    await waitFor(() => {
      expect(screen.getByLabelText(/credential theft detected/i)).toBeInTheDocument();
    });
    expect(screen.queryByLabelText(/routine login/i)).not.toBeInTheDocument();

    await userEvent.click(screen.getByLabelText(/credential theft detected/i));
    await userEvent.click(screen.getByRole('button', { name: /run test/i }));

    await waitFor(() => {
      expect(requestMock).toHaveBeenCalledWith(
        '/api/v1/runbook/automation-rules/22222222-2222-4222-8222-222222222222/test',
        expect.objectContaining({ method: 'POST' }),
      );
    });
  });
});
