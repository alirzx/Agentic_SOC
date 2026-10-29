import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { DetectionFuseView } from './DetectionFuseView';

const incidentAlert = {
  alert_id: '11111111-1111-4111-8111-111111111111',
  title: 'Credential dumping on FIN-WS-04',
  severity: 'high',
  created_at: '2026-10-29T10:00:00Z',
  rule_id: 'splunk-rule-9901',
  rule_name: 'Mimikatz string match',
  connector_type: 'splunk',
  confidence: 78,
  occurrence_count: 4,
  fusion_state: 'incident',
  fusion_incident_id: '99999999-9999-4999-8999-999999999999',
  parent_alert_id: null,
};

const rulelessAlert = {
  ...incidentAlert,
  alert_id: '22222222-2222-4222-8222-222222222222',
  title: 'Unattributed process spawn',
  rule_id: null,
  rule_name: null,
  connector_type: null,
  confidence: null,
  occurrence_count: 1,
  fusion_state: 'standalone',
  fusion_incident_id: null,
};

const payload = {
  summary: {
    examined: 2,
    distinct_rules: 1,
    without_rule: 1,
    merged: 0,
    incident_linked: 1,
    deduplicated: 1,
  },
  items: [incidentAlert, rulelessAlert],
};

describe('DetectionFuseView', () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders each alert with its rule, source, dedup count and fusion state', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => payload });
    vi.stubGlobal('fetch', fetchMock);

    render(<DetectionFuseView />);

    await waitFor(() =>
      expect(screen.getByText('Mimikatz string match')).toBeInTheDocument(),
    );
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/runbook/detections?limit=50');
    expect(screen.getByText('splunk')).toBeInTheDocument();
    expect(screen.getByText('×4 similar events')).toBeInTheDocument();
    expect(screen.getByText('Incident')).toBeInTheDocument();
    // The alert is reachable, since the deeper lineage lives behind Explain.
    expect(
      screen.getByRole('link', { name: 'Credential dumping on FIN-WS-04' }),
    ).toHaveAttribute('href', `/alerts/${incidentAlert.alert_id}`);
  });

  it('says a rule is missing instead of inventing one', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, json: async () => payload }),
    );

    render(<DetectionFuseView />);

    await waitFor(() => expect(screen.getByText('No rule recorded')).toBeInTheDocument());
    expect(screen.getByText('Standalone')).toBeInTheDocument();
  });

  it('scopes the counts to the rows on screen', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, json: async () => payload }),
    );

    render(<DetectionFuseView />);

    await waitFor(() => expect(screen.getByText(/Last 2 promotions/)).toBeInTheDocument());
    expect(screen.getByText(/most recent alerts, not the full history/)).toBeInTheDocument();
  });

  it('shows an honest empty state rather than a demo placeholder', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ summary: { examined: 0 }, items: [] }),
      }),
    );

    render(<DetectionFuseView />);

    await waitFor(() =>
      expect(screen.getByText('No alerts have been promoted yet')).toBeInTheDocument(),
    );
  });

  it('surfaces a load failure instead of an empty table', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: false, status: 503, json: async () => ({}) }),
    );

    render(<DetectionFuseView />);

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/HTTP 503/));
  });
});
