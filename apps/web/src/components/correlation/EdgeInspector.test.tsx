import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { EdgeInspector } from './EdgeInspector';
import { KIND_BY_NAME } from '@/components/candidates/CandidateGraphView';
import type {
  CandidateGraphEdge,
  CandidateGraphNode,
  CandidatePairScore,
} from '@/hooks/useCaseCandidates';

const observation = (key: string, label: string): CandidateGraphNode => ({
  id: `obs:${key}`,
  kind: 'observation',
  label,
  alert_count: 2,
  observation_key: key,
});

const nodes = new Map<string, CandidateGraphNode>([
  ['obs:a', observation('a', 'credential_access:lsass')],
  ['obs:b', observation('b', 'lateral_movement:smb')],
  ['host:win-dc-01', { id: 'host:win-dc-01', kind: 'host', label: 'win-dc-01', token: 'host:win-dc-01' }],
]);

const renderer = (edge: CandidateGraphEdge, pair: CandidatePairScore | null, onFocus = vi.fn()) =>
  render(
    <EdgeInspector
      edge={edge}
      pair={pair}
      nodes={nodes}
      onDismiss={vi.fn()}
      onFocus={onFocus}
      onHide={vi.fn()}
    />
  );

describe('EdgeInspector', () => {
  it('keeps process leaves on the original cut-rectangle silhouette and teal color', () => {
    expect(KIND_BY_NAME.process_guid.shape).toBe('polygon');
    expect(KIND_BY_NAME.process_guid.points).toBeDefined();
    expect(KIND_BY_NAME.process_guid.color).toBe('#14b8a6');
  });

  it('names a key link, its weight and both endpoints', () => {
    renderer(
      {
        id: 'obs:a->host:win-dc-01',
        source: 'obs:a',
        target: 'host:win-dc-01',
        kind: 'OBSERVED_ON',
        weight: 2,
        token: 'host:win-dc-01',
      },
      null
    );

    expect(screen.getByText('shared host')).toBeTruthy();
    expect(screen.getByText('weight 2')).toBeTruthy();
    expect(screen.getByText('credential_access:lsass')).toBeTruthy();
    expect(screen.getByText('win-dc-01')).toBeTruthy();
    // The shared key itself, so an analyst sees the exact value that linked them.
    expect(screen.getByText('host:win-dc-01')).toBeTruthy();
  });

  it('explains a scored pair link with its L1/L2/L3 split and matched keys', () => {
    renderer(
      {
        id: 'obs:a~obs:b',
        source: 'obs:a',
        target: 'obs:b',
        kind: 'CORRELATION',
        weight: 7,
        threshold_met: true,
      },
      {
        source: 'a',
        target: 'b',
        l1: 4,
        l2: 2,
        l3: 1,
        score: 7,
        matched: [{ kind: 'user', value: 'administrator', weight: 2 }],
        l3_via: { via: 'obs:c', left_token: 'user:administrator', right_token: 'ip:10.0.0.9' },
        threshold_met: true,
      }
    );

    expect(screen.getByText('pair link')).toBeTruthy();
    expect(screen.getByText('score 7')).toBeTruthy();
    expect(screen.getByText('L1 4 · L2 2 · L3 1')).toBeTruthy();
    expect(screen.getByText(/L3 — path through a third observation/)).toBeTruthy();
    // Once as the L1 contribution, once as the key the L3 path left through.
    expect(screen.getAllByText('user:administrator')).toHaveLength(2);
  });

  it('flags a below-threshold link instead of hiding the number', () => {
    renderer(
      {
        id: 'obs:a~obs:b',
        source: 'obs:a',
        target: 'obs:b',
        kind: 'CORRELATION',
        weight: 2,
        threshold_met: false,
      },
      { source: 'a', target: 'b', l1: 2, l2: 0, l3: 0, score: 2, threshold_met: false }
    );

    expect(screen.getByText('below θ')).toBeTruthy();
  });

  it('explains an action edge: role, alerts, collapsed observations', () => {
    renderer(
      {
        id: 'role:host:win-dc-01~user:administrator',
        source: 'host:win-dc-01',
        target: 'user:administrator',
        kind: 'OBSERVATION',
        role: 'general:intrusion',
        roles: ['credential_access:lsass', 'general:intrusion'],
        observations: ['entity|T1003.006|abc'],
        count: 2,
        alert_count: 7,
        endpoint_count: 3,
      },
      null
    );

    // The observation is a relation now: its role names the edge, and the
    // evidence behind it stays one click away.
    expect(screen.getByText('general:intrusion')).toBeTruthy();
    expect(screen.getByText('7 alerts')).toBeTruthy();
    expect(screen.getByText('2 actions collapsed')).toBeTruthy();
    expect(screen.getByText('entity|T1003.006|abc')).toBeTruthy();
    expect(
      screen.getByText(/roles: credential_access:lsass, general:intrusion/)
    ).toBeTruthy();
    // An action edge has no L1 "weight" to show; the alert count is the number.
    expect(screen.queryByText(/^weight /)).toBeNull();
  });

  it('focuses an endpoint from its card', async () => {
    const onFocus = vi.fn();
    renderer(
      {
        id: 'obs:a->host:win-dc-01',
        source: 'obs:a',
        target: 'host:win-dc-01',
        kind: 'OBSERVED_ON',
        weight: 2,
      },
      null,
      onFocus
    );

    const [sourceFocus] = screen.getAllByRole('button', { name: 'Focus' });
    await userEvent.click(sourceFocus);
    expect(onFocus).toHaveBeenCalledWith('obs:a');
  });

  it('lists the other observations that share the same key', () => {
    render(
      <EdgeInspector
        edge={{
          id: 'obs:a->host:win-dc-01',
          source: 'obs:a',
          target: 'host:win-dc-01',
          kind: 'OBSERVED_ON',
          weight: 2,
        }}
        pair={null}
        nodes={nodes}
        siblings={[observation('b', 'lateral_movement:smb')]}
        onDismiss={vi.fn()}
        onFocus={vi.fn()}
        onHide={vi.fn()}
      />
    );

    expect(screen.getByText('also on this key')).toBeTruthy();
    expect(screen.getByText('lateral_movement:smb')).toBeTruthy();
  });
});
