import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { GraphEntityPanel, type GraphEntityRow } from './GraphEntityPanel';

const rows: GraphEntityRow[] = [
  {
    id: 'host:win-dc-01',
    kind: 'host',
    label: 'win-dc-01',
    token: 'host:win-dc-01',
    alerts: 6,
    links: 9,
    actions: 4,
  },
  {
    id: 'user:administrator',
    kind: 'user',
    label: 'administrator',
    token: 'user:administrator',
    alerts: 2,
    links: 3,
    actions: 2,
  },
];

const setup = (overrides: Partial<Parameters<typeof GraphEntityPanel>[0]> = {}) => {
  const props = {
    entities: rows,
    hiddenIds: new Set<string>(),
    removedIds: new Set<string>(),
    selectedIds: new Set<string>(),
    activeId: null,
    kindLabel: (kind: string) => kind,
    kindColor: () => '#94a3b8',
    onActivate: vi.fn(),
    onHide: vi.fn(),
    onShow: vi.fn(),
    onRemove: vi.fn(),
    onRestore: vi.fn(),
    onSetSelection: vi.fn(),
    onToggleSelection: vi.fn(),
    onSelectRelated: vi.fn(),
    onOpenDetails: vi.fn(),
    onClose: vi.fn(),
    ...overrides,
  };
  render(<GraphEntityPanel {...props} />);
  return props;
};

describe('GraphEntityPanel', () => {
  it('switches to the cluster tab and reports a toggle', async () => {
    const onToggleCluster = vi.fn();
    setup({
      clusters: [
        {
          community: 'c1',
          title: 'win-dc-01',
          subtitle: '9 · credential_access',
          color: '#38bdf8',
          size: 9,
        },
      ],
      onToggleCluster,
    });

    await userEvent.click(screen.getByRole('tab', { name: /clusters/i }));
    expect(screen.getByText('win-dc-01')).toBeTruthy();

    await userEvent.click(screen.getByTitle(/Collapse win-dc-01/i));
    expect(onToggleCluster).toHaveBeenCalledWith('c1');
  });

  it('groups the list by kind, strongest kind first', () => {
    setup({ kindLabel: (kind) => kind.toUpperCase() });

    const headings = screen
      .getAllByTestId('kind-group')
      .map((node) => node.textContent?.trim());
    // rows arrive strongest-first (host links 9, user links 3), so the headings
    // follow that ranking instead of a hardcoded order.
    expect(headings).toEqual(['HOST', 'USER']);
  });

  it('draws each row with the kind’s own silhouette, not one shape for all', () => {
    setup({
      kindIcon: (kind) => <svg data-testid={`kind-${kind}`} />,
    });

    expect(screen.getByTestId('kind-host')).toBeTruthy();
    expect(screen.getByTestId('kind-user')).toBeTruthy();
  });

  it('lists each entity with the counts that place it', () => {
    setup();

    expect(screen.getByText('win-dc-01')).toBeTruthy();
    expect(screen.getByText('9 links · 4 actions · 6 alerts')).toBeTruthy();
    expect(screen.getByText('administrator')).toBeTruthy();
  });

  it('filters by value and by type', async () => {
    setup();

    await userEvent.type(screen.getByLabelText('Filter entities'), 'admin');
    expect(screen.queryByText('win-dc-01')).toBeNull();
    expect(screen.getByText('administrator')).toBeTruthy();

    await userEvent.clear(screen.getByLabelText('Filter entities'));
    await userEvent.type(screen.getByLabelText('Filter entities'), 'host');
    expect(screen.getByText('win-dc-01')).toBeTruthy();
    expect(screen.queryByText('administrator')).toBeNull();
  });

  it('jumps the camera to the entity that was clicked', async () => {
    const props = setup();

    await userEvent.click(screen.getByText('win-dc-01'));
    expect(props.onActivate).toHaveBeenCalledWith('host:win-dc-01');
  });

  it('flags a hidden row and offers to put it back', async () => {
    const props = setup({ hiddenIds: new Set(['host:win-dc-01']) });

    expect(screen.getByText('hidden')).toBeTruthy();
    await userEvent.click(screen.getByLabelText('Show win-dc-01'));
    expect(props.onRestore).toHaveBeenCalledWith(['host:win-dc-01']);
  });

  it('inverts the selection across the visible rows', async () => {
    const props = setup({ selectedIds: new Set(['host:win-dc-01']) });

    await userEvent.click(screen.getByText('Invert'));
    expect(props.onSetSelection).toHaveBeenCalledWith(['user:administrator']);
  });

  it('passes the current selection into Related so the list and graph stay in sync', async () => {
    const props = setup({ selectedIds: new Set(['host:win-dc-01']) });

    await userEvent.click(screen.getByText('Related'));
    expect(props.onSelectRelated).toHaveBeenCalledWith(['host:win-dc-01']);
  });

  it('opens details explicitly for a row even when the main toggle is off', async () => {
    const props = setup();

    await userEvent.click(screen.getByLabelText('Open details for win-dc-01'));
    expect(props.onOpenDetails).toHaveBeenCalledWith('host:win-dc-01');
  });

  it('keeps Related inert until something is selected', () => {
    setup();
    const related = screen.getByText('Related').closest('button') as HTMLButtonElement;
    expect(related.disabled).toBe(true);
  });

  it('hides and removes only when a selection exists', async () => {
    const props = setup({ selectedIds: new Set(['user:administrator']) });

    await userEvent.click(screen.getByText('Hide'));
    expect(props.onHide).toHaveBeenCalledWith(['user:administrator']);

    await userEvent.click(screen.getByText('Remove'));
    expect(props.onRemove).toHaveBeenCalledWith(['user:administrator']);
  });
});
