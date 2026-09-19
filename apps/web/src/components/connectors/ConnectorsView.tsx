'use client';

/**
 * Top-level Connectors page.
 *
 * Owns the SWR cache for `connectorsApi.list()` and renders three sub-views
 * depending on state:
 *
 *   - loading  → skeleton tiles
 *   - error    → error banner + empty list (no fabricated demo connectors)
 *   - data     → header stats + `ConnectorInstanceList` + add-connector modal
 */

import { useMemo, useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import Link from 'next/link';

import {
  connectorsApi,
  type Connector,
  type ConnectorHealthSummary,
} from '@/lib/api';
import { AddConnectorModal } from './AddConnectorModal';
import { ConnectorInstanceList } from './ConnectorInstanceList';
import { InboxTokensPanel } from './InboxTokensPanel';

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function ConnectorsView() {
  const [modalOpen, setModalOpen] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, boolean | undefined>>({});

  const { data, error, isLoading, mutate } = useSWR(
    'connectors',
    () => connectorsApi.list(),
    { revalidateOnFocus: false },
  );

  const { data: healthSummary } = useSWR<ConnectorHealthSummary | null>(
    'connectors:health',
    async () => {
      try {
        return await connectorsApi.health();
      } catch {
        return null;
      }
    },
    { revalidateOnFocus: false, refreshInterval: 60_000 },
  );

  const connectors: Connector[] = useMemo(() => data?.connectors ?? [], [data]);

  const localStats = useMemo(() => {
    const active = connectors.filter((c) => c.status === 'active').length;
    const errored = connectors.filter((c) => c.status === 'error').length;
    const totalEvents = connectors.reduce(
      (sum, c) => sum + (c.alertCount ?? c.alertsIngested ?? 0),
      0,
    );
    const driftedRecently = connectors.filter((c) => {
      if (!c.lastSchemaDriftAt) return false;
      return Date.now() - new Date(c.lastSchemaDriftAt).getTime() < 24 * 60 * 60 * 1000;
    }).length;
    const totalDropped = connectors.reduce(
      (sum, c) => sum + (c.eventsDropped ?? 0),
      0,
    );
    return { active, errored, totalEvents, driftedRecently, totalDropped };
  }, [connectors]);

  const stats = useMemo(() => {
    if (healthSummary) {
      return {
        active: healthSummary.healthy,
        errored: healthSummary.unhealthy,
        totalEvents: healthSummary.totalEventsIngested,
        driftedRecently: healthSummary.driftedRecently,
        totalDropped: healthSummary.totalEventsDropped,
      };
    }
    return localStats;
  }, [healthSummary, localStats]);

  const handleTest = async (id: string) => {
    if (!UUID_RE.test(id)) {
      toast.error(
        'This is not a saved connector. Click Add Connector to create a real Splunk instance.',
      );
      return;
    }
    setTestingId(id);
    setTestResults((prev) => ({ ...prev, [id]: undefined }));
    try {
      const result = await connectorsApi.test(id);
      setTestResults((prev) => ({ ...prev, [id]: result.success }));
      if (result.success) {
        toast.success(result.message ?? 'Connection test passed');
      } else {
        toast.error(result.error ?? result.message ?? 'Connection test failed');
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Test request failed';
      setTestResults((prev) => ({ ...prev, [id]: false }));
      toast.error(msg);
    } finally {
      setTestingId(null);
    }
  };

  const handleDelete = async (connector: Connector) => {
    const ok = window.confirm(
      `Delete connector "${connector.name}"? This stops polling and removes its credentials. Already-ingested alerts are preserved.`,
    );
    if (!ok) return;

    try {
      await connectorsApi.delete(connector.id);
      toast.success(`Removed ${connector.name}`);
      mutate();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to delete connector';
      toast.error(msg);
    }
  };

  const handleConfigure = (_connector: Connector) => {
    toast('Connector editing UI is coming soon. Delete + re-add for now.', {
      icon: '🔧',
    });
  };

  const handleCreated = () => {
    mutate();
  };

  const authError = error instanceof Error && /401|Unauthorized/i.test(error.message);

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Connectors</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Security tool integrations and data source management
          </p>
        </div>
        <button
          type="button"
          onClick={() => setModalOpen(true)}
          className="bg-brand-600 hover:bg-brand-500 text-white text-sm px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Connector
        </button>
      </div>

      <div
        className={clsx(
          'grid grid-cols-2 gap-3',
          stats.driftedRecently > 0 || stats.totalDropped > 0
            ? 'md:grid-cols-6'
            : 'md:grid-cols-4',
        )}
      >
        {[
          {
            label: 'Total Connectors',
            value: healthSummary?.total ?? connectors.length,
            color: 'text-brand-400',
            show: true,
          },
          { label: 'Active', value: stats.active, color: 'text-green-400', show: true },
          { label: 'Errors', value: stats.errored, color: 'text-red-400', show: true },
          {
            label: 'Events Ingested',
            value: stats.totalEvents.toLocaleString(),
            color: 'text-purple-400',
            show: true,
          },
          {
            label: 'Schema Drift (24h)',
            value: stats.driftedRecently,
            color: 'text-amber-400',
            show: stats.driftedRecently > 0,
            tooltip: healthSummary?.lastDriftAt
              ? `Most recent drift: ${new Date(healthSummary.lastDriftAt).toLocaleString()}`
              : undefined,
          },
          {
            label: 'Events Dropped',
            value: stats.totalDropped.toLocaleString(),
            color: 'text-cyan-400',
            show: stats.totalDropped > 0,
            tooltip: 'Filtered out by pre-ingest pipeline rules',
          },
        ]
          .filter((stat) => stat.show)
          .map((stat) => (
            <div
              key={stat.label}
              title={stat.tooltip}
              className="bg-dark-60 border border-[#374151]/60 rounded-xl p-4"
            >
              <p className={clsx('text-2xl font-bold mb-1', stat.color)}>{stat.value}</p>
              <p className="text-xs text-gray-500">{stat.label}</p>
            </div>
          ))}
      </div>

      {authError && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm text-amber-100">
          Not authenticated.{' '}
          <Link href="/login" className="underline hover:text-white">
            Sign in
          </Link>{' '}
          with <code className="text-xs">demo@tryaisoc.com</code> /{' '}
          <code className="text-xs">aisoc-demo</code>, then use <strong>Add Connector</strong> to
          create a real Splunk instance.
        </div>
      )}
      {error && !authError && (
        <div className="rounded-md border border-red-500/30 bg-red-500/5 px-4 py-2 text-xs text-red-200">
          Connectors API error: {error instanceof Error ? error.message : String(error)}
        </div>
      )}

      <ConnectorInstanceList
        connectors={connectors}
        isLoading={isLoading && !data}
        testingId={testingId}
        testResults={testResults}
        onTest={handleTest}
        onAdd={() => setModalOpen(true)}
        onConfigure={handleConfigure}
        onDelete={handleDelete}
      />

      <InboxTokensPanel />

      <AddConnectorModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onCreated={handleCreated}
      />
    </div>
  );
}
