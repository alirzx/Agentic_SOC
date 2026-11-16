'use client';

/**
 * PipelineHealth
 * ==============
 * Five-stage pipeline health strip (ingest → normalize → fuse → correlate → alert).
 * Each stage shows backlog, p95 latency, error rate, and an at-a-glance status
 * ({@link Status}). Mirrors the reference SOC console's pipeline-health rail.
 *
 * Data source: `GET /api/v1/health/pipeline` ({@link metricsApi.getPipelineHealth}).
 * Polls every 30 s; ignores SWR retries (the endpoint never throws under nominal
 * conditions — failures are reported in the row).
 *
 * Author: Beenu Arora <beenu@cyble.com>
 */

import useSWR from 'swr';
import { clsx } from 'clsx';
import {
  metricsApi,
  type PipelineHealth as PipelineHealthData,
  type PipelineStage,
} from '@/lib/api';
import { Card, CardHeader, Pill } from './ui';

type Status = PipelineStage['status'];

const STAGE_LABELS: Record<PipelineStage['stage'], string> = {
  ingest: 'Ingest',
  normalize: 'Normalize',
  fuse: 'Fuse',
  correlate: 'Correlate',
  alert: 'Alert',
};

const STAGE_DESCRIPTIONS: Record<PipelineStage['stage'], string> = {
  ingest: 'Connector → raw events',
  normalize: 'OCSF mapping',
  fuse: 'Alert fusion',
  correlate: 'Cross-source correlation',
  alert: 'Final alert emission',
};

const STAGE_ORDER: PipelineStage['stage'][] = [
  'ingest',
  'normalize',
  'fuse',
  'correlate',
  'alert',
];

function statusStyles(status: Status) {
  switch (status) {
    case 'green':
      return {
        dot: 'bg-green-500',
        ring: 'ring-green-500/25',
        text: 'text-teal-20',
        bar: 'bg-green-500/70',
      };
    case 'yellow':
      return {
        dot: 'bg-[#F98B3E]',
        ring: 'ring-[#F98B3E]/25',
        text: 'text-[#F98B3E]',
        bar: 'bg-amber-500/70',
      };
    case 'red':
      return {
        dot: 'bg-[#FD4E4E]',
        ring: 'ring-[#FD4E4E]/25',
        text: 'text-[#FD4E4E]',
        bar: 'bg-red-500/70',
      };
    default:
      return {
        dot: 'bg-gray-500',
        ring: 'ring-gray-500/25',
        text: 'text-fg-muted',
        bar: 'bg-gray-600/50',
      };
  }
}

function formatLatency(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1) return '< 1 ms';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1).replace(/\.0$/, '')} s`;
  return `${(ms / 60_000).toFixed(1).replace(/\.0$/, '')} m`;
}

function formatBacklog(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n >= 1_000_000)
    return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}k`;
  return String(Math.round(n));
}

function formatErrorRate(ratio: number): string {
  if (!Number.isFinite(ratio) || ratio < 0) return '—';
  if (ratio === 0) return '0%';
  if (ratio < 0.001) return '< 0.1%';
  return `${(ratio * 100).toFixed(2).replace(/\.?0+$/, '')}%`;
}

function StageCard({ stage }: { stage: PipelineStage }) {
  const styles = statusStyles(stage.status);
  return (
    <div className="rounded-2xl border border-surface-border bg-surface-card p-5 min-w-0">
      <div className="flex items-start justify-between mb-2">
        <p className="text-lg font-gilroy-semibold text-fg-primary truncate">
          {STAGE_LABELS[stage.stage]}
        </p>
        <span
          className={clsx('mt-1.5 h-2 w-2 rounded-full ring-4', styles.dot, styles.ring)}
          aria-label={`status ${stage.status}`}
        />
      </div>
      <p className="text-xs text-fg-muted truncate">
        {STAGE_DESCRIPTIONS[stage.stage]}
      </p>

      <dl className="mt-3 space-y-1.5">
        <div className="grid grid-cols-2 gap-2 text-xs">
          <dt className="text-fg-subtle">Backlog</dt>
          <dd className="text-fg-subtle tabular-nums">
            {formatBacklog(stage.backlog)}
          </dd>
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <dt className="text-fg-subtle">p95</dt>
          <dd className="text-fg-subtle tabular-nums">
            {formatLatency(stage.p95_latency_ms)}
          </dd>
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <dt className="text-fg-subtle">Errors</dt>
          <dd className={clsx('tabular-nums', styles.text)}>
            {formatErrorRate(stage.error_rate)}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function LoadingStage({ stage }: { stage: PipelineStage['stage'] }) {
  return (
    <div className="rounded-2xl border border-surface-border bg-surface-card p-5 min-w-0">
      <div className="flex items-start justify-between mb-2">
        <p className="text-lg font-gilroy-semibold text-fg-primary truncate">
          {STAGE_LABELS[stage]}
        </p>
        <span className="mt-1.5 h-2 w-2 rounded-full bg-gray-500 ring-4 ring-gray-500/25 animate-pulse" />
      </div>
      <p className="text-xs text-fg-muted truncate">
        {STAGE_DESCRIPTIONS[stage]}
      </p>
      <div className="mt-3 space-y-2">
        <div className="h-3 w-full rounded bg-dark-20/60 animate-pulse" />
        <div className="h-3 w-full rounded bg-dark-20/60 animate-pulse" />
        <div className="h-3 w-2/3 rounded bg-dark-20/60 animate-pulse" />
      </div>
    </div>
  );
}

export function PipelineHealth() {
  const { data, error, isLoading } = useSWR<PipelineHealthData>(
    'pipeline-health',
    () => metricsApi.getPipelineHealth(),
    {
      refreshInterval: 30_000,
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    },
  );

  // Build a stage→data map and render in canonical order so the UI never
  // re-orders mid-flight even if the API ever changes its ordering.
  const stagesByName: Partial<Record<PipelineStage['stage'], PipelineStage>> = {};
  for (const s of data?.stages ?? []) stagesByName[s.stage] = s;

  return (
    <Card className="p-6">
      <CardHeader
        title="Pipeline Health"
        subtitle="Ingest → normalize → fuse → correlate → alert"
        action={
          error ? (
            <Pill className="border-red-500/30 bg-red-500/10 text-[#FD4E4E]">unavailable</Pill>
          ) : (
            <Pill>Live</Pill>
          )
        }
        className="mb-5"
      />

      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-4">
        {STAGE_ORDER.map((name) => {
          const stage = stagesByName[name];
          if (isLoading || !stage) return <LoadingStage key={name} stage={name} />;
          return <StageCard key={name} stage={stage} />;
        })}
      </div>
    </Card>
  );
}

export default PipelineHealth;
