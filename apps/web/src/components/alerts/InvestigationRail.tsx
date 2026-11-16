'use client';

/**
 * Investigation Rail (v1.5 W6 — SOC console parity).
 *
 * Structured triage panel rendered to the right of the `/alerts` grid
 * whenever an analyst selects a row. The rail consumes the envelope
 * served by `GET /api/v1/alerts/{id}` — which carries four sections
 * the analyst needs at first glance:
 *
 *   1. Narrative — deterministic, Markdown-light explanation of *why*
 *      fusion promoted this alert. Cached on the row at fusion time and
 *      lazily back-filled by the API for legacy alerts so we never
 *      surface a blank panel.
 *   2. Related entities — principal / network / workflow / tenant
 *      groupings. Entries with a `pivotPath` link straight into the
 *      AttackGraphView so analysts can hop from "10.0.0.7" to its
 *      neighbourhood in two clicks instead of switching pages.
 *   3. Mini-timeline — the six most recent case-timeline + audit-log
 *      events for this alert's case, surfaced inline so the analyst
 *      doesn't have to leave the queue just to see what happened last.
 *   4. Recommended actions — ResponderAgent's structured guidance,
 *      normalised server-side so legacy list-of-strings payloads and
 *      the modern `{priority, action, rationale, risk}` shape render
 *      uniformly.
 *
 * A single "Deep Explain" button at the top of the rail still opens the
 * existing {@link ExplainDrawer} for the rich LLM-driven walkthrough —
 * the rail itself is deterministic and cheap so we don't burn an LLM
 * call every time the analyst clicks a row.
 *
 * Author: Beenu Arora <beenu@cyble.com>
 */

import Link from 'next/link';
import { useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { format, formatDistanceToNow } from 'date-fns';
import { X } from 'lucide-react';
import {
  alertsApi,
  type Alert,
  type MiniTimelineEvent,
  type RecommendedAction,
  type RelatedEntity,
} from '@/lib/api';
import { ExplainDrawer } from './ExplainDrawer';
import { Skeleton } from '@/components/ui/Skeleton';

// ─── Visual config ───────────────────────────────────────────────────────────

/**
 * Grouping config for {@link RelatedEntity.kind}.
 *
 * The order of these keys determines the render order inside the rail.
 * "principal" goes first because that's the entity an analyst usually
 * pivots on (who did it / who was hit). "tenant" is last because it's
 * the broadest-context grouping.
 */
const ENTITY_KIND_CONFIG: Record<
  RelatedEntity['kind'],
  { label: string; tone: string }
> = {
  principal: { label: 'Principals', tone: 'text-teal-10' },
  network: { label: 'Network', tone: 'text-[#3163CF]' },
  workflow: { label: 'Workflow', tone: 'text-[#7B5EE6]' },
  tenant: { label: 'Tenant', tone: 'text-fg-muted' },
};

/** Outlined pill colours for the rail header (light dashboard design). */
const PILL_HEX: Record<string, string> = {
  critical: '#FD4E4E',
  high: '#F98B3E',
  medium: '#F2AC49',
  low: '#4FD2C2',
  info: '#939DAD',
  new: '#7B5EE6',
  triaged: '#3163CF',
  investigating: '#4FD2C2',
  resolved: '#4ADE80',
  false_positive: '#939DAD',
};

const CONFIDENCE_LABEL: Record<string, { label: string; hex: string }> = {
  high: { label: 'High conf.', hex: '#4FD2C2' },
  medium: { label: 'Med', hex: '#F2BD57' },
  low: { label: 'Low', hex: '#939DAD' },
};

function RailPill({ hex, children, className }: { hex: string; children: React.ReactNode; className?: string }) {
  return (
    <span
      className={clsx('inline-flex items-center rounded-md border px-2.5 py-1 text-[11px] leading-none', className)}
      style={{ borderColor: `${hex}B3`, backgroundColor: `${hex}1F`, color: hex }}
    >
      {children}
    </span>
  );
}

/** Tone map for the priority chip on a recommended action. */
const PRIORITY_TONE: Record<RecommendedAction['priority'], string> = {
  critical: 'border-[#FD4E4E]/60 bg-[#FD4E4E]/10 text-[#FD4E4E]',
  high: 'border-[#F98B3E]/60 bg-[#F98B3E]/10 text-[#F98B3E]',
  medium: 'border-[#F2BD57]/70 bg-[#F2BD57]/10 text-[#D99A1E]',
  low: 'border-teal-20/60 bg-teal-20/10 text-teal-10',
  info: 'border-gray-500/50 bg-gray-500/10 text-fg-muted',
};

// ─── Props ───────────────────────────────────────────────────────────────────

export interface InvestigationRailProps {
  /** Selected alert id. When `null` the rail renders an empty-state hint. */
  alertId: string | null;
  /** Called when the analyst dismisses the rail (close button). */
  onClose: () => void;
}

// ─── Main component ──────────────────────────────────────────────────────────

export function InvestigationRail({ alertId, onClose }: InvestigationRailProps) {
  // The drawer is mounted on demand and closed by default; we don't
  // burn the LLM call until the analyst explicitly asks for it.
  const [deepExplainOpen, setDeepExplainOpen] = useState(false);

  const { data: alert, error, isLoading } = useSWR(
    alertId ? (['alerts', alertId, 'rail'] as const) : null,
    () => alertsApi.get(alertId as string),
    {
      // The rail is supposed to feel like a *snapshot* — the analyst
      // explicitly opens it. We don't want noisy revalidates on tab
      // focus throwing off their reading flow.
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    },
  );

  if (!alertId) {
    return <RailPlaceholder />;
  }

  if (isLoading || (!alert && !error)) {
    return <RailLoading onClose={onClose} />;
  }

  if (error || !alert) {
    return (
      <RailShell title="Investigation rail" onClose={onClose}>
        <div className="px-4 py-6 text-sm text-[#FD4E4E]">
          <p className="font-medium">Couldn&apos;t load the alert envelope.</p>
          <p className="mt-1 text-xs text-fg-muted">
            The alert API didn&apos;t respond. Try selecting the alert again or
            open the full detail view.
          </p>
        </div>
      </RailShell>
    );
  }

  return (
    <>
      <RailShell title={alert.title} onClose={onClose}>
        <RailHeader alert={alert} onDeepExplain={() => setDeepExplainOpen(true)} />
        <NarrativeSection narrative={alert.narrative ?? null} />
        <RelatedEntitiesSection entities={alert.relatedEntities ?? []} />
        <MiniTimelineSection events={alert.miniTimeline ?? []} />
        <RecommendedActionsSection actions={alert.recommendedActions ?? []} />
      </RailShell>
      {/*
       * Deep Explain is mounted only when requested — keeping it inside the
       * rail (rather than at AlertsView level) means the rail owns the
       * "deep" affordance and we don't end up with two ways to open the
       * same drawer from different places.
       */}
      {deepExplainOpen && (
        <ExplainDrawer
          open={true}
          alert={alert}
          onClose={() => setDeepExplainOpen(false)}
        />
      )}
    </>
  );
}

// ─── Layout primitives ───────────────────────────────────────────────────────

function RailShell({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <aside
      className="flex flex-col min-w-0 max-w-full bg-surface-card border border-surface-border rounded-2xl overflow-hidden h-full"
      aria-label="Investigation rail"
    >
      <div className="flex items-center justify-between gap-2 px-4 py-4 border-b border-surface-border min-w-0">
        <h2 className="text-[13px] font-gilroy-semibold text-fg-primary truncate min-w-0" title={title}>
          {title}
        </h2>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close investigation rail"
          className="shrink-0 inline-flex h-[18px] w-[18px] items-center justify-center rounded-full border border-fg-subtle/60 text-fg-subtle hover:text-fg-primary hover:border-fg-muted transition-colors"
        >
          <X className="h-3 w-3" strokeWidth={2} aria-hidden />
        </button>
      </div>
      <div className="flex-1 min-w-0 overflow-y-auto overflow-x-hidden">{children}</div>
    </aside>
  );
}

function RailPlaceholder() {
  return (
    <aside
      className="flex min-h-[220px] flex-col items-center justify-center bg-surface-card border border-dashed border-surface-border rounded-2xl text-fg-muted text-sm h-full p-6 text-center"
      aria-label="Investigation rail (no alert selected)"
    >
      <p className="font-gilroy-medium text-fg-secondary">Select an alert to investigate</p>
      <p className="mt-1 text-xs text-fg-subtle">
        Click a row in the queue on the left. The rail will show the fusion
        narrative, related entities, recent events, and recommended actions.
      </p>
    </aside>
  );
}

function RailLoading({ onClose }: { onClose: () => void }) {
  return (
    <RailShell title="Loading…" onClose={onClose}>
      <div className="p-4 space-y-4">
        <Skeleton className="h-4 w-2/3" />
        <Skeleton className="h-3 w-full" />
        <Skeleton className="h-3 w-5/6" />
        <Skeleton className="h-3 w-4/6" />
        <div className="pt-3 space-y-2">
          <Skeleton className="h-3 w-1/4" />
          <Skeleton className="h-3 w-3/4" />
          <Skeleton className="h-3 w-2/4" />
        </div>
      </div>
    </RailShell>
  );
}

// ─── Header (severity, status, deep explain) ─────────────────────────────────

function RailHeader({
  alert,
  onDeepExplain,
}: {
  alert: Alert;
  onDeepExplain: () => void;
}) {
  const confidence = alert.confidenceLabel ? CONFIDENCE_LABEL[alert.confidenceLabel] : undefined;
  const technique = alert.mitreAttack?.[0]?.techniqueId;
  return (
    <div className="px-4 py-4 border-b border-surface-border">
      <div className="flex flex-wrap items-center gap-2">
        {confidence && (
          <RailPill hex={confidence.hex}>
            <span title="Detection confidence">{confidence.label}</span>
          </RailPill>
        )}
        <RailPill hex={PILL_HEX[alert.severity] ?? PILL_HEX.info}>
          <span className="capitalize">{alert.severity}</span>
        </RailPill>
        <RailPill hex={PILL_HEX[alert.status] ?? PILL_HEX.new}>
          <span className="capitalize">{alert.status.replace('_', ' ')}</span>
        </RailPill>
        {typeof alert.riskScore === 'number' && (
          <RailPill hex="#939DAD">
            <span className="font-mono">risk {Math.round(alert.riskScore)}</span>
          </RailPill>
        )}
      </div>

      <dl className="mt-4 grid grid-cols-[80px_1fr] gap-x-3 gap-y-2.5 text-[11px]">
        <dt className="text-fg-subtle">Source</dt>
        <dd className="text-fg-secondary break-words">{alert.source}</dd>
        <dt className="text-fg-subtle">Stage</dt>
        <dd className="text-fg-secondary">{alert.funnelStage ? alert.funnelStage.replace(/_/g, ' ') : '—'}</dd>
        <dt className="text-fg-subtle">Technique</dt>
        <dd className="text-fg-secondary">{technique ?? '—'}</dd>
        <dt className="text-fg-subtle">Time</dt>
        <dd className="text-fg-secondary" suppressHydrationWarning>
          {formatDistanceToNow(new Date(alert.createdAt), { addSuffix: true })}
        </dd>
      </dl>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onDeepExplain}
          aria-label="Open AI deep explain drawer"
          title="Run the LLM deep-explain for this alert"
          className="text-[11px] px-2.5 py-1 rounded-md border border-[#3163CF]/60 bg-[#3163CF]/10 text-[#3163CF] hover:bg-[#3163CF]/20 transition-colors"
        >
          ✦ Deep Explain
        </button>
        <Link
          href={`/alerts/${alert.id}`}
          className="text-[11px] px-2.5 py-1 rounded-md border border-teal-20/60 bg-teal-20/10 text-teal-10 hover:bg-teal-20/20 transition-colors"
        >
          Open full detail
        </Link>
      </div>
    </div>
  );
}

// ─── Sections ────────────────────────────────────────────────────────────────

function SectionHeader({ title, count }: { title: string; count?: number }) {
  return (
    <h3 className="text-[11px] text-fg-subtle mb-3">
      {title}
      {typeof count === 'number' && (
        <span className="ml-1">({count})</span>
      )}
    </h3>
  );
}

function NarrativeSection({ narrative }: { narrative: string | null }) {
  if (!narrative || !narrative.trim()) return null;
  // Markdown-light: we preserve newlines so the deterministic
  // paragraph + bullet structure produced by `narrative.build_narrative`
  // renders without us pulling in a full Markdown engine.
  return (
    <section className="px-4 py-4 border-b border-surface-border">
      <SectionHeader title="Narrative" />
      <p className="text-[11px] text-fg-secondary whitespace-pre-wrap break-words leading-relaxed">
        {narrative}
      </p>
    </section>
  );
}

function RelatedEntitiesSection({ entities }: { entities: RelatedEntity[] }) {
  if (entities.length === 0) return null;
  // Server already groups by kind in the canonical order, but defensively
  // re-group on the client so an out-of-order payload (older API) still
  // renders cleanly grouped.
  const grouped = entities.reduce<Record<RelatedEntity['kind'], RelatedEntity[]>>(
    (acc, e) => {
      (acc[e.kind] ||= []).push(e);
      return acc;
    },
    { principal: [], network: [], workflow: [], tenant: [] },
  );
  return (
    <section className="px-4 py-4 border-b border-surface-border min-w-0 max-w-full overflow-x-hidden">
      <SectionHeader title="Related entities" count={entities.length} />
      <div className="space-y-3 min-w-0 max-w-full">
        {(Object.keys(ENTITY_KIND_CONFIG) as Array<keyof typeof ENTITY_KIND_CONFIG>).map(
          (kind) => {
            const items = grouped[kind];
            if (!items || items.length === 0) return null;
            const cfg = ENTITY_KIND_CONFIG[kind];
            return (
              <div key={kind} className="min-w-0 max-w-full">
                <p className={clsx('text-[11px]', cfg.tone)}>{cfg.label}</p>
                {/*
                  Stack chips vertically. Horizontal flex-wrap still overflows
                  when a grid/flex ancestor keeps min-width:auto for long
                  monospace labels (rule titles, MITRE tactics).
                */}
                <ul className="mt-1.5 flex flex-col gap-1.5 w-full min-w-0 max-w-full">
                  {items.map((e) => (
                    <EntityChip key={`${e.type}:${e.value}`} entity={e} />
                  ))}
                </ul>
              </div>
            );
          },
        )}
      </div>
    </section>
  );
}

function EntityChip({ entity }: { entity: RelatedEntity }) {
  const display = entity.label || entity.value;
  const inner = (
    <span
      className={clsx(
        'flex w-full min-w-0 max-w-full items-baseline gap-1.5 text-[13px] px-3 py-2.5 rounded-lg border border-surface-border bg-surface-card text-fg-secondary box-border',
        entity.pivotPath &&
          'hover:border-teal-20/60 hover:text-fg-primary cursor-pointer transition-colors',
      )}
      title={`${entity.type}: ${entity.value}`}
    >
      <span className="shrink-0 text-fg-subtle text-[10px] leading-relaxed">
        {entity.type}
      </span>
      <span className="min-w-0 flex-1 break-all whitespace-normal leading-relaxed">
        {display}
      </span>
    </span>
  );
  return (
    <li className="w-full min-w-0 max-w-full list-none">
      {entity.pivotPath ? (
        <Link href={entity.pivotPath} className="block w-full min-w-0 max-w-full">
          {inner}
        </Link>
      ) : (
        inner
      )}
    </li>
  );
}

function MiniTimelineSection({ events }: { events: MiniTimelineEvent[] }) {
  if (events.length === 0) return null;
  return (
    <section className="px-4 py-4 border-b border-surface-border">
      <SectionHeader title="Recent events" count={events.length} />
      <ol className="space-y-2.5">
        {events.map((e) => (
          <TimelineRow key={e.id} event={e} />
        ))}
      </ol>
    </section>
  );
}

function TimelineRow({ event }: { event: MiniTimelineEvent }) {
  let ts: string;
  try {
    ts = format(new Date(event.timestamp), 'MMM d HH:mm');
  } catch {
    // Defensive: if the server hands back a malformed timestamp we still
    // render the row rather than crashing the rail.
    ts = event.timestamp;
  }
  return (
    <li className="text-xs text-fg-secondary border-l-2 border-teal-20/50 pl-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-fg-subtle text-[10px] tabular-nums" suppressHydrationWarning>
          {ts}
        </span>
        <span className="px-1.5 py-0 text-[10px] rounded-md border border-surface-border bg-surface-hover text-fg-muted uppercase">
          {event.source === 'case_timeline' ? 'case' : 'audit'}
        </span>
        <span className="text-[10px] uppercase text-fg-subtle tracking-wide">
          {event.type}
        </span>
      </div>
      <p className="mt-0.5 text-fg-primary break-words">{event.title}</p>
      {event.description && (
        <p className="mt-0.5 text-fg-muted line-clamp-2">{event.description}</p>
      )}
      {event.actor && (
        <p className="mt-0.5 text-[10px] text-fg-subtle">by {event.actor}</p>
      )}
    </li>
  );
}

function RecommendedActionsSection({ actions }: { actions: RecommendedAction[] }) {
  if (actions.length === 0) return null;
  return (
    <section className="px-4 py-4">
      <SectionHeader title="Recommended actions" count={actions.length} />
      <ul className="space-y-2">
        {actions.map((a, idx) => (
          <li
            key={`${a.action}-${idx}`}
            className="border border-surface-border bg-surface-card rounded-lg p-3"
          >
            <div className="flex items-start gap-2">
              <span
                className={clsx(
                  'text-[10px] uppercase px-1.5 py-0.5 rounded-md border shrink-0 mt-0.5',
                  PRIORITY_TONE[a.priority] ?? PRIORITY_TONE.medium,
                )}
              >
                {a.priority}
              </span>
              <p className="text-[13px] text-fg-primary flex-1 min-w-0 break-words">{a.action}</p>
            </div>
            {a.rationale && (
              <p className="mt-1 text-xs text-fg-muted ml-[3.25rem] break-words">
                {a.rationale}
              </p>
            )}
            {a.risk && (
              <p className="mt-1 text-xs text-[#D98A1E] ml-[3.25rem] break-words">
                Risk: {a.risk}
              </p>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
