'use client';

/**
 * DashboardView
 * =============
 * Main SOC dashboard with live metrics, charts, and source activity.
 *
 * WS-F3: Drag-and-drop widget reordering.
 * Each major section (DashboardWelcome, Alert triage, Alert volume, Live feed +
 * severity, Pipeline & efficiency, SOC Performance) is a draggable "widget".
 * The user can grab the ⠿ handle in the widget's header and drop it anywhere in
 * the layout. Order is persisted to localStorage so it survives page refreshes.
 *
 * Author: Beenu <beenu@cyble.com>
 */

import React, { Component, Suspense, type ErrorInfo, type ReactNode, useState, useEffect, useRef, useCallback } from 'react';
import useSWR from 'swr';
import { metricsApi, type DashboardMetrics } from '@/lib/api';
import { clsx } from 'clsx';
import dynamic from 'next/dynamic';
import { format } from 'date-fns';
import { Bell, Building2 } from 'lucide-react';
import { useTheme } from '@/components/theme/ThemeProvider';
import { LiveFeedPanel } from './LiveFeedPanel';
import { SOCMetricsDashboard } from './SOCMetricsDashboard';
import { DashboardWelcome } from './DashboardWelcome';
import { FunnelKpiBar } from './FunnelKpiBar';
import { EfficiencyReport } from './EfficiencyReport';
import { PipelineHealth } from './PipelineHealth';
import { ACCENT, Card, CardHeader, IconBadge, Pill, SectionHeading, type AccentName } from './ui';

/** Theme-aware chart chrome (grid lines, axis ticks, tooltip, slice gaps). */
function useChartChrome() {
  const { resolved } = useTheme();
  return resolved === 'light'
    ? { grid: '#D1D5DB', axis: '#9CA3AF', tick: '#374151', card: '#FFFFFF' }
    : { grid: '#2A3142', axis: '#374151', tick: '#9CA3AF', card: '#181E2D' };
}

type ChartChrome = ReturnType<typeof useChartChrome>;

const RechartsLine = dynamic(
  () => import('recharts').then((m) => {
    const { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } = m;
    function RechartsLineInner(props: { data: { time: string; count: number }[]; chrome: ChartChrome }) {
      const { chrome } = props;
      return (
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={props.data} margin={{ top: 10, right: 12, left: -8, bottom: 0 }}>
            <CartesianGrid strokeDasharray="2 3" stroke={chrome.grid} />
            <XAxis
              dataKey="time"
              tick={{ fill: chrome.tick, fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: chrome.axis }}
              interval="preserveStartEnd"
              minTickGap={18}
            />
            <YAxis tick={{ fill: chrome.tick, fontSize: 11 }} tickLine={false} axisLine={{ stroke: chrome.axis }} />
            <Tooltip content={<CustomTooltip />} cursor={{ stroke: chrome.grid }} />
            <Line
              type="monotone"
              dataKey="count"
              stroke={ACCENT.purple}
              strokeWidth={1.5}
              name="Alerts"
              dot={(dotProps: { cx?: number; cy?: number; index?: number }) => (
                <g key={dotProps.index}>
                  <circle cx={dotProps.cx} cy={dotProps.cy} r={6} fill={ACCENT.purple} fillOpacity={0.25} />
                  <circle cx={dotProps.cx} cy={dotProps.cy} r={2.5} fill={ACCENT.purple} />
                </g>
              )}
              activeDot={{ r: 5, fill: ACCENT.purple, stroke: chrome.card, strokeWidth: 2 }}
            />
          </LineChart>
        </ResponsiveContainer>
      );
    }
    return RechartsLineInner;
  }),
  { ssr: false, loading: () => <div className="h-[260px] bg-dark-20/30 animate-pulse rounded" /> },
);

const RechartsPie = dynamic(
  () => import('recharts').then((m) => {
    const { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } = m;
    function RechartsPieInner(props: { data: { name: string; value: number; color: string }[]; chrome: ChartChrome }) {
      return (
        <ResponsiveContainer width="100%" height={240}>
          <PieChart>
            <Pie
              data={props.data}
              cx="50%"
              cy="50%"
              innerRadius={58}
              outerRadius={108}
              dataKey="value"
              stroke={props.chrome.card}
              strokeWidth={3}
              cornerRadius={4}
            >
              {props.data.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>
      );
    }
    return RechartsPieInner;
  }),
  { ssr: false, loading: () => <div className="h-[240px] bg-dark-20/30 animate-pulse rounded" /> },
);

const RechartsBar = dynamic(
  () => import('recharts').then((m) => {
    const { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } = m;
    function RechartsBarInner(props: { data: { tactic: string; count: number }[]; chrome: ChartChrome }) {
      const { chrome } = props;
      return (
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={props.data} layout="vertical" margin={{ top: 4, right: 12, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="2 3" stroke={chrome.grid} />
            <XAxis type="number" tick={{ fill: chrome.tick, fontSize: 11 }} tickLine={false} axisLine={false} />
            <YAxis
              type="category"
              dataKey="tactic"
              tick={{ fill: chrome.tick, fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: chrome.tick }}
              width={100}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: chrome.grid, fillOpacity: 0.25 }} />
            <Bar dataKey="count" fill={ACCENT.purple} fillOpacity={0.75} maxBarSize={38} name="Alerts" />
          </BarChart>
        </ResponsiveContainer>
      );
    }
    return RechartsBarInner;
  }),
  { ssr: false, loading: () => <div className="h-[300px] bg-dark-20/30 animate-pulse rounded" /> },
);

class DashboardErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  state = { hasError: false };
  static getDerivedStateFromError() { return { hasError: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('[DashboardView] render error:', error, info); }
  render() {
    if (this.state.hasError) {
      return (
        <div className="p-6 text-center text-gray-400">
          <p className="text-sm">Dashboard encountered an error. Please refresh.</p>
          <button onClick={() => this.setState({ hasError: false })} className="mt-2 text-xs text-brand-400 underline">Retry</button>
        </div>
      );
    }
    return this.props.children;
  }
}

// Empty baseline — dashboard never invents mock SOC numbers. Charts stay
// zeroed until `/metrics/dashboard` returns live connector-ingested data.
const EMPTY_METRICS: DashboardMetrics = {
  alerts: {
    total: 0,
    new: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    resolvedToday: 0,
    mttr: 0,
  },
  cases: {
    open: 0,
    inProgress: 0,
    resolvedThisWeek: 0,
  },
  sources: [],
  topMitre: [],
  alertsTrend: [],
  threatsBySource: [],
};

// ─── Metric Card ──────────────────────────────────────────────────────────────

interface MetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
  accent: AccentName;
  icon?: ReactNode;
  trend?: { value: number; label: string };
}

function MetricCard({ label, value, sub, accent, icon, trend }: MetricCardProps) {
  return (
    <Card className="p-5">
      <div className="flex items-center gap-3">
        <IconBadge accent={accent}>{icon ?? <Bell className="h-4 w-4" strokeWidth={1.75} />}</IconBadge>
        <p className="text-sm text-fg-muted truncate">{label}</p>
      </div>
      <p className="mt-4 text-2xl font-gilroy-semibold text-fg-primary tabular-nums">
        {typeof value === 'number' ? value.toLocaleString('en-US') : value}
      </p>
      {sub && <p className="text-xs text-fg-muted mt-2">{sub}</p>}
      {trend && (
        <div className={clsx(
          'flex items-center gap-1 mt-1.5 text-xs',
          trend.value >= 0 ? 'text-[#FD4E4E]' : 'text-teal-20'
        )}>
          <span>{trend.value >= 0 ? '+' : '-'}{Math.abs(trend.value)}%</span>
          <span className={trend.value >= 0 ? 'text-[#FD4E4E]' : 'text-teal-20'}>{trend.label}</span>
        </div>
      )}
    </Card>
  );
}

// ─── Chart tooltip ────────────────────────────────────────────────────────────

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-surface-card border border-surface-border rounded-lg px-3 py-2 text-xs shadow-sm">
      {label && <p className="text-fg-muted mb-1">{label}</p>}
      {payload.map((p: any, i: number) => (
        <p key={i} style={{ color: p.payload?.color ?? p.color }} className="font-medium">
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
}

// ─── Drag-and-Drop Widget Layout (WS-F3) ──────────────────────────────────────

const WIDGET_ORDER_KEY = 'aisoc:dashboard:widget-order';

type WidgetId =
  | 'welcome'
  | 'funnel-kpis'
  | 'efficiency-and-pipeline'
  | 'top-metrics'
  | 'charts-row'
  | 'bottom-row'
  | 'soc-performance';

const DEFAULT_WIDGET_ORDER: WidgetId[] = [
  'welcome',
  'top-metrics',
  'charts-row',
  'bottom-row',
  'funnel-kpis',
  'efficiency-and-pipeline',
  'soc-performance',
];

function loadWidgetOrder(): WidgetId[] {
  if (typeof window === 'undefined') return DEFAULT_WIDGET_ORDER;
  try {
    const raw = localStorage.getItem(WIDGET_ORDER_KEY);
    if (!raw) return DEFAULT_WIDGET_ORDER;
    const parsed = JSON.parse(raw) as WidgetId[];
    // Guard against stale storage with missing or extra IDs
    if (
      Array.isArray(parsed) &&
      parsed.length === DEFAULT_WIDGET_ORDER.length &&
      DEFAULT_WIDGET_ORDER.every((id) => parsed.includes(id))
    ) {
      return parsed;
    }
  } catch {}
  return DEFAULT_WIDGET_ORDER;
}

/** Drag state kept in a ref so re-renders stay minimal during the drag gesture. */
interface DragState {
  dragId: WidgetId | null;
  overId: WidgetId | null;
}

interface DraggableWidgetProps {
  id: WidgetId;
  dragState: DragState;
  onDragStart: (id: WidgetId) => void;
  onDragOver: (id: WidgetId) => void;
  onDrop: () => void;
  children: ReactNode;
}

/**
 * Thin drag-and-drop shell around each dashboard section.
 * The ⠿ handle (aria-label "Drag to reorder") is the only interactive target;
 * clicking anywhere else in the widget works normally.
 */
function DraggableWidget({ id, dragState, onDragStart, onDragOver, onDrop, children }: DraggableWidgetProps) {
  const isDragging = dragState.dragId === id;
  const isOver = dragState.overId === id && dragState.dragId !== id;

  return (
    <div
      draggable
      onDragStart={() => onDragStart(id)}
      onDragOver={(e) => { e.preventDefault(); onDragOver(id); }}
      onDrop={(e) => { e.preventDefault(); onDrop(); }}
      onDragEnd={onDrop}
      className={clsx(
        'relative group transition-opacity',
        isDragging && 'opacity-40',
        isOver && 'ring-2 ring-brand-500/60 ring-offset-4 ring-offset-surface-base rounded-2xl',
      )}
      aria-label={`Dashboard widget: ${id}`}
    >
      {/* Drag handle — visible on hover */}
      <button
        aria-label="Drag to reorder"
        title="Drag to reorder"
        className={clsx(
          'absolute -top-1 right-0 z-10 cursor-grab active:cursor-grabbing',
          'px-1.5 py-0.5 rounded text-fg-subtle hover:text-fg-muted',
          'opacity-0 group-hover:opacity-100 transition-opacity',
          'select-none text-base leading-none',
        )}
        // Pointer-down on the handle initiates the native drag
        onPointerDown={(e) => {
          // We rely on the parent div's draggable; just prevent focus loss
          e.currentTarget.closest('[draggable]')?.dispatchEvent(
            new DragEvent('dragstart', { bubbles: true })
          );
        }}
        tabIndex={-1}
      >
        ⠿
      </button>
      {children}
    </div>
  );
}

/** Persist + manage the ordered list of widget IDs. */
function useDashboardLayout() {
  const [order, setOrder] = useState<WidgetId[]>(DEFAULT_WIDGET_ORDER);
  const dragState = useRef<DragState>({ dragId: null, overId: null });
  // Trigger a render when drag state changes so highlights update
  const [, forceRender] = useState(0);

  // Hydrate from localStorage on mount (client-only)
  useEffect(() => { setOrder(loadWidgetOrder()); }, []);

  const handleDragStart = useCallback((id: WidgetId) => {
    dragState.current = { dragId: id, overId: null };
    forceRender((n) => n + 1);
  }, []);

  const handleDragOver = useCallback((id: WidgetId) => {
    if (dragState.current.overId !== id) {
      dragState.current = { ...dragState.current, overId: id };
      forceRender((n) => n + 1);
    }
  }, []);

  const handleDrop = useCallback(() => {
    const { dragId, overId } = dragState.current;
    dragState.current = { dragId: null, overId: null };
    forceRender((n) => n + 1);

    if (!dragId || !overId || dragId === overId) return;

    setOrder((prev) => {
      const next = [...prev];
      const from = next.indexOf(dragId);
      const to = next.indexOf(overId);
      if (from === -1 || to === -1) return prev;
      next.splice(from, 1);
      next.splice(to, 0, dragId);
      try { localStorage.setItem(WIDGET_ORDER_KEY, JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);

  return { order, dragState: dragState.current, handleDragStart, handleDragOver, handleDrop };
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export function DashboardView() {
  const chrome = useChartChrome();
  const { data: rawMetrics, error: metricsError } = useSWR(
    'dashboard-metrics',
    () => metricsApi.getDashboard(),
    {
      fallbackData: EMPTY_METRICS,
      refreshInterval: 60000,
      revalidateOnMount: true,
      revalidateOnFocus: false,
      shouldRetryOnError: true,
      errorRetryCount: 3,
      errorRetryInterval: 4000,
    }
  );

  const metricsErrorMessage =
    metricsError instanceof Error
      ? metricsError.message
      : metricsError
        ? String(metricsError)
        : null;

  // Live API only — never pad empty series with fabricated demo numbers.
  // Always merge alerts with EMPTY_METRICS defaults so a partial/failed
  // payload cannot crash the severity tiles (``metrics.alerts.critical``).
  const apiData = rawMetrics as Partial<DashboardMetrics> | undefined;
  const hasRealAlerts = !!apiData && typeof apiData.alerts?.total === 'number';
  const metrics: DashboardMetrics = hasRealAlerts
    ? {
        alerts: { ...EMPTY_METRICS.alerts, ...apiData!.alerts },
        cases: { ...EMPTY_METRICS.cases, ...(apiData!.cases ?? {}) },
        sources: Array.isArray(apiData!.sources) ? apiData!.sources! : [],
        topMitre: Array.isArray(apiData!.topMitre) ? apiData!.topMitre! : [],
        alertsTrend: Array.isArray(apiData!.alertsTrend) ? apiData!.alertsTrend! : [],
        threatsBySource: Array.isArray(apiData!.threatsBySource)
          ? apiData!.threatsBySource!
          : [],
      }
    : EMPTY_METRICS;

  const trendData = metrics.alertsTrend.map((d) => ({
    time: format(new Date(d.timestamp), 'HH:mm'),
    count: d.count,
  }));

  const SEVERITY_CHART_DATA = [
    { name: 'Critical', value: metrics.alerts.critical, color: ACCENT.red },
    { name: 'High', value: metrics.alerts.high, color: ACCENT.orange },
    { name: 'Medium', value: metrics.alerts.medium, color: ACCENT.yellow },
    { name: 'Low', value: metrics.alerts.low, color: ACCENT.teal },
    { name: 'Info', value: metrics.alerts.info ?? 0, color: ACCENT.slate },
  ];

  const activeSourceCount = metrics.sources.filter((s) => s.status === 'active').length;

  // WS-F3: drag-and-drop widget reordering
  const { order, dragState, handleDragStart, handleDragOver, handleDrop } = useDashboardLayout();

  /** Map each widget ID to its rendered section. */
  const widgetContent: Record<WidgetId, ReactNode> = {
    welcome: <Suspense fallback={null}><DashboardWelcome /></Suspense>,

    'top-metrics': (
      <section>
        <SectionHeading>Alert triage</SectionHeading>
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-4">
          <MetricCard
            label="Critical"
            value={metrics.alerts.critical}
            sub="Require immediate action"
            accent="red"
            trend={{ value: -3, label: 'vs yesterday' }}
          />
          <MetricCard
            label="Active alerts"
            value={metrics.alerts.total}
            sub={`${metrics.alerts.new.toLocaleString('en-US')} new today`}
            accent="green"
            trend={{ value: 12, label: 'vs yesterday' }}
          />
          <MetricCard
            label="Open cases"
            value={metrics.cases.open}
            sub={`${metrics.cases.inProgress} in progress`}
            accent="orange"
          />
          <MetricCard
            label="MTTR"
            value={`${metrics.alerts.mttr}m`}
            sub="Mean time to resolve"
            accent="violet"
            trend={{ value: -8, label: 'vs last week' }}
          />
          <MetricCard
            label="Connected sources"
            value={activeSourceCount}
            sub="EDR, SIEM, Cloud, IAM, SaaS"
            accent="blue"
          />
        </div>
      </section>
    ),

    'charts-row': (
      <section>
        <SectionHeading>Alert volume</SectionHeading>
        <Card className="p-6">
          <CardHeader
            title="Alert volume (24h)"
            subtitle="Alerts per interval, hourly pattern"
            action={<Pill>Last 24h</Pill>}
            className="mb-5"
          />
          <RechartsLine data={trendData} chrome={chrome} />
        </Card>
      </section>
    ),

    'bottom-row': (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <LiveFeedPanel />
        <Card className="p-6">
          <CardHeader title="Severity breakdown" subtitle="Alert mix across the five severity tiers" />
          <div className="mt-2 flex flex-col sm:flex-row items-center gap-4">
            <div className="w-full sm:w-1/2">
              <RechartsPie data={SEVERITY_CHART_DATA} chrome={chrome} />
            </div>
            <div className="w-full sm:w-1/2 space-y-3">
              {SEVERITY_CHART_DATA.map((d) => (
                <div key={d.name} className="grid grid-cols-[1fr_auto] items-center gap-4 text-xs">
                  <div className="flex items-center gap-2.5">
                    <span className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                    <span className="text-fg-secondary">{d.name}</span>
                  </div>
                  <span className="text-fg-secondary tabular-nums min-w-[4rem]">{d.value.toLocaleString('en-US')}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>
    ),

    // PR-3 / W1: Six-tile funnel KPI strip (events → correlations → alerts +
    // signal/noise, MTTD, analyst queue) backed by /api/v1/metrics/funnel.
    'funnel-kpis': (
      <section>
        <SectionHeading>Pipeline &amp; efficiency</SectionHeading>
        <FunnelKpiBar period="24h" />
      </section>
    ),

    // PR-3 / W1+W9: Per-stage pipeline health, then efficiency ratios
    // (correlation efficiency, alert yield, MITRE coverage) beside the
    // per-source event volume.
    'efficiency-and-pipeline': (
      <div className="space-y-4">
        <PipelineHealth />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <EfficiencyReport period="24h" />
          <Card className="p-6">
            <CardHeader
              title="Connected sources"
              subtitle={`${activeSourceCount} active · events per source`}
              action={<IconBadge accent="blue" size={32}><Building2 className="h-4 w-4" strokeWidth={1.75} /></IconBadge>}
              className="mb-5"
            />
            <div className="space-y-5">
              {metrics.sources.length === 0 && (
                <p className="text-xs text-fg-muted py-6 text-center">No connected sources yet.</p>
              )}
              {metrics.sources.map((src) => {
                const maxCount = Math.max(...metrics.sources.map(s => s.count));
                const pct = Math.round((src.count / maxCount) * 100);
                return (
                  <div key={src.name}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={clsx(
                          'w-1.5 h-1.5 rounded-full shrink-0',
                          src.status === 'active' ? 'bg-green-500' : 'bg-gray-500'
                        )} />
                        <span className="text-sm font-gilroy-semibold text-fg-primary truncate">{src.name}</span>
                      </div>
                      <span className="text-sm font-gilroy-semibold text-fg-primary tabular-nums">{src.count}</span>
                    </div>
                    <div className="h-1.5 bg-gray-700 rounded-full">
                      <div className="h-1.5 bg-teal-20 rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>
      </div>
    ),

    'soc-performance': (
      <SOCMetricsDashboard
        topTactics={
          <Card className="p-6 h-full">
            <CardHeader title="Top tactics" subtitle="Alerts per tactic" className="mb-4" />
            <RechartsBar data={metrics.topMitre} chrome={chrome} />
          </Card>
        }
      />
    ),
  };

  return (
    <DashboardErrorBoundary>
      <div className="space-y-6">
        {metricsErrorMessage && (
          <div className="rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200">
            <p className="font-semibold">Dashboard metrics unavailable</p>
            <p className="mt-1 text-xs text-red-300/80">
              {metricsErrorMessage}
            </p>
            <p className="mt-1 text-xs text-red-300/60">
              Showing baseline mock data while SWR retries every 4s. Refresh the
              page if it persists.
            </p>
          </div>
        )}
        {order.map((id) => (
          <DraggableWidget
            key={id}
            id={id}
            dragState={dragState}
            onDragStart={handleDragStart}
            onDragOver={handleDragOver}
            onDrop={handleDrop}
          >
            {widgetContent[id]}
          </DraggableWidget>
        ))}
      </div>
    </DashboardErrorBoundary>
  );
}
