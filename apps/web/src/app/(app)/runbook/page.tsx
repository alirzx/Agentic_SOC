'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { Search, ChevronDown } from 'lucide-react';
import { useSearchParams } from 'next/navigation';
import { AutomationRulesView } from '@/components/runbook/AutomationRulesView';
import { GovernanceView } from '@/components/runbook/GovernanceView';
import { ActionPlanView } from '@/components/runbook/ActionPlanView';
import { DetectionFuseView } from '@/components/runbook/DetectionFuseView';
import { RunbookPage } from '@/components/runbook/RunbookPage';
import { request } from '@/lib/api';
import type {
  RunbookEnvelope,
  RunbookTaskType,
} from '@/components/runbook/runbook.types';

type Tab = 'ledger' | 'detect' | 'action-plan' | 'automation' | 'governance';

/** Where each Runbook tab sits in the Workflow SOC lifecycle it enforces. */
const LIFECYCLE_STAGE: Record<Tab, string> = {
  ledger: 'investigate',
  detect: 'detect',
  'action-plan': 'decide',
  automation: 'detect',
  governance: 'respond',
};

const TASK_TYPES: RunbookTaskType[] = ['manual_review', 'approval_gate', 'mssp_sla_check'];

const TAB_META: Record<Tab, { label: string; title: string }> = {
  ledger: {
    label: 'Ledger',
    title: 'Governed action history: who acted, why it was allowed, and the outcome.',
  },
  detect: {
    label: 'Detect & Fuse',
    title: 'How the most recent alerts were produced: detection rule, source, dedup, and what fusion did with them.',
  },
  'action-plan': {
    label: 'Action Plan',
    title: 'Manual tasks awaiting analyst action: needs_review verdicts, approval gates, MSSP SLAs.',
  },
  automation: {
    label: 'Automation Rules',
    title: 'Trigger-based rules that fire on alert/case events and record governed actions in the ledger.',
  },
  governance: {
    label: 'Governance',
    title: 'Full action catalog: blast radii, autonomy thresholds, and all four execution contracts.',
  },
};

const SUBJECT_TYPES = ['alert', 'case', 'incident'] as const;
type SubjectType = typeof SUBJECT_TYPES[number];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface RecentItem { id: string; title: string; severity?: string; }

export default function RunbookIndexPage() {
  const searchParams = useSearchParams();
  const [tab, setTab] = useState<Tab>('ledger');
  const [taskTypeFilter, setTaskTypeFilter] = useState<RunbookTaskType | null>(null);
  const [subjectType, setSubjectType] = useState<SubjectType>('alert');
  const [subjectId, setSubjectId] = useState('');
  const [resolvedSubject, setResolvedSubject] = useState<{ type: SubjectType; id: string } | null>(null);
  const [idError, setIdError] = useState<string | null>(null);
  const [recentItems, setRecentItems] = useState<RecentItem[]>([]);
  const [showPicker, setShowPicker] = useState(false);

  // Auto-populate from URL query: /runbook?type=alert&id=<uuid>
  // and the Workflow SOC deep links: /runbook?tab=action-plan&task_type=<type>
  useEffect(() => {
    const urlTab = searchParams.get('tab') as Tab | null;
    if (urlTab && urlTab in TAB_META) {
      setTab(urlTab);
      const urlTaskType = searchParams.get('task_type') as RunbookTaskType | null;
      if (urlTaskType && TASK_TYPES.includes(urlTaskType)) {
        setTaskTypeFilter(urlTaskType);
      }
    }

    const urlType = searchParams.get('type') as SubjectType | null;
    const urlId = searchParams.get('id') ?? '';
    if (urlType && SUBJECT_TYPES.includes(urlType) && UUID_RE.test(urlId)) {
      setSubjectType(urlType);
      setSubjectId(urlId);
      setTab('ledger');
      setResolvedSubject({ type: urlType, id: urlId });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Fetch recent items when the picker opens
  useEffect(() => {
    if (!showPicker || recentItems.length > 0) return;
    const ep = subjectType === 'alert'
      ? '/api/v1/alerts?page=1&page_size=20'
      : '/api/v1/cases?page=1&page_size=20';
    request<Record<string, unknown>>(ep)
      .then((d) => {
        const raw = (d.items ?? d.alerts ?? []) as Record<string, unknown>[];
        setRecentItems(
          raw.slice(0, 15).map((a) => ({
            id: String(a.id ?? ''),
            title: String(a.title ?? (a.id as string ?? '').slice(0, 8)),
            severity: a.severity ? String(a.severity) : undefined,
          }))
        );
      })
      .catch(() => { /* picker is optional UX — fail silently */ });
  }, [showPicker, subjectType, recentItems.length]);

  const handleViewLedger = () => {
    const trimmed = subjectId.trim();
    if (!UUID_RE.test(trimmed)) {
      setIdError('Must be a valid UUID (e.g. 4eb8b17b-0000-0000-0000-000000000000)');
      return;
    }
    setIdError(null);
    setResolvedSubject({ type: subjectType, id: trimmed });
  };

  const pickItem = (item: RecentItem) => {
    setSubjectId(item.id);
    setShowPicker(false);
    setIdError(null);
    setResolvedSubject({ type: subjectType, id: item.id });
  };

  const fetchRunbook = (type: SubjectType, id: string) => () =>
    request<RunbookEnvelope>(`/api/v1/runbook/${type}/${id}`);

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">Runbook Console</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Governed action ledger, automation rules, and the full action catalog.
          </p>
        </div>
        <Link
          href={`/workflow-soc?stage=${LIFECYCLE_STAGE[tab]}`}
          title="Where this surface sits in the end-to-end Agentic SOC lifecycle"
          className="inline-flex items-center gap-1.5 rounded-md bg-slate-800/60 px-3 py-1.5 text-xs text-slate-300 ring-1 ring-slate-700/60 transition-colors hover:bg-slate-800 hover:text-slate-100"
        >
          View lifecycle →
        </Link>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-slate-800/60">
        {(Object.keys(TAB_META) as Tab[]).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            title={TAB_META[t].title}
            className={[
              'px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px',
              tab === t
                ? 'text-blue-400 border-blue-400'
                : 'text-slate-500 border-transparent hover:text-slate-300',
            ].join(' ')}
          >
            {TAB_META[t].label}
          </button>
        ))}
      </div>

      {/* ── Ledger tab ───────────────────────────────────────────────────────── */}
      {tab === 'ledger' && (
        <div className="space-y-4">
          {/* Subject selector */}
          <div className="rounded-lg border border-slate-800/60 bg-slate-950/30 p-4 space-y-3">
            <div>
              <p className="text-xs font-medium text-slate-300 mb-0.5">View ledger for a subject</p>
              <p className="text-[10px] text-slate-500">
                Enter a UUID or click ▾ to browse recent items. The Ledger shows every governed
                action — who acted, which policy allowed it, and the outcome.
              </p>
            </div>
            <div className="flex flex-col sm:flex-row gap-2">
              <select
                value={subjectType}
                onChange={(e) => {
                  setSubjectType(e.target.value as SubjectType);
                  setResolvedSubject(null);
                  setRecentItems([]);
                }}
                className="bg-slate-800/60 border border-slate-700/60 rounded px-2.5 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500/50"
              >
                {SUBJECT_TYPES.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>

              <div className="relative flex-1">
                <input
                  type="text"
                  value={subjectId}
                  onChange={(e) => {
                    setSubjectId(e.target.value);
                    setIdError(null);
                    if (resolvedSubject) setResolvedSubject(null);
                  }}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleViewLedger(); }}
                  placeholder="UUID — or click ▾ to browse recent"
                  className="w-full bg-slate-800/60 border border-slate-700/60 rounded px-2.5 py-1.5 pr-8 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50"
                />
                <button
                  type="button"
                  onClick={() => { setShowPicker((v) => !v); setRecentItems([]); }}
                  title="Browse recent items"
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  <ChevronDown className="h-3.5 w-3.5" />
                </button>

                {showPicker && (
                  <div className="absolute z-10 left-0 right-0 top-full mt-1 rounded-lg border border-slate-700/60 bg-slate-900 shadow-xl max-h-56 overflow-auto">
                    {recentItems.length === 0 && (
                      <p className="px-3 py-2 text-xs text-slate-500">Loading recent {subjectType}s…</p>
                    )}
                    {recentItems.map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => pickItem(item)}
                        className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-slate-800/60 transition-colors"
                      >
                        <div className="flex-1 min-w-0">
                          <p className="text-xs text-slate-200 truncate">{item.title}</p>
                          <p className="text-[10px] text-slate-600 font-mono">{item.id.slice(0, 8)}…</p>
                        </div>
                        {item.severity && (
                          <span className="text-[10px] text-slate-500 shrink-0">{item.severity}</span>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={handleViewLedger}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-blue-600/80 hover:bg-blue-600 text-white rounded transition-colors"
              >
                <Search className="h-3.5 w-3.5" />
                View
              </button>
            </div>
            {idError && (
              <p className="text-[10px] text-red-400">{idError}</p>
            )}
          </div>

          {/* Resolved ledger */}
          {resolvedSubject ? (
            <RunbookPage
              subjectType={resolvedSubject.type}
              subjectId={resolvedSubject.id}
              fetchRunbook={fetchRunbook(resolvedSubject.type, resolvedSubject.id)}
            />
          ) : (
            <div className="rounded-lg border border-slate-800/60 bg-slate-950/20 p-6 space-y-3">
              <p className="text-sm text-slate-400">
                The Runbook Ledger (L5) records every governed action taken against an alert or
                case — who acted, which policy allowed it, and the outcome.
              </p>
              <p className="text-xs text-slate-600">
                You can also click{' '}
                <span className="text-slate-400 font-medium">Runbook →</span>{' '}
                on any alert row, or navigate to{' '}
                <span className="font-mono">/runbook?type=alert&amp;id=&lt;uuid&gt;</span>.
              </p>
              <div className="flex flex-wrap gap-3">
                <Link
                  href="/alerts"
                  className="inline-flex items-center gap-1.5 rounded-md bg-slate-800/60 px-3 py-1.5 text-xs text-slate-300 ring-1 ring-slate-700/60 hover:bg-slate-800 hover:text-slate-100 transition-colors"
                >
                  Open Alerts →
                </Link>
                <Link
                  href="/cases"
                  className="inline-flex items-center gap-1.5 rounded-md bg-slate-800/60 px-3 py-1.5 text-xs text-slate-300 ring-1 ring-slate-700/60 hover:bg-slate-800 hover:text-slate-100 transition-colors"
                >
                  Open Cases →
                </Link>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Detect & Fuse tab (Workflow SOC stage 02) ────────────────────────── */}
      {tab === 'detect' && <DetectionFuseView />}

      {/* ── Automation Rules tab ─────────────────────────────────────────────── */}
      {tab === 'automation' && <AutomationRulesView />}

      {/* ── Action Plan tab ──────────────────────────────────────────────────── */}
      {tab === 'action-plan' && (
        <div className="space-y-4">
          <ActionPlanView
            subject_type={resolvedSubject?.type}
            subject_id={resolvedSubject?.id}
            task_type={taskTypeFilter ?? undefined}
          />
        </div>
      )}

      {/* ── Governance tab ───────────────────────────────────────────────────── */}
      {tab === 'governance' && <GovernanceView />}
    </div>
  );
}
