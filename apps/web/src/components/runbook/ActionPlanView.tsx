/**
 * ActionPlanView — the human half of the Runbook control plane.
 *
 * Auto-triage clears the routine path on its own. What lands here is only what
 * the engine could not (or must not) finish alone:
 *
 *   manual_review   — the model was not confident enough to decide
 *   approval_gate   — a governed action is blocked by the autonomy ceiling
 *   mssp_sla_check  — a customer obligation (no SLA source exists yet, so these
 *                     are shown read-only rather than faked into a deadline)
 *
 * Each task type gets the actions that actually resolve it. Model feedback is
 * optional: an analyst approving a blocked action is a governance decision, not
 * a grade of the model.
 */

'use client';

import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  ExternalLink,
  Loader,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { feedbackApi, realtimeApi } from '@/lib/api';
import { RunbookModal } from '@/components/runbook/RunbookModal';
import type {
  RunbookFeedbackStats,
  RunbookTask,
  RunbookTaskStatus,
  RunbookTaskType,
} from '@/components/runbook/runbook.types';

interface ActionPlanViewProps {
  subject_type?: 'alert' | 'case' | 'incident';
  subject_id?: string;
  /**
   * Pre-scope the queue to one task type. The Workflow SOC lifecycle deep-links
   * here for "Verdict & Copilot" (manual_review) and "Approved Response"
   * (approval_gate), so the stage a manager is looking at is the stage whose
   * tasks actually open. Clearing the filter is a local action, not a navigation.
   */
  task_type?: RunbookTaskType;
}

type Feedback = '' | 'good' | 'poor';
type AnalystVerdict = 'true_positive' | 'false_positive' | 'escalate';

const TASK_LABELS: Record<RunbookTaskType, string> = {
  manual_review: 'Manual review',
  approval_gate: 'Approval gate',
  mssp_sla_check: 'SLA check',
};

const TASK_CHIPS: Record<RunbookTaskType, string> = {
  manual_review: 'text-blue-300 bg-blue-500/10 border-blue-500/20',
  approval_gate: 'text-amber-300 bg-amber-500/10 border-amber-500/20',
  mssp_sla_check: 'text-purple-300 bg-purple-500/10 border-purple-500/20',
};

function errMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

export function ActionPlanView({ subject_type, subject_id, task_type }: ActionPlanViewProps) {
  const [tasks, setTasks] = useState<RunbookTask[]>([]);
  const [stats, setStats] = useState<RunbookFeedbackStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedCompleted, setExpandedCompleted] = useState(false);
  const [activeTask, setActiveTask] = useState<RunbookTask | null>(null);
  const [resolution, setResolution] = useState('');
  const [feedback, setFeedback] = useState<Feedback>('');
  const [busyTaskId, setBusyTaskId] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<RunbookTaskType | null>(task_type ?? null);
  const wsRef = useRef<WebSocket | null>(null);

  const query = useMemo(() => {
    const params = new URLSearchParams();
    if (subject_id && subject_type === 'alert') params.set('alert_id', subject_id);
    if (subject_id && subject_type === 'case') params.set('case_id', subject_id);
    if (typeFilter) params.set('task_type', typeFilter);
    return params.toString();
  }, [subject_type, subject_id, typeFilter]);

  const load = useCallback(async () => {
    setError(null);
    try {
      const response = await fetch(`/api/v1/runbook/tasks${query ? `?${query}` : ''}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = (await response.json()) as RunbookTask[];
      setTasks(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(errMessage(err, 'Failed to load tasks'));
    } finally {
      setLoading(false);
    }
  }, [query]);

  /**
   * The loop metric. Informational only: if it fails we keep the last numbers
   * (or nothing) rather than rendering zeros that look like a measured result.
   */
  const loadStats = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/runbook/stats');
      if (!response.ok) return;
      setStats((await response.json()) as RunbookFeedbackStats);
    } catch {
      // Leave whatever was last known on screen.
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    void load();
    void loadStats();
  }, [load, loadStats]);

  // Live updates: the triage worker creates tasks while this page is open.
  useEffect(() => {
    let cancelled = false;

    const subscribe = async () => {
      try {
        const ticket = await realtimeApi.ticket();
        if (cancelled) return;
        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const socket = new WebSocket(
          `${protocol}://${window.location.host}/ws/runbook?token=${encodeURIComponent(ticket.token)}`,
        );
        wsRef.current = socket;

        socket.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data) as {
              type?: string;
              payload?: RunbookTask;
            };
            const payload = message.payload;
            if (!payload?.id) return;
            if (message.type === 'runbook.task_created') {
              setTasks((prev) => (prev.some((t) => t.id === payload.id) ? prev : [payload, ...prev]));
            } else if (
              message.type === 'runbook.task_updated' ||
              message.type === 'runbook.task_completed'
            ) {
              setTasks((prev) => prev.map((t) => (t.id === payload.id ? payload : t)));
            }
          } catch {
            // A malformed frame must not break the queue view.
          }
        };

        socket.onclose = () => {
          wsRef.current = null;
        };
      } catch {
        // Realtime is a nice-to-have; the list still loads over HTTP.
      }
    };

    void subscribe();
    return () => {
      cancelled = true;
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, []);

  const openTask = (task: RunbookTask) => {
    setActiveTask(task);
    setResolution('');
    setFeedback('');
    setError(null);
  };

  const completeTask = useCallback(
    async (
      task: RunbookTask,
      payload: {
        resolution: string;
        feedback: Feedback;
        /** Explicit for gate tasks: approving releases the guarded steps. */
        decision?: 'approve' | 'reject';
      },
    ) => {
      setBusyTaskId(task.id);
      setError(null);
      try {
        const response = await fetch(`/api/v1/runbook/tasks/${task.id}/complete`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            resolution: payload.resolution || null,
            feedback_to_llm: payload.feedback || null,
            ...(payload.decision ? { decision: payload.decision } : {}),
          }),
        });
        if (!response.ok) {
          // A 403 here means the role lacks `playbooks:approve`, and a 422 means
          // the gate was submitted without a decision. Say which, rather than
          // leaving the analyst with a bare status code.
          const detail = await response
            .json()
            .then((body: unknown) =>
              typeof (body as { detail?: unknown })?.detail === 'string'
                ? (body as { detail: string }).detail
                : null,
            )
            .catch(() => null);
          throw new Error(detail ? `HTTP ${response.status} — ${detail}` : `HTTP ${response.status}`);
        }
        const updated = (await response.json()) as RunbookTask;
        setTasks((prev) => prev.map((t) => (t.id === updated.id ? updated : t)));
        setActiveTask(null);
        // A completion can move the prior count, so refresh the funnel.
        void loadStats();
      } catch (err) {
        setError(errMessage(err, 'Failed to complete task'));
      } finally {
        setBusyTaskId(null);
      }
    },
    [loadStats],
  );

  /** manual_review: the analyst's verdict is also the correction signal. */
  const submitVerdict = useCallback(
    async (task: RunbookTask, verdict: AnalystVerdict) => {
      setBusyTaskId(task.id);
      setError(null);
      try {
        if (!task.alert_id) throw new Error('Task has no alert to correct');
        await feedbackApi.submitOverride({
          alert_id: task.alert_id,
          // This task is only ever created for a needs_review verdict, so that
          // is the verdict being overridden.
          original_verdict: 'needs_review',
          corrected_verdict: verdict,
          reason: resolution.trim() || undefined,
        });
        await completeTask(task, {
          resolution: resolution.trim() || `Analyst verdict: ${verdict}`,
          feedback,
        });
      } catch (err) {
        setError(errMessage(err, 'Failed to record verdict'));
        setBusyTaskId(null);
      }
    },
    [completeTask, feedback, resolution],
  );

  const pending = tasks.filter((task) => task.status !== 'completed');
  const completed = tasks.filter((task) => task.status === 'completed');

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-10 text-slate-500">
        <Loader className="h-4 w-4 animate-spin" />
        <span className="text-xs">Loading tasks…</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {error && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded border border-red-500/25 bg-red-500/10 px-3 py-2 text-xs text-red-300"
        >
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {stats && stats.tasks_total > 0 && <FeedbackLoopStrip stats={stats} />}

      {typeFilter && (
        <div className="flex items-center gap-2 text-[11px] text-slate-400">
          <span>
            Showing only{' '}
            <span className="text-slate-200">{TASK_LABELS[typeFilter]}</span> tasks
          </span>
          <button
            type="button"
            onClick={() => setTypeFilter(null)}
            className="rounded border border-slate-700/60 px-1.5 py-0.5 text-[10px] text-slate-400 transition-colors hover:text-slate-200"
          >
            Show all
          </button>
        </div>
      )}

      {tasks.length === 0 && !error && (
        <div className="rounded-lg border border-slate-800/60 bg-slate-950/20 p-6 text-center">
          <CheckCircle2 className="mx-auto mb-2 h-7 w-7 text-emerald-500/70" />
          <p className="text-sm text-slate-300">
            {typeFilter
              ? `No ${TASK_LABELS[typeFilter].toLowerCase()} tasks waiting`
              : 'Nothing waiting on you'}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {typeFilter
              ? `This view is scoped to one task type. Other task types may still be waiting.`
              : 'Auto-triage is handling current alerts. Tasks appear here when a verdict needs a human, or a governed action is blocked by the autonomy ceiling.'}
          </p>
        </div>
      )}

      {pending.length > 0 && (
        <section className="space-y-2">
          <h3 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
            <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />
            Waiting on you ({pending.length})
          </h3>
          {pending.map((task) => (
            <TaskCard
              key={task.id}
              task={task}
              busy={busyTaskId === task.id}
              onOpen={() => openTask(task)}
            />
          ))}
        </section>
      )}

      {completed.length > 0 && (
        <section>
          <button
            type="button"
            onClick={() => setExpandedCompleted((value) => !value)}
            className="flex w-full items-center justify-between rounded-lg border border-slate-800/60 bg-slate-900/40 px-3 py-2 text-xs font-medium text-slate-400 transition-colors hover:text-slate-200"
          >
            <span>Completed ({completed.length})</span>
            {expandedCompleted ? (
              <ChevronUp className="h-3.5 w-3.5" />
            ) : (
              <ChevronDown className="h-3.5 w-3.5" />
            )}
          </button>
          {expandedCompleted && (
            <div className="mt-2 space-y-2">
              {completed.map((task) => (
                <div
                  key={task.id}
                  className="rounded-lg border border-slate-800/50 bg-slate-950/20 px-3 py-2 text-xs"
                >
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500/80" />
                    <span className="text-slate-300">{task.title}</span>
                    {task.completed_at && (
                      <span className="ml-auto text-[10px] text-slate-600">
                        {new Date(task.completed_at).toLocaleString()}
                      </span>
                    )}
                  </div>
                  {task.resolution && (
                    <p className="mt-1 text-slate-500">
                      <span className="text-slate-600">Resolution: </span>
                      {task.resolution}
                    </p>
                  )}
                  {task.resume_applied !== null && task.resume_applied !== undefined && (
                    <ResumeOutcome applied={task.resume_applied} />
                  )}
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Completion surface */}
      <RunbookModal
        open={activeTask !== null}
        onClose={() => setActiveTask(null)}
        title={activeTask ? activeTask.title : 'Task'}
        subtitle={
          activeTask
            ? `${TASK_LABELS[activeTask.task_type]}${activeTask.alert_id ? ' · linked to an alert' : ''}`
            : undefined
        }
        size="md"
      >
        {activeTask && (
          <div className="space-y-4">
            {activeTask.description && (
              <p className="rounded border border-slate-800/60 bg-slate-950/40 px-3 py-2 text-xs leading-relaxed text-slate-400">
                {activeTask.description}
              </p>
            )}

            {activeTask.playbook_run_id && (
              <div className="rounded border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-[11px] leading-relaxed text-amber-200/90">
                <p>
                  This gate is inside a playbook run. Approving continues from the step
                  after this gate; rejecting ends the run as cancelled. Nothing after the
                  gate has run yet.
                </p>
                <p className="mt-1 font-mono text-[10px] text-amber-300/60">
                  run {activeTask.playbook_run_id}
                </p>
              </div>
            )}

            {activeTask.alert_id && (
              <a
                href={`/alerts/${activeTask.alert_id}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"
              >
                Open alert context
                <ExternalLink className="h-3 w-3" />
              </a>
            )}

            <div>
              <label
                htmlFor="task-resolution"
                className="mb-1 block text-xs font-medium text-slate-400"
              >
                Findings / decision notes
              </label>
              <textarea
                id="task-resolution"
                rows={3}
                value={resolution}
                onChange={(event) => setResolution(event.target.value)}
                placeholder="What did you find, and what did you decide?"
                className="w-full resize-none rounded border border-slate-700/60 bg-slate-800/60 px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-600 focus:border-blue-500/50 focus:outline-none"
              />
            </div>

            <div>
              <p className="mb-1 text-xs font-medium text-slate-400">
                AI feedback <span className="text-slate-600">(optional)</span>
              </p>
              <p className="mb-2 text-[10px] text-slate-600">
                Sent to outcome memory for this alert family. Leave blank if you are only
                approving an action.
              </p>
              <div className="flex gap-2">
                {(['good', 'poor'] as const).map((value) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => setFeedback((prev) => (prev === value ? '' : value))}
                    aria-pressed={feedback === value}
                    className={`rounded border px-2.5 py-1 text-[11px] transition-colors ${
                      feedback === value
                        ? 'border-blue-500/50 bg-blue-500/15 text-blue-200'
                        : 'border-slate-700/60 bg-slate-800/40 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {value === 'good' ? 'AI was right' : 'AI was wrong'}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-800/60 pt-3">
              <button
                type="button"
                onClick={() => setActiveTask(null)}
                className="px-3 py-1.5 text-xs text-slate-400 transition-colors hover:text-slate-200"
              >
                Cancel
              </button>

              {activeTask.task_type === 'manual_review' && (
                <>
                  <button
                    type="button"
                    disabled={busyTaskId === activeTask.id}
                    onClick={() => void submitVerdict(activeTask, 'false_positive')}
                    className="rounded border border-slate-700/60 px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-red-500/40 hover:text-red-300 disabled:opacity-50"
                  >
                    Mark false positive
                  </button>
                  <button
                    type="button"
                    disabled={busyTaskId === activeTask.id}
                    onClick={() => void submitVerdict(activeTask, 'true_positive')}
                    className="rounded bg-blue-600/80 px-3 py-1.5 text-xs text-white transition-colors hover:bg-blue-600 disabled:opacity-50"
                  >
                    Mark true positive
                  </button>
                </>
              )}

              {activeTask.task_type === 'approval_gate' && (
                <>
                  <button
                    type="button"
                    disabled={busyTaskId === activeTask.id}
                    onClick={() =>
                      void completeTask(activeTask, {
                        resolution: resolution.trim() || 'Rejected by analyst',
                        feedback,
                        decision: 'reject',
                      })
                    }
                    className="rounded border border-slate-700/60 px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-red-500/40 hover:text-red-300 disabled:opacity-50"
                  >
                    {activeTask.playbook_run_id ? 'Reject run' : 'Reject action'}
                  </button>
                  <button
                    type="button"
                    disabled={busyTaskId === activeTask.id}
                    onClick={() =>
                      void completeTask(activeTask, {
                        resolution: resolution.trim() || 'Approved by analyst',
                        feedback,
                        decision: 'approve',
                      })
                    }
                    className="rounded bg-emerald-600/80 px-3 py-1.5 text-xs text-white transition-colors hover:bg-emerald-600 disabled:opacity-50"
                  >
                    {activeTask.playbook_run_id ? 'Approve & resume run' : 'Approve action'}
                  </button>
                </>
              )}

              {activeTask.task_type === 'mssp_sla_check' && (
                <button
                  type="button"
                  disabled={busyTaskId === activeTask.id}
                  onClick={() =>
                    void completeTask(activeTask, {
                      resolution: resolution.trim() || 'SLA obligation handled',
                      feedback,
                    })
                  }
                  className="rounded bg-blue-600/80 px-3 py-1.5 text-xs text-white transition-colors hover:bg-blue-600 disabled:opacity-50"
                >
                  Mark handled
                </button>
              )}
            </div>
          </div>
        )}
      </RunbookModal>
    </div>
  );
}

/**
 * Did the approval actually continue the playbook?
 *
 * Only rendered when the API recorded an answer (`resume_applied`), which only
 * happens for gate tasks that carried a playbook run. A recorded decision that
 * did not move the run is the interesting case: it means the analyst believes
 * something continued that did not, so it is shown in amber, not green.
 */
function ResumeOutcome({ applied }: { applied: boolean }) {
  return (
    <p
      className={`mt-1 inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] ${
        applied
          ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300/90'
          : 'border-amber-500/25 bg-amber-500/10 text-amber-300/90'
      }`}
      title={
        applied
          ? 'The playbook run continued past the approval gate.'
          : 'The decision was recorded, but the playbook run did not move — check the run in Playbooks → Run History.'
      }
    >
      {applied ? 'Playbook resumed' : 'Decision recorded · run not resumed'}
    </p>
  );
}

function FeedbackLoopStrip({ stats }: { stats: RunbookFeedbackStats }) {
  const { priors_updated, completions_with_feedback, feedback_unapplied } = stats;
  const ratio = completions_with_feedback > 0
    ? `${priors_updated}/${completions_with_feedback}`
    : '0/0';

  return (
    <div
      className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-slate-800/60 bg-slate-900/30 px-3 py-2 text-[11px]"
      title="Outcome memory only learns when a prior exists for the alert's evidence signature. Feedback that found no prior is counted separately instead of being reported as a success."
    >
      <span className="flex items-center gap-1.5 font-medium uppercase tracking-wider text-slate-500">
        <RefreshCw className="h-3 w-3" />
        Feedback loop
      </span>
      {completions_with_feedback === 0 ? (
        <span className="text-slate-500">
          No analyst feedback yet — completions will show whether outcome memory learned.
        </span>
      ) : (
        <>
          <span className="text-slate-300">
            <span className="font-semibold text-emerald-300">{ratio}</span> analyst completions
            updated an outcome prior
          </span>
          {feedback_unapplied > 0 && (
            <span className="rounded border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 text-amber-300/90">
              {feedback_unapplied} not applied
            </span>
          )}
        </>
      )}
    </div>
  );
}

interface TaskCardProps {
  task: RunbookTask;
  busy: boolean;
  onOpen: () => void;
}

function TaskCard({ task, busy, onOpen }: TaskCardProps) {
  return (
    <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 px-3 py-2.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${TASK_CHIPS[task.task_type]}`}
            >
              {TASK_LABELS[task.task_type]}
            </span>
            {task.due_at && (
              <span className="flex items-center gap-1 text-[10px] text-slate-500">
                <Clock className="h-3 w-3" />
                Due {new Date(task.due_at).toLocaleDateString()}
              </span>
            )}
            <TaskStatusChip status={task.status} />
          </div>
          <p className="mt-1 truncate text-sm text-slate-200" title={task.title}>
            {task.title}
          </p>
          {task.description && (
            <p className="mt-0.5 line-clamp-2 text-xs text-slate-500">{task.description}</p>
          )}
        </div>

        <button
          type="button"
          onClick={onOpen}
          disabled={busy}
          className="shrink-0 rounded bg-blue-600/80 px-3 py-1 text-xs text-white transition-colors hover:bg-blue-600 disabled:opacity-50"
        >
          Review
        </button>
      </div>
    </div>
  );
}

function TaskStatusChip({ status }: { status: RunbookTaskStatus }) {
  const styles: Record<RunbookTaskStatus, string> = {
    pending: 'text-amber-300 bg-amber-500/10 border-amber-500/20',
    in_progress: 'text-blue-300 bg-blue-500/10 border-blue-500/20',
    completed: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/20',
  };
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[10px] ${styles[status]}`}>
      {status.replace('_', ' ')}
    </span>
  );
}
