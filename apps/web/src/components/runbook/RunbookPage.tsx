"use client";

import type { FC } from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Download, MessageSquarePlus, Shield, X } from "lucide-react";
import type { RunbookEnvelope } from "@/components/runbook/runbook.types";
import {
  EmptyRunbook,
  ErrorRunbook,
  LoadingRunbook,
  ProcedureStepper,
  RunbookActions,
  RunbookTimeline,
} from "@/components/runbook/internal";

interface RunbookPageProps {
  subjectType: "alert" | "case" | "incident";
  subjectId: string;
  initialEnvelope?: RunbookEnvelope;
  /** Optional fetch function used by client-rendered callers. Server pages must
    pass a resolved envelope instead of a function prop. */
  fetchRunbook?: () => Promise<RunbookEnvelope>;
}

function isEnvelope(v: unknown): v is RunbookEnvelope {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.subject_type === "string" &&
    typeof o.subject_id === "string" &&
    typeof o.total_steps === "number" &&
    Array.isArray(o.steps) &&
    typeof o.empty === "boolean"
  );
}

export const RunbookPage: FC<RunbookPageProps> = ({
  subjectType,
  subjectId,
  initialEnvelope,
  fetchRunbook,
}) => {
  const [envelope, setEnvelope] = useState<RunbookEnvelope | null>(initialEnvelope ?? null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"actions" | "timeline" | "policy">("actions");
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [feedbackText, setFeedbackText] = useState("");
  const [feedbackSent, setFeedbackSent] = useState(false);
  const mountedRef = useRef(true);

  const load = useCallback(async () => {
    if (!fetchRunbook) return;

    setError(null);
    setEnvelope(null);
    try {
      const data = await fetchRunbook();
      if (!mountedRef.current) return;
      if (!isEnvelope(data)) {
        setError("Runbook response was not in the expected shape");
        return;
      }
      setEnvelope(data);
    } catch (err) {
      if (!mountedRef.current) return;
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [fetchRunbook]);

  useEffect(() => {
    mountedRef.current = true;

    if (initialEnvelope) {
      setEnvelope(initialEnvelope);
      setError(null);
      return () => {
        mountedRef.current = false;
      };
    }

    if (!fetchRunbook) return () => {
      mountedRef.current = false;
    };

    load();
    return () => {
      mountedRef.current = false;
    };
  }, [fetchRunbook, initialEnvelope, load]);

  const handleRetry = useCallback(() => {
    setError(null);
    load();
  }, [load]);

  const exportMarkdown = useCallback(() => {
    if (!envelope) return;
    const lines: string[] = [
      `# Runbook — ${envelope.workflow_name}`,
      ``,
      `**Subject:** ${subjectType} / \`${subjectId}\``,
      `**Steps:** ${envelope.total_steps}`,
      ``,
      `## Actions`,
      ``,
    ];
    envelope.steps.forEach((s) => {
      lines.push(`### ${s.stage_label}${ s.action_name ? ` — \`${s.action_name}\`` : "" }`);
      lines.push(`- **Actor:** ${s.actor_label ?? s.actor_type}`);
      lines.push(`- **Status:** ${s.status}`);
      lines.push(`- **Time:** ${new Date(s.occurred_at).toLocaleString()}`);
      if (s.summary) lines.push(`- **Summary:** ${s.summary}`);
      if (s.policy?.decision) lines.push(`- **Gate:** ${String(s.policy.decision)} (layer: ${String(s.policy.layer ?? "defaults")})`);
      lines.push("");
    });
    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `runbook-${subjectType}-${subjectId.slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  }, [envelope, subjectType, subjectId]);

  const submitFeedback = useCallback(async () => {
    if (!feedbackText.trim()) return;
    try {
      await fetch(`/api/v1/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          subject_type: subjectType,
          subject_id: subjectId,
          kind: "runbook_feedback",
          text: feedbackText.trim(),
        }),
      });
    } catch {
      // Feedback is best-effort; never block the analyst.
    } finally {
      setFeedbackSent(true);
      setFeedbackText("");
      setTimeout(() => { setFeedbackOpen(false); setFeedbackSent(false); }, 1500);
    }
  }, [feedbackText, subjectType, subjectId]);

  return (
    <div className="rounded-lg border border-slate-800/70 bg-slate-950/30 p-4 min-h-[240px]">
      <header className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Runbook</h2>
          <p className="text-xs text-slate-500 mt-1 line-clamp-2">
            Governed actions taken against this {subjectType} — what happened,
            by whom, under which policy, and with what result.
          </p>
        </div>
        {envelope && !envelope.empty && (
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              type="button"
              onClick={exportMarkdown}
              title="Export this Runbook as Markdown (for case reports or Jira attachments)"
              className="flex items-center gap-1 px-2 py-1 text-[10px] text-slate-400 hover:text-slate-200 border border-slate-700/60 hover:border-slate-600 rounded transition-colors"
            >
              <Download className="h-3 w-3" />
              Export .md
            </button>
            <button
              type="button"
              onClick={() => setFeedbackOpen((v) => !v)}
              title="Give feedback to the agent to improve future triage accuracy"
              className="flex items-center gap-1 px-2 py-1 text-[10px] text-slate-400 hover:text-blue-300 border border-slate-700/60 hover:border-blue-500/40 rounded transition-colors"
            >
              <MessageSquarePlus className="h-3 w-3" />
              Feedback
            </button>
          </div>
        )}
      </header>

      {/* Feedback panel */}
      {feedbackOpen && (
        <div className="mb-4 rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-slate-300">Give feedback to the agent</p>
            <button type="button" onClick={() => setFeedbackOpen(false)} className="text-slate-600 hover:text-slate-400">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          {feedbackSent ? (
            <p className="text-xs text-emerald-400">Feedback sent — thank you.</p>
          ) : (
            <>
              <textarea
                rows={3}
                value={feedbackText}
                onChange={(e) => setFeedbackText(e.target.value)}
                placeholder="e.g. The triage verdict was wrong — this is a false positive because…"
                className="w-full bg-slate-800/60 border border-slate-700/60 rounded px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50 resize-none"
              />
              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={submitFeedback}
                  disabled={!feedbackText.trim()}
                  className="px-3 py-1.5 text-xs bg-blue-600/80 hover:bg-blue-600 text-white rounded disabled:opacity-40 transition-colors"
                >
                  Send to agent
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {envelope && (
        <div className="mb-4 rounded-lg border border-slate-800/70 bg-slate-900/40 p-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Operational workflow</p>
              <p className="mt-1 text-sm font-medium text-slate-200">{envelope.workflow_name}</p>
            </div>
            <div className="rounded-full border border-blue-500/20 bg-blue-500/10 px-2 py-1 text-[10px] text-blue-300">
              {envelope.supporting_rule_count} supporting rules
            </div>
          </div>
          <p className="mt-2 text-xs leading-relaxed text-slate-400">{envelope.workflow_objective}</p>
        </div>
      )}

      {/* Procedure — what should happen, in order. Shown even when empty so the
          analyst always sees the expected path, not just history. */}
      {envelope && envelope.procedure.length > 0 && (
        <ProcedureStepper stages={envelope.procedure} />
      )}

      {error ? (
        <ErrorRunbook onRetry={handleRetry} />
      ) : envelope === null ? (
        <LoadingRunbook />
      ) : envelope.empty ? (
        <EmptyRunbook subjectType={subjectType} subjectId={subjectId} />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center gap-4 border-b border-slate-800/60 pb-2">
            <button
              type="button"
              className={`text-xs font-medium uppercase tracking-wide ${
                activeTab === "actions"
                  ? "text-slate-100 border-b-2 border-slate-400"
                  : "text-slate-500 hover:text-slate-300"
              }`}
              onClick={() => setActiveTab("actions")}
            >
              Actions ({envelope.total_steps})
            </button>
            <button
              type="button"
              className={`text-xs font-medium uppercase tracking-wide ${
                activeTab === "timeline"
                  ? "text-slate-100 border-b-2 border-slate-400"
                  : "text-slate-500 hover:text-slate-300"
              }`}
              onClick={() => setActiveTab("timeline")}
            >
              Timeline
            </button>
            <button
              type="button"
              className={`text-xs font-medium uppercase tracking-wide flex items-center gap-1 ${
                activeTab === "policy"
                  ? "text-slate-100 border-b-2 border-slate-400"
                  : "text-slate-500 hover:text-slate-300"
              }`}
              onClick={() => setActiveTab("policy")}
            >
              <Shield className="h-3 w-3" />
              Policy
            </button>
          </div>

          {activeTab === "actions" && (
            <RunbookActions steps={envelope.steps} />
          )}
          {activeTab === "timeline" && (
            <RunbookTimeline steps={envelope.steps} />
          )}
          {activeTab === "policy" && (
            <div className="space-y-2">
              {envelope.steps.filter((s) => s.policy && Object.keys(s.policy).length > 0).length === 0 ? (
                <p className="text-xs text-slate-600 italic">
                  No governance decisions recorded for this subject yet.
                </p>
              ) : (
                envelope.steps
                  .filter((s) => s.policy && Object.keys(s.policy).length > 0)
                  .map((step) => (
                    <div
                      key={step.seq}
                      className="rounded border border-slate-800/50 bg-slate-900/30 px-3 py-2 text-xs space-y-1"
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-slate-200">{step.stage_label}</span>
                        {step.action_name && (
                          <span className="font-mono text-slate-500 text-[10px]">{step.action_name}</span>
                        )}
                        <span className="text-[10px] text-slate-600">
                          {new Date(step.occurred_at).toLocaleTimeString()}
                        </span>
                      </div>
                      {step.policy && (
                        <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-[10px] text-slate-500 mt-1">
                          {step.policy.layer && (
                            <span>layer: <span className="text-slate-300">{String(step.policy.layer)}</span></span>
                          )}
                          {step.policy.autonomy_level && (
                            <span>autonomy: <span className="text-slate-300">{String(step.policy.autonomy_level)}</span></span>
                          )}
                          {step.policy.decision && (
                            <span>decision: <span className={
                              step.policy.decision === "allow" ? "text-emerald-400"
                              : step.policy.decision === "deny" ? "text-red-400"
                              : "text-orange-400"
                            }>{String(step.policy.decision)}</span></span>
                          )}
                          {step.policy.blast_radius && (
                            <span>blast: <span className="text-slate-300">{String(step.policy.blast_radius)}</span></span>
                          )}
                        </div>
                      )}
                      {step.policy?.reason && (
                        <p className="text-[10px] text-slate-500 italic">{String(step.policy.reason)}</p>
                      )}
                    </div>
                  ))
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

function kindLabel(kind: string | null | undefined): string {
  if (!kind) return "Action";
  return kind
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
