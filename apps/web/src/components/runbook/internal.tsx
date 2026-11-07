import type { FC } from "react";
import { AlertTriangle, Check, Clock, Info, User, Bot, Cpu, Plug, SkipForward, Minus } from "lucide-react";
import type {
  ProcedureStage,
  ProcedureStageStatus,
  RunbookStep,
  RunbookPolicy,
} from "@/components/runbook/runbook.types";

// ── empty / loading / error states ────────────────────────────────────────

export const EmptyRunbook: FC<{
  subjectType: "alert" | "case" | "incident";
  subjectId: string;
}> = ({ subjectType, subjectId }) => (
  <div className="space-y-3">
    <div className="flex items-start gap-2 text-slate-400">
      <Info className="h-4 w-4 shrink-0 mt-0.5" />
      <p className="text-xs leading-relaxed">
        No governed actions recorded for this{" "}
        <span className="font-medium text-slate-300">{subjectType}</span>{" "}
        ({subjectId.slice(0, 8)}…).
      </p>
    </div>
    <p className="text-xs text-slate-500 leading-relaxed">
      The Runbook starts empty and fills as actions run against this subject —
      auto-triage, escalation, suppression, case transitions, ITSM inbound
      updates, and future policy-driven steps.
    </p>
  </div>
);

export const LoadingRunbook: FC = () => (
  <div className="flex items-center gap-2 text-slate-500">
    <Clock className="h-4 w-4 animate-pulse" />
    <p className="text-xs">Loading Runbook…</p>
  </div>
);

export const ErrorRunbook: FC<{ onRetry: () => void }> = ({ onRetry }) => (
  <div className="space-y-3">
    <div className="flex items-start gap-2 text-amber-300">
      <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
      <p className="text-xs leading-relaxed font-medium">
        Could not load Runbook
      </p>
    </div>
    <p className="text-xs text-slate-500 leading-relaxed">
      The server returned an error while reading the ledger. Retry to refresh;
      contact support if it persists.
    </p>
    <button
      type="button"
      className="text-xs text-slate-300 underline hover:text-slate-100"
      onClick={onRetry}
    >
      Retry
    </button>
  </div>
);

// ── helpers ────────────────────────────────────────────────────────────────

const ACTOR_ICONS: Record<string, FC<{ className?: string }>> = {
  system:    ({ className }) => <Cpu className={className} />,
  agent:     ({ className }) => <Bot className={className} />,
  analyst:   ({ className }) => <User className={className} />,
  connector: ({ className }) => <Plug className={className} />,
};

const ACTOR_COLORS: Record<string, string> = {
  system:    "text-slate-400 bg-slate-500/10",
  agent:     "text-blue-400 bg-blue-500/10",
  analyst:   "text-purple-400 bg-purple-500/10",
  connector: "text-cyan-400 bg-cyan-500/10",
};

const STATUS_CHIPS: Record<string, string> = {
  executed:  "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  simulated: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  allowed:   "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  denied:    "text-red-400 bg-red-500/10 border-red-500/20",
  failed:    "text-red-400 bg-red-500/10 border-red-500/20",
  skipped:   "text-slate-500 bg-slate-500/10 border-slate-700/40",
  recorded:  "text-slate-400 bg-slate-500/10 border-slate-700/40",
};

const DECISION_COLORS: Record<string, string> = {
  allow:    "text-emerald-400",
  deny:     "text-red-400",
  escalate: "text-orange-400",
  reject:   "text-red-400",
};

const BLAST_DOTS: Record<string, string> = {
  read:     "bg-slate-500",
  low:      "bg-emerald-500",
  medium:   "bg-yellow-500",
  high:     "bg-orange-500",
  critical: "bg-red-500",
};

function ActorBadge({ type, label }: { type: string; label: string | null }) {
  const Icon = ACTOR_ICONS[type] ?? ACTOR_ICONS.system;
  const color = ACTOR_COLORS[type] ?? ACTOR_COLORS.system;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded ${color}`}>
      <Icon className="h-2.5 w-2.5" />
      {label ?? type}
    </span>
  );
}

function StatusChip({ status }: { status: string }) {
  const chipClass = STATUS_CHIPS[status] ?? "text-slate-400 bg-slate-500/10 border-slate-700/40";
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${chipClass}`}>
      {status}
    </span>
  );
}

function GovernancePanel({ policy }: { policy: RunbookPolicy }) {
  const decision = policy.decision ?? "allow";
  // Auto-triage verdicts (needs_review / false_positive / …) live in the same
  // field as gate decisions but answer a different question, so they get their
  // own treatment instead of borrowing "allow" green.
  const isTriage = policy.layer === "auto_triage";
  const decisionColor = isTriage
    ? "text-blue-300"
    : (DECISION_COLORS[decision] ?? DECISION_COLORS.allow);
  const blastDot = BLAST_DOTS[policy.blast_radius ?? ""] ?? "bg-slate-500";

  return (
    <div className="mt-2 rounded border border-slate-800/50 bg-slate-950/20 px-3 py-2 text-[10px] space-y-1">
      <p className="text-slate-500 uppercase tracking-wider font-medium mb-1.5">
        {isTriage ? "Automated triage" : "Governance"}
      </p>
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {!isTriage && (
          <span>
            layer: <span className="text-slate-300">{policy.layer ?? "defaults"}</span>
          </span>
        )}
        {policy.autonomy_level && (
          <span>
            autonomy: <span className="text-slate-300">{policy.autonomy_level}</span>
          </span>
        )}
        <span>
          {isTriage ? "verdict" : "decision"}:{" "}
          <span className={decisionColor}>{decision}</span>
        </span>
        {policy.blast_radius && (
          <span className="flex items-center gap-1">
            blast:{" "}
            <span className={`inline-block h-2 w-2 rounded-full ${blastDot}`} />
            <span className="text-slate-300">{policy.blast_radius}</span>
          </span>
        )}
        {policy.confidence !== undefined && (
          <span>
            confidence:{" "}
            <span className="text-slate-300">{Math.round(policy.confidence * 100)}%</span>
          </span>
        )}
      </div>
      {policy.reason && (
        <p className="text-slate-500 mt-1 italic">{policy.reason}</p>
      )}
      {policy.approval_actor && (
        <p className="text-slate-400 mt-1">
          Approved by{" "}
          <span className="text-slate-200">{policy.approval_actor}</span>
          {policy.approval_at ? ` at ${new Date(policy.approval_at).toLocaleTimeString()}` : ""}
        </p>
      )}
    </div>
  );
}

// ── procedure ─────────────────────────────────────────────────────────────

const PROCEDURE_ICONS: Record<ProcedureStageStatus, FC<{ className?: string }>> = {
  done: ({ className }) => <Check className={className} />,
  skipped: ({ className }) => <SkipForward className={className} />,
  pending: ({ className }) => <Minus className={className} />,
  blocked: ({ className }) => <AlertTriangle className={className} />,
};

const PROCEDURE_COLORS: Record<ProcedureStageStatus, string> = {
  done: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
  skipped: "text-slate-500 border-slate-700/50 bg-slate-800/30",
  pending: "text-slate-400 border-slate-700/50 bg-slate-900/40",
  blocked: "text-amber-300 border-amber-500/40 bg-amber-500/10",
};

/**
 * The expected operational sequence for this subject, with the evidence-backed
 * status of each stage. Order comes from the server's procedure definition, not
 * from timestamps, so a late-arriving ingest row cannot reorder the workflow.
 */
export const ProcedureStepper: FC<{ stages: ProcedureStage[] }> = ({ stages }) => (
  <div className="mb-4 rounded-lg border border-slate-800/70 bg-slate-900/30 p-3">
    <div className="flex items-center justify-between gap-3">
      <p className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Expected procedure</p>
      <p className="text-[10px] text-slate-600">
        blocked = waiting on you · skipped = not needed for this case
      </p>
    </div>
    <ol className="mt-2 flex flex-wrap items-center gap-1.5">
      {stages.map((stage, index) => {
        const Icon = PROCEDURE_ICONS[stage.status] ?? PROCEDURE_ICONS.pending;
        const colors = PROCEDURE_COLORS[stage.status] ?? PROCEDURE_COLORS.pending;
        return (
          <li key={stage.stage} className="flex items-center gap-1.5">
            <span
              className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${colors}`}
              title={`${stage.stage_label} — ${stage.status}`}
            >
              <Icon className="h-2.5 w-2.5" />
              {stage.stage_label}
            </span>
            {index < stages.length - 1 && (
              <span className="text-slate-700" aria-hidden="true">
                →
              </span>
            )}
          </li>
        );
      })}
    </ol>
  </div>
);

// ── ledger rendering ──────────────────────────────────────────────────────

export const RunbookActions: FC<{ steps: RunbookStep[] }> = ({ steps }) => (
  <ul className="space-y-3">
    {steps.map((step) => (
      <li
        key={step.seq}
        className="rounded-lg border border-slate-800/50 bg-slate-900/30 px-3 py-2.5 text-xs"
      >
        {/* header row */}
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-1.5 flex-wrap">
            <ActorBadge type={step.actor_type} label={step.actor_label} />
            <span className="text-slate-200 font-medium">
              {kindLabel(step.kind)}
              {step.action_name ? (
                <span className="font-mono text-slate-400 ml-1">{step.action_name}</span>
              ) : null}
            </span>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <StatusChip status={step.status} />
            <span className="text-[10px] text-slate-600">{formatTime(step.occurred_at)}</span>
          </div>
        </div>

        {/* summary */}
        <p className="text-slate-400 mt-1.5 leading-relaxed">{step.summary}</p>

        {/* detail */}
        {step.detail ? (
          <pre className="mt-2 text-[10px] text-slate-400 bg-slate-900/60 rounded p-2 overflow-x-auto">
            {step.detail}
          </pre>
        ) : null}

        {/* stage label */}
        <div className="flex items-center gap-2 mt-1.5 text-[10px] text-slate-600">
          <span>{step.stage_label}</span>
        </div>

        {/* governance panel */}
        {step.policy && Object.keys(step.policy).length > 0 && (
          <GovernancePanel policy={step.policy} />
        )}
      </li>
    ))}
  </ul>
);

export const RunbookTimeline: FC<{ steps: RunbookStep[] }> = ({ steps }) => (
  <div className="space-y-0">
    {steps.map((step, idx) => {
      const dotColor = STATUS_CHIPS[step.status]?.match(/bg-(\w+-\d+)/)?.[1]
        ? `bg-${STATUS_CHIPS[step.status]!.match(/bg-(\w+-\d+)/)![1]}`
        : "bg-slate-600";

      return (
        <div key={step.seq} className="flex gap-3 text-xs">
          <div className="shrink-0 flex flex-col items-center pt-1">
            <div className={`h-2 w-2 rounded-full ${dotColor}`} />
            {idx < steps.length - 1 && (
              <div className="w-px flex-1 bg-slate-800 mt-1 mb-0" style={{ minHeight: "1.5rem" }} />
            )}
          </div>
          <div className="pb-4 flex-1 min-w-0">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-slate-200 font-medium">
                {kindLabel(step.kind)}
                {step.action_name ? (
                  <span className="font-mono text-slate-500 text-[10px] ml-1">{step.action_name}</span>
                ) : null}
              </span>
              <StatusChip status={step.status} />
              <ActorBadge type={step.actor_type} label={step.actor_label} />
            </div>
            <p className="text-slate-500 mt-0.5 line-clamp-2">{step.summary}</p>
            <div className="mt-0.5 text-[10px] text-slate-600">
              {formatTime(step.occurred_at)}
              <span className="mx-1">·</span>
              {step.stage_label}
            </div>
            {step.policy?.decision && (
              <span className={`text-[10px] ${DECISION_COLORS[step.policy.decision] ?? "text-slate-400"}`}>
                gate: {step.policy.decision}
              </span>
            )}
          </div>
        </div>
      );
    })}
  </div>
);

function kindLabel(kind: string | null | undefined): string {
  if (!kind) return "Action";
  return kind
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString();
  } catch {
    return iso;
  }
}
