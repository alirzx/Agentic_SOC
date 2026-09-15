/**
 * T3.8 — AiSOC console StatusPill primitive.
 *
 * Compact status indicator with an animated dot for live states. Used
 * in the runs panel, connector cards, ingest health bar, etc.
 */
import { clsx } from 'clsx';
import type { HTMLAttributes } from 'react';

export type StatusKind =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'unknown';

const STATUS_META: Record<StatusKind, { label: string; classes: string; pulse: boolean }> = {
  pending: { label: 'Pending', classes: 'text-[#F0BC56] bg-[#F0BC56]/10 border-[#F0BC56]/30', pulse: false },
  running: { label: 'Running', classes: 'text-teal-20 bg-teal-20/10 border-teal-20/30', pulse: true },
  completed: { label: 'Completed', classes: 'text-[#64FF99] bg-[#64FF99]/10 border-[#64FF99]/30', pulse: false },
  failed: { label: 'Failed', classes: 'text-red-300 bg-red-900/30 border-red-800', pulse: false },
  cancelled: { label: 'Cancelled', classes: 'text-amgray-40 bg-dark-20/60 border-[#333A47]', pulse: false },
  unknown: { label: 'Unknown', classes: 'text-amgray-50 bg-dark-70/80 border-[#374151]', pulse: false },
};

export interface StatusPillProps extends HTMLAttributes<HTMLSpanElement> {
  status: StatusKind;
  /** Override the rendered label (defaults to the canonical name). */
  label?: string;
}

export function StatusPill({ status, label, className, ...rest }: StatusPillProps) {
  const meta = STATUS_META[status];
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium',
        meta.classes,
        className,
      )}
      {...rest}
    >
      <span
        aria-hidden="true"
        className={clsx(
          'h-1.5 w-1.5 rounded-full bg-current',
          meta.pulse && 'animate-pulse',
        )}
      />
      {label ?? meta.label}
    </span>
  );
}
