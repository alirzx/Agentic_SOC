'use client';

import { useId, useState, type ReactNode } from 'react';
import { clsx } from 'clsx';

interface InfoTipProps {
  /** Tooltip body. Keep it to one or two sentences. */
  label: string;
  children: ReactNode;
  className?: string;
  /** Which edge the tooltip aligns to. Defaults to the left edge. */
  align?: 'left' | 'right';
}

/**
 * Small hover/focus tooltip for filter controls.
 *
 * Deliberately local to the candidates workbench: the shared
 * `AnimatedTooltip` is 14rem wide and centres under its trigger, which is too
 * narrow for an explanation of what a correlation score actually means, and
 * clips inside the filter bar. This one is 20rem and edge-aligned, and it opens
 * on keyboard focus so the explanation is reachable without a mouse.
 */
export function InfoTip({ label, children, className, align = 'left' }: InfoTipProps) {
  const [open, setOpen] = useState(false);
  const tipId = useId();

  return (
    <span
      className={clsx('relative inline-flex items-center', className)}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      <span
        aria-describedby={open ? tipId : undefined}
        tabIndex={0}
        className="inline-flex cursor-help items-center gap-1 rounded outline-none focus-visible:ring-1 focus-visible:ring-orange-500/60"
      >
        {children}
        <svg
          aria-hidden="true"
          viewBox="0 0 16 16"
          className="h-3 w-3 shrink-0 text-gray-500"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.4}
        >
          <circle cx="8" cy="8" r="6.25" />
          <path strokeLinecap="round" d="M8 7.25v3.5M8 5.1v.05" />
        </svg>
      </span>
      {open && (
        <span
          id={tipId}
          role="tooltip"
          className={clsx(
            'pointer-events-none absolute top-full z-40 mt-2 w-80 rounded-lg border border-[#374151] bg-[#0b1220] px-3 py-2 text-[11px] font-normal leading-relaxed text-gray-300 shadow-[0_12px_32px_-16px_rgba(0,0,0,0.8)]',
            align === 'left' ? 'left-0' : 'right-0'
          )}
        >
          {label}
        </span>
      )}
    </span>
  );
}
