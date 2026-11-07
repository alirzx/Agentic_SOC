'use client';

import type { FC, ReactNode } from 'react';
import { useEffect } from 'react';
import { X } from 'lucide-react';

type Size = 'md' | 'lg';

const WIDTHS: Record<Size, string> = {
  md: 'max-w-2xl',
  lg: 'max-w-4xl',
};

interface RunbookModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: ReactNode;
  size?: Size;
}

/**
 * Modal shell for the Runbook console (rule authoring, rule testing).
 *
 * These flows used to render inline above the rule list, which pushed the page
 * down and made an edit feel like a page navigation. A modal keeps the list in
 * place and gives the form a single, dismissible surface.
 *
 * Behaviour: Escape and backdrop click close, body scroll is locked while open,
 * and focus moves to the dialog on mount.
 */
export const RunbookModal: FC<RunbookModalProps> = ({
  open,
  onClose,
  title,
  subtitle,
  children,
  size = 'md',
}) => {
  useEffect(() => {
    if (!open) return;

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKey);

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.removeEventListener('keydown', handleKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4 sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={onClose}
    >
      <div
        className={`my-auto w-full ${WIDTHS[size]} rounded-xl border border-slate-700/60 bg-slate-900 shadow-2xl`}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3 border-b border-slate-800/80 px-4 py-3">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
            {subtitle && (
              <p className="mt-0.5 text-[11px] text-slate-500">{subtitle}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="shrink-0 rounded p-1 text-slate-500 transition-colors hover:text-slate-200"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-[75vh] overflow-y-auto px-4 py-4">{children}</div>
      </div>
    </div>
  );
};
