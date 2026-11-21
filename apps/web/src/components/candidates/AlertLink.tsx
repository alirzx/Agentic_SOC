'use client';

/**
 * One alert, linked to its detail page and opened in a new tab.
 *
 * Every candidate surface (the Alerts table, the Timeline entries and the
 * alert ids inside an observation) renders the same thing: the notable's
 * search name, the analytic name from `llm_payload.rule.title` underneath when
 * it adds information, and an external-link marker. The current tab is never
 * navigated — a candidate review must survive opening an alert.
 */

import { ExternalLink } from 'lucide-react';
import { clsx } from 'clsx';

interface AlertLinkProps {
  alertId: string;
  title?: string | null;
  payloadTitle?: string | null;
  /** Smaller type, used when the link sits inside a list item. */
  compact?: boolean;
}

export function AlertLink({ alertId, title, payloadTitle, compact = false }: AlertLinkProps) {
  return (
    <a
      href={`/alerts/${alertId}`}
      target="_blank"
      rel="noopener noreferrer"
      title="Open the full alert in a new tab"
      className="group relative block -mx-1 rounded px-1 py-0.5 pr-5 focus:outline-none focus-visible:ring-1 focus-visible:ring-teal-400/60"
    >
      <span
        className={clsx(
          'line-clamp-2 text-gray-200 group-hover:text-teal-300',
          compact && 'text-[11px] leading-snug'
        )}
      >
        {title ?? 'Untitled alert'}
      </span>
      <ExternalLink
        className="absolute right-0 top-1 h-3 w-3 text-gray-500 group-hover:text-teal-300"
        aria-hidden="true"
      />
      {payloadTitle && (
        <span
          className={clsx(
            'mt-0.5 block line-clamp-2 text-teal-300/80',
            compact ? 'text-[10px] leading-snug' : 'text-[11px] leading-snug'
          )}
        >
          {payloadTitle}
        </span>
      )}
    </a>
  );
}
