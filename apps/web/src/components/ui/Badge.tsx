/**
 * Console Badge primitive — AssetManagement chip tones.
 */
import { clsx } from 'clsx';
import type { HTMLAttributes, ReactNode } from 'react';

export type BadgeTone =
  | 'neutral'
  | 'info'
  | 'success'
  | 'warning'
  | 'danger'
  | 'severity-info'
  | 'severity-low'
  | 'severity-medium'
  | 'severity-high'
  | 'severity-critical';

const TONE_CLASSES: Record<BadgeTone, string> = {
  neutral: 'bg-dark-20 text-amgray-30 border-[#333A47]',
  info: 'bg-teal-20/10 text-teal-20 border-teal-20/30',
  success: 'bg-[#64FF99]/10 text-[#64FF99] border-[#64FF99]/30',
  warning: 'bg-[#F0BC56]/10 text-[#F0BC56] border-[#F0BC56]/30',
  danger: 'bg-red-900/40 text-red-300 border-red-800',
  'severity-info': 'bg-dark-20 text-amgray-30 border-[#333A47]',
  'severity-low': 'bg-[#3163CF]/15 text-[#7BA3F0] border-[#3163CF]/40',
  'severity-medium': 'bg-[#F0BC56]/15 text-[#F0BC56] border-[#F0BC56]/40',
  'severity-high': 'bg-orange-900/50 text-orange-300 border-orange-800',
  'severity-critical': 'bg-red-900/60 text-red-200 border-red-700',
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  icon?: ReactNode;
  /** Small dot on the left, common for status indicators. */
  dot?: boolean;
}

export function Badge({
  tone = 'neutral',
  icon,
  dot,
  className,
  children,
  ...rest
}: BadgeProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-[6px] border px-2 py-0.5 text-[11px] font-medium',
        TONE_CLASSES[tone],
        className,
      )}
      {...rest}
    >
      {dot && (
        <span
          aria-hidden="true"
          className="h-1.5 w-1.5 rounded-full bg-current opacity-80"
        />
      )}
      {icon}
      {children}
    </span>
  );
}
