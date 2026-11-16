'use client';

/**
 * Dashboard design primitives (light dashboard design).
 *
 * Presentation-only building blocks shared by the dashboard widgets: white
 * rounded cards with a hairline border, sentence-case section headings,
 * "Last 24h" style pills and tinted icon badges. Everything is expressed in
 * semantic `surface-*` / `fg-*` tokens so both themes render correctly.
 */

import type { ReactNode } from 'react';
import { clsx } from 'clsx';

/** Design accents (light dashboard design palette). */
export const ACCENT = {
  red: '#FD4E4E',
  orange: '#F98B3E',
  yellow: '#F2BD57',
  green: '#4ADE80',
  teal: '#4FD2C2',
  blue: '#3163CF',
  purple: '#7B5EE6',
  violet: '#8531CF',
  slate: '#939DAD',
} as const;

export type AccentName = keyof typeof ACCENT;

/** Text colour classes for good / warning / bad metric states. */
export const TONE_TEXT = {
  good: 'text-teal-20',
  warn: 'text-[#F2BD57]',
  bad: 'text-[#FD4E4E]',
  neutral: 'text-fg-primary',
} as const;

export type Tone = keyof typeof TONE_TEXT;

export function Card({
  children,
  className,
  as: As = 'div',
}: {
  children: ReactNode;
  className?: string;
  as?: 'div' | 'section';
}) {
  return (
    <As className={clsx('rounded-2xl border border-surface-border bg-surface-card', className)}>
      {children}
    </As>
  );
}

export function SectionHeading({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <h2 className="text-[22px] leading-tight font-gilroy-semibold text-fg-primary">{children}</h2>
      {action}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  action,
  className,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={clsx('flex items-start justify-between gap-3', className)}>
      <div className="min-w-0">
        <h3 className="text-[17px] leading-snug font-gilroy-semibold text-fg-primary">{title}</h3>
        {subtitle && <p className="mt-0.5 text-xs text-fg-muted">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function Pill({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span
      title={title}
      className={clsx(
        'inline-flex shrink-0 items-center gap-1.5 rounded-full border border-surface-border bg-surface-hover px-3 py-1 text-xs text-fg-muted',
        className,
      )}
    >
      {children}
    </span>
  );
}

/** Round tinted badge holding an icon (KPI cards). */
export function IconBadge({ accent, children, size = 36 }: { accent: AccentName; children: ReactNode; size?: number }) {
  const hex = ACCENT[accent];
  return (
    <span
      aria-hidden
      className="inline-flex shrink-0 items-center justify-center rounded-full"
      style={{ width: size, height: size, backgroundColor: `${hex}26`, color: hex }}
    >
      {children}
    </span>
  );
}

/** Plain KPI tile: label, big value, optional unit (SOC performance / cost). */
export function StatTile({
  label,
  value,
  unit,
  tone = 'neutral',
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  tone?: Tone;
}) {
  return (
    <Card className="flex flex-col gap-2 p-6">
      <span className="text-base text-fg-muted">{label}</span>
      <span className={clsx('text-[28px] leading-none font-gilroy-semibold tabular-nums', TONE_TEXT[tone])}>
        {value}
        {unit && <span className="ml-1.5">{unit}</span>}
      </span>
    </Card>
  );
}
