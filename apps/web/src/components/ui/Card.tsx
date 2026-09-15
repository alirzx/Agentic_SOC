/**
 * Console Card primitive — AssetManagement section/card surfaces.
 *
 * Navy panels with `#374151` borders; optional teal accent bar via
 * callers. Elevation maps to dark-70 / dark-60 / dark-80 shells.
 */
import { clsx } from 'clsx';
import type { HTMLAttributes, ReactNode } from 'react';

export type CardElevation = 'flat' | 'raised' | 'inset';

const ELEVATION_CLASSES: Record<CardElevation, string> = {
  flat: 'bg-dark-70/80 border border-[#374151]/80',
  raised: 'bg-dark-60 border border-[#374151] shadow-none',
  inset: 'bg-dark-80 border border-[#1D232F] shadow-inner shadow-black/20',
};

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  elevation?: CardElevation;
  /** When true, removes the outer padding so a list/table can hug the edges. */
  flush?: boolean;
}

export function Card({
  elevation = 'raised',
  flush = false,
  className,
  children,
  ...rest
}: CardProps) {
  return (
    <div
      className={clsx(
        'rounded-[10px]',
        ELEVATION_CLASSES[elevation],
        !flush && 'p-5',
        className,
      )}
      {...rest}
    >
      {children}
    </div>
  );
}

export interface CardHeaderProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
}

export function CardHeader({
  title,
  description,
  action,
  className,
  children,
  ...rest
}: CardHeaderProps) {
  return (
    <div className={clsx('flex items-start justify-between gap-3 mb-3', className)} {...rest}>
      {children ?? (
        <div className="min-w-0 flex items-start gap-3">
          <span
            aria-hidden
            className="mt-0.5 w-[2px] h-8 shrink-0 rounded-sm bg-teal-10"
          />
          <div className="min-w-0">
            {title && (
              <h3 className="text-sm font-gilroy-semibold text-fg-primary">
                {title}
              </h3>
            )}
            {description && (
              <p className="mt-0.5 text-xs text-amgray-40">{description}</p>
            )}
          </div>
        </div>
      )}
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

export function CardBody({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={clsx('text-sm text-amgray-20', className)} {...rest} />;
}

export function CardFooter({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={clsx(
        'mt-4 flex items-center justify-end gap-2 border-t border-[#374151] pt-3',
        className,
      )}
      {...rest}
    />
  );
}
