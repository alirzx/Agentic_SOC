/**
 * Console Button primitive — AssetManagement visual language.
 *
 * Variants mirror AssetManagment_Front PrimaryButton / shadcn button:
 * teal primary CTA, dark secondary panels, soft outline borders.
 */
import { clsx } from 'clsx';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { forwardRef } from 'react';

export type ButtonVariant =
  | 'primary'
  | 'secondary'
  | 'destructive'
  | 'ghost'
  | 'outline';

export type ButtonSize = 'xs' | 'sm' | 'md' | 'lg';

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary:
    'bg-teal-20 text-dark-80 shadow-glow-teal hover:bg-teal-10 active:bg-brand-600 disabled:bg-teal-20/40',
  secondary:
    'bg-dark-10 text-amgray-30 border border-[#374151] hover:text-white hover:bg-dark-20 active:bg-dark-20 disabled:opacity-40',
  destructive:
    'bg-red-600 text-white hover:bg-red-500 active:bg-red-700 disabled:bg-red-600/40',
  ghost:
    'bg-transparent text-amgray-30 hover:bg-dark-20/60 hover:text-white disabled:text-amgray-50',
  outline:
    'bg-transparent text-teal-20 border border-teal-20/40 hover:bg-teal-20/10 hover:border-teal-20 disabled:opacity-50',
};

const SIZE_CLASSES: Record<ButtonSize, string> = {
  xs: 'h-7 px-2 text-xs gap-1.5 rounded-[6px]',
  sm: 'h-8 px-3 text-xs gap-1.5 rounded-[6px]',
  md: 'h-9 px-4 text-sm gap-2 rounded-[6px]',
  lg: 'h-10 px-8 text-sm font-semibold gap-2 rounded-[6px]',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
  /** Renders an inline spinner and disables the button. */
  loading?: boolean;
  /** Sets ``aria-pressed`` and a subtle pressed style; used for toggles. */
  pressed?: boolean;
}

/**
 * Console button primitive. Forwards its ref so popovers and tooltips
 * can anchor to it without contortions.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'primary',
    size = 'md',
    leadingIcon,
    trailingIcon,
    loading = false,
    pressed,
    disabled,
    className,
    children,
    type = 'button',
    ...rest
  },
  ref,
) {
  const isDisabled = disabled || loading;
  return (
    <button
      ref={ref}
      type={type}
      disabled={isDisabled}
      aria-pressed={pressed}
      aria-busy={loading || undefined}
      className={clsx(
        'inline-flex items-center justify-center font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-teal-20/60 disabled:cursor-not-allowed',
        VARIANT_CLASSES[variant],
        SIZE_CLASSES[size],
        pressed && 'ring-1 ring-teal-20/40',
        className,
      )}
      {...rest}
    >
      {loading ? (
        <span
          aria-hidden="true"
          className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-r-transparent"
        />
      ) : (
        leadingIcon
      )}
      <span>{children}</span>
      {!loading && trailingIcon}
    </button>
  );
});
