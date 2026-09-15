import { clsx } from 'clsx';
import { BRAND } from '@/lib/brand';
import { BRAND_LOGO } from '@/lib/brand-assets';

export type BrandLogoVariant = 'mark' | 'lockup' | 'nav';

export interface BrandLogoProps {
  /** `mark` = square icon; `lockup` = full SVG wordmark; `nav` = mark + text. */
  variant?: BrandLogoVariant;
  /** Pixel size for the mark / lockup image height. */
  size?: number;
  className?: string;
  /** Kept for API compatibility with Image-based call sites. */
  priority?: boolean;
}

/**
 * Single brand logo component for the whole web app.
 * Always loads assets from `/public/logo/`.
 */
export function BrandLogo({
  variant = 'mark',
  size = 32,
  className,
}: BrandLogoProps) {
  if (variant === 'lockup') {
    const width = Math.round(size * (93 / 118));
    return (
      // eslint-disable-next-line @next/next/no-img-element -- SVG brand asset
      <img
        src={BRAND_LOGO.lockup}
        alt={BRAND.product}
        width={width}
        height={size}
        className={clsx('shrink-0 object-contain', className)}
      />
    );
  }

  if (variant === 'nav') {
    return (
      <span className={clsx('inline-flex items-center gap-2.5', className)}>
        {/* eslint-disable-next-line @next/next/no-img-element -- SVG brand asset */}
        <img
          src={BRAND_LOGO.mark}
          alt=""
          width={size}
          height={size}
          className="shrink-0 rounded-[10px] object-contain"
        />
        <span className="leading-tight">
          <span className="block text-[11px] font-gilroy-bold tracking-[0.16em] text-white uppercase">
            {BRAND.shortName}
          </span>
          <span className="block text-[9px] font-gilroy-medium tracking-wide text-amgray-40">
            Attack Detection
          </span>
        </span>
      </span>
    );
  }

  return (
    // eslint-disable-next-line @next/next/no-img-element -- SVG brand asset
    <img
      src={BRAND_LOGO.mark}
      alt={BRAND.product}
      width={size}
      height={size}
      className={clsx('shrink-0 rounded-[10px] object-contain', className)}
    />
  );
}
