import { BrandLogo } from '@/components/brand/BrandLogo';
import { clsx } from 'clsx';

interface LogoProps {
  size?: number;
  withWordmark?: boolean;
  className?: string;
}

/**
 * Back-compat wrapper — prefer `BrandLogo` for new call sites.
 * Renders assets from `/public/logo/`.
 */
export function Logo({ size = 36, withWordmark = false, className }: LogoProps) {
  return (
    <span className={clsx('inline-flex items-center', className)}>
      <BrandLogo
        variant={withWordmark ? 'nav' : 'mark'}
        size={size}
      />
    </span>
  );
}
