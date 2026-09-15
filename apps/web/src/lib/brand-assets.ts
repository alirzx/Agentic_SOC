/**
 * Canonical brand asset paths under `apps/web/public/logo/`.
 *
 * Prefer the URL-safe filenames (`logo-mark.svg`, `soorin-attack-detection.svg`).
 * The originals with spaces remain on disk for design handoff.
 */
export const BRAND_LOGO = {
  /** Square Soorin Attack Detection mark (56×56). */
  mark: '/logo/logo-mark.svg',
  /** Full lockup with wordmark (icon + SOORIN ATTACK DETECTION). */
  lockup: '/logo/soorin-attack-detection.svg',
  /** Original filenames (kept for design handoff / docs). */
  markSource: '/logo/logo_sad.svg',
  lockupSource: '/logo/Soorin%20Attack%20Detection%20Logo.svg',
} as const;
