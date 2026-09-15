import Image from 'next/image';
import Link from 'next/link';
import { BRAND } from '@/lib/brand';

const LOGIN_HREF = '/login';
const GET_STARTED_HREF = '/login';

/**
 * Product splash at `/` — pixel-faithful to `Hero Section.jpg`.
 *
 * The designed frame (logo, headline, copy, CTAs, mesh) lives in the
 * background image. We do NOT re-render that copy as HTML on top (that
 * caused the ghosting/double-text bug). Clickable hotspots sit over the
 * designed Log in / Get started buttons so the page stays interactive
 * and accessible.
 */
export function SoorinHero() {
  return (
    <main className="relative h-dvh w-full overflow-hidden bg-[#05080f]">
      <Image
        src="/soorin-hero.jpg"
        alt=""
        fill
        priority
        sizes="100vw"
        className="object-cover object-left lg:object-center"
      />

      <h1 className="sr-only">{BRAND.product}.</h1>
      <p className="sr-only">
        Discover relationships between assets, services, users, and network
        activity. Analyze connections, detect anomalies, and investigate your
        infrastructure with AI-powered insights.
      </p>

      {/* Brand mark hotspot (top-left pill in the art) */}
      <Link
        href="/"
        aria-label={BRAND.product}
        className="absolute left-[2.8%] top-[3.8%] z-10 h-[5.2%] w-[18%] min-h-[40px] min-w-[140px] max-h-[56px] max-w-[220px] rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#6ff3df] focus-visible:ring-offset-2 focus-visible:ring-offset-[#05080f]"
      />

      {/* Log in — matches the teal pill in the top-right of the art */}
      <Link
        href={LOGIN_HREF}
        aria-label="Log in"
        className="absolute right-[3.2%] top-[4%] z-10 h-[5%] w-[9.5%] min-h-[40px] min-w-[96px] max-h-[52px] max-w-[140px] rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#6ff3df] focus-visible:ring-offset-2 focus-visible:ring-offset-[#05080f]"
      />

      {/* Get started — matches the primary CTA under the hero copy */}
      <Link
        href={GET_STARTED_HREF}
        aria-label="Get started"
        className="absolute left-[5.5%] top-[61%] z-10 h-[6.5%] w-[14%] min-h-[44px] min-w-[130px] max-h-[58px] max-w-[200px] rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#6ff3df] focus-visible:ring-offset-2 focus-visible:ring-offset-[#05080f] sm:left-[6%] sm:top-[58%] lg:left-[7%] lg:top-[56%]"
      />
    </main>
  );
}
