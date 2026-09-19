import Image from 'next/image';
import Link from 'next/link';
import { BrandLogo } from '@/components/brand/BrandLogo';
import { BRAND } from '@/lib/brand';

const LOGIN_HREF = '/login';
const GET_STARTED_HREF = '/login';

const SUBCOPY_LEAD =
  'Discover relationships between assets, services, users, and network activity. Analyze connections, detect anomalies, and investigate your infrastructure with';
const SUBCOPY_EMPHASIS = 'AI-powered';
const SUBCOPY_TAIL = 'insights.';

/**
 * Landing hero — real HTML/CSS matching the Soorin design.
 * Mesh art is decorative only (`soorin-hero-mesh.jpg`); all copy and CTAs
 * are coded so nothing is a zoomed screenshot.
 */
export function SoorinHero() {
  return (
    <main className="relative flex h-dvh flex-col overflow-hidden bg-[#05080f] font-sans text-white">
      {/* Decorative mesh — right side only, no baked-in UI text */}
      <div className="pointer-events-none absolute inset-y-0 right-0 w-[70%] sm:w-[65%] lg:w-[58%]">
        <Image
          src="/soorin-hero-mesh.jpg"
          alt=""
          fill
          priority
          sizes="(max-width: 1024px) 70vw, 58vw"
          className="object-cover object-left"
        />
        <div className="absolute inset-0 bg-gradient-to-r from-[#05080f] via-[#05080f]/55 to-transparent" />
        <div className="absolute inset-0 bg-gradient-to-t from-[#05080f]/80 via-transparent to-[#05080f]/35" />
      </div>

      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,_rgba(79,210,194,0.14),_transparent_42%)]"
      />

      <header className="relative z-10 flex items-center justify-between px-5 py-5 sm:px-10 lg:px-14">
        <Link
          href="/"
          aria-label={BRAND.product}
          className="inline-flex items-center rounded-full border border-white/15 bg-[#0b1c24]/75 px-3 py-1.5 backdrop-blur-sm transition hover:border-teal-20/40"
        >
          <BrandLogo variant="nav" size={28} />
        </Link>

        <Link
          href={LOGIN_HREF}
          className="inline-flex items-center gap-2 rounded-full bg-[#6ff3df] px-5 py-2 text-sm font-gilroy-semibold text-[#06242a] shadow-[0_8px_24px_rgba(111,243,223,0.28)] transition hover:bg-[#8af7e7]"
        >
          <LoginGlyph />
          Log in
        </Link>
      </header>

      <div className="relative z-10 flex flex-1 flex-col justify-center px-5 pb-16 sm:px-10 lg:max-w-3xl lg:px-14">
        <h1 className="font-gilroy-bold text-[2.6rem] leading-[1.05] tracking-[-0.04em] text-white sm:text-6xl lg:text-[4.35rem]">
          Soorin
          <br />
          Agentic SOC.
        </h1>
        <p className="mt-7 max-w-xl text-base leading-relaxed text-white/85 sm:text-lg font-gilroy-medium">
          {SUBCOPY_LEAD}{' '}
          <span className="font-gilroy-semibold text-[#6ff3df]">{SUBCOPY_EMPHASIS}</span>{' '}
          {SUBCOPY_TAIL}
        </p>
        <Link
          href={GET_STARTED_HREF}
          className="mt-10 inline-flex w-fit items-center gap-2 rounded-full bg-[#6ff3df] px-7 py-3 text-base font-gilroy-semibold text-[#06242a] shadow-[0_10px_28px_rgba(111,243,223,0.3)] transition hover:bg-[#8af7e7]"
        >
          Get started
          <span aria-hidden>→</span>
        </Link>
      </div>
    </main>
  );
}

function LoginGlyph() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <path
        d="M10 17l5-5-5-5M15 12H3"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
