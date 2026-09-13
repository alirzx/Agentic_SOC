import Image from 'next/image';
import Link from 'next/link';
import { BRAND } from '@/lib/brand';

const LOGIN_HREF = '/login';
const GET_STARTED_HREF = '/login';
const SUBCOPY_LEAD =
  'Discover relationships between assets, services, users, and network activity. Analyze connections, detect anomalies, and investigate your infrastructure with';
const SUBCOPY_EMPHASIS = 'AI-powered';
const SUBCOPY_TAIL = 'insights.';

/**
 * Single-screen product splash shown at `/`.
 *
 * The atmospheric mesh is the design reference (`public/soorin-hero.jpg`);
 * logo, copy, and CTAs are real HTML so Log in / Get started stay clickable
 * and accessible at every viewport.
 */
export function SoorinHero() {
  return (
    <main className="relative flex h-dvh flex-col overflow-hidden bg-[#06141c] font-sans text-white">
      <Image
        src="/soorin-hero.jpg"
        alt=""
        fill
        priority
        sizes="100vw"
        className="object-cover object-right"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-gradient-to-r from-[#06141c] via-[#06141c]/88 to-[#06141c]/20 sm:via-[#06141c]/78 sm:to-transparent"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_left,_rgba(45,212,191,0.16),_transparent_55%)]"
      />
      <header className="relative z-10 flex items-center justify-between px-5 py-6 sm:px-10 lg:px-14">
        <BrandMark />
        <Link
          href={LOGIN_HREF}
          className="inline-flex items-center gap-2 rounded-full bg-[#6ff3df] px-5 py-2 text-sm font-semibold text-[#06242a] shadow-[0_8px_24px_rgba(111,243,223,0.28)] transition hover:bg-[#8af7e7]"
        >
          <LoginGlyph />
          Log in
        </Link>
      </header>
      <div className="relative z-10 flex flex-1 flex-col justify-center px-5 pb-16 sm:px-10 lg:max-w-3xl lg:px-14">
        <h1 className="text-[2.6rem] font-semibold leading-[1.05] tracking-[-0.04em] sm:text-6xl lg:text-[4.35rem]">
          Soorin{' '}
          <br />
          Agentic SOC.
        </h1>
        <p className="mt-7 max-w-xl text-base leading-relaxed text-slate-200/85 sm:text-lg">
          {SUBCOPY_LEAD}{' '}
          <span className="font-medium text-[#6ff3df]">{SUBCOPY_EMPHASIS}</span>{' '}
          {SUBCOPY_TAIL}
        </p>
        <Link
          href={GET_STARTED_HREF}
          className="mt-10 inline-flex w-fit items-center gap-2 rounded-full bg-[#6ff3df] px-7 py-3 text-base font-semibold text-[#06242a] shadow-[0_10px_28px_rgba(111,243,223,0.3)] transition hover:bg-[#8af7e7]"
        >
          Get started
          <span aria-hidden>→</span>
        </Link>
      </div>
    </main>
  );
}

function BrandMark() {
  return (
    <Link
      href="/"
      className="inline-flex items-center gap-2.5 rounded-full border border-white/15 bg-[#0b1c24]/80 px-3 py-1.5 backdrop-blur-sm"
      aria-label={BRAND.product}
    >
      <SoorinGlyph />
      <span className="leading-tight">
        <span className="block text-[11px] font-semibold tracking-[0.18em] text-white">
          SOORIN
        </span>
        <span className="block text-[9px] font-medium tracking-wide text-slate-400">
          Alliance Detection
        </span>
      </span>
    </Link>
  );
}

function SoorinGlyph() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M7 7.5c0-2 1.7-3.5 5-3.5 2.6 0 4.2 1 5.1 2.2"
        stroke="#6ff3df"
        strokeWidth="2.1"
        strokeLinecap="round"
      />
      <path
        d="M17 16.5c0 2-1.7 3.5-5 3.5-2.6 0-4.2-1-5.1-2.2"
        stroke="#6ff3df"
        strokeWidth="2.1"
        strokeLinecap="round"
      />
      <path
        d="M8.2 14.6c.9 1.1 2.3 1.8 4.3 1.8 3.1 0 4.5-1.6 4.5-3.4 0-1.6-1.1-2.5-3.8-3.1-2.4-.5-3.7-1.2-3.7-2.7 0-.6.2-1.1.6-1.6"
        stroke="white"
        strokeWidth="2.1"
        strokeLinecap="round"
      />
    </svg>
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
