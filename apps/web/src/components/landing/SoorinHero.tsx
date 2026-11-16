import Link from "next/link";
import { BrandWordmark } from "@/components/brand/BrandWordmark";
import { BRAND } from "@/lib/brand";

const LOGIN_HREF = "/login";
const GET_STARTED_HREF = "/login";

const SUBCOPY_LEAD =
  "Detect threats, investigate security incidents, and automate your security operations with AI-powered intelligence. Correlate alerts, uncover hidden attack patterns, and accelerate incident response with autonomous";
const SUBCOPY_EMPHASIS = "AI agents";

/**
 * Landing hero — real HTML/CSS matching the Soorin light hero design.
 * The wave-line art and teal glows are decorative only
 * (`/landing-hero-bg.svg`, extracted from the design with no baked-in UI
 * text); all copy and CTAs are coded so nothing is a zoomed screenshot.
 *
 * Colours are explicit hex values on purpose: this splash keeps its light
 * design regardless of the console theme.
 */
export function SoorinHero() {
  return (
    <main className="relative flex min-h-dvh flex-col overflow-hidden bg-[#ffffff] font-sans text-[#121724]">
      {/* Decorative background — glows + wave lines */}
      {/* eslint-disable-next-line @next/next/no-img-element -- decorative SVG art */}
      <img
        src="/landing-hero-bg.svg"
        alt=""
        aria-hidden
        className="pointer-events-none absolute inset-0 h-full w-full select-none object-cover object-[70%_50%] opacity-70"
      />

      <header className="relative z-10 flex items-center justify-between px-5 pl-6 py-6 sm:px-10 lg:px-20 lg:py-8">
        <Link
          href="/"
          aria-label={BRAND.product}
          // Inline colour: the light-theme remap layer turns the dark-surface
          // utility `bg-[#121724]` white, but this pill is dark by design.
          style={{ backgroundColor: "#121724" }}
          className="inline-flex h-12 items-center rounded-full pl-3 pr-1 transition hover:opacity-90 sm:h-16 sm:pr-1"
        >
          <span className="sm:hidden">
            <BrandWordmark height={30} textClassName="text-[#ffffff]" />
          </span>
          <span className="hidden sm:inline">
            <BrandWordmark height={36} textClassName="text-[#ffffff]" />
          </span>
        </Link>

        <Link
          href={LOGIN_HREF}
          className="inline-flex h-[47px] items-center gap-2.5 rounded-full border border-[#4FD2C2] bg-[#4FD2C2] px-7 text-[15px] font-gilroy-medium text-[#ffffff] transition hover:bg-[#3AC7B6]"
        >
          <LoginGlyph />
          Log in
        </Link>
      </header>

      <div className="relative z-10 flex flex-1 flex-col justify-center px-5 pb-20 sm:px-10 lg:px-[110px]">
        <h1 className="font-gilroy-bold text-[2.75rem] leading-[1.05] tracking-[-0.02em] text-[#121724] sm:text-6xl lg:text-[5.4rem]">
          Ai-powered SOC.
        </h1>
        <p className="mt-8 max-w-[1020px] text-base leading-[1.65] text-[#121724] sm:text-lg lg:text-[23px] font-gilroy-medium">
          {SUBCOPY_LEAD}{" "}
          <span className="font-gilroy-semibold text-[#4FD2C2]">{SUBCOPY_EMPHASIS}</span>.
        </p>
        <Link
          href={GET_STARTED_HREF}
          className="mt-12 inline-flex h-[54px] w-fit items-center gap-4 rounded-[10px] bg-[#58DFCF] px-8 text-[19px] font-gilroy-semibold text-[#ffffff] shadow-[0_0_0_3px_rgba(106,248,231,0.25)] transition hover:bg-[#4FD2C2]"
        >
          Get started
          <ArrowGlyph />
        </Link>
      </div>
    </main>
  );
}

function LoginGlyph() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M9.6 7.6c.3-3.3 2-4.6 5.7-4.6h.1c4.1 0 5.7 1.6 5.7 5.7v6.6c0 4.1-1.6 5.7-5.7 5.7h-.1c-3.6 0-5.3-1.3-5.7-4.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M3 12h11.9M12.7 8.6 16 12l-3.3 3.4"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function ArrowGlyph() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M4 12h15M13 6l6 6-6 6"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
