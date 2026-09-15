'use client';

/**
 * Desktop console login.
 *
 * Email + password against ``POST /api/v1/auth/login`` for the open-source
 * console. The mobile responder PWA at ``/responder/login`` uses passkeys; this
 * page is the desktop counterpart and the link target from the responder login
 * footer ("Sign in on desktop").
 *
 * Demo credentials live in `services/api/app/api/v1/dev_auth.py`:
 *   demo@tryaisoc.com / aisoc-demo
 */

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useEffect, useState } from 'react';
import { authApi } from '@/lib/api';
import { BrandLogo } from '@/components/brand/BrandLogo';
import { BRAND } from '@/lib/brand';

type Phase = 'idle' | 'pending' | 'success' | 'error';

export const dynamic = 'force-dynamic';

const DEMO_EMAIL = 'demo@tryaisoc.com';
const DEMO_PASSWORD = 'aisoc-demo';

/**
 * Sanitize the ``?next=`` redirect target so a crafted link can't be used to
 * bounce an authenticated user to an attacker-controlled host.
 *
 * Only same-origin relative paths are allowed. Anything that looks like an
 * absolute URL (``http://``, ``//evil.com``), a JS scheme, or a path that
 * doesn't start with a single ``/`` is replaced with the dashboard default.
 */
function sanitizeNext(raw: string | null | undefined): string {
  const fallback = '/dashboard';
  if (!raw) return fallback;
  if (raw.startsWith('//') || raw.startsWith('\\\\')) return fallback;
  if (!raw.startsWith('/')) return fallback;
  if (raw.startsWith('/\\')) return fallback;
  return raw;
}

function LoginInner() {
  const router = useRouter();
  const search = useSearchParams();
  const next = sanitizeNext(search?.get('next'));

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (authApi.isAuthenticated()) {
      router.replace(next);
    }
  }, [next, router]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (phase === 'pending') return;
    setPhase('pending');
    setError(null);

    try {
      await authApi.login(email.trim(), password);
      setPhase('success');
      router.replace(next);
    } catch (err) {
      console.error('[login] failed', err);
      setPhase('error');
      const message = err instanceof Error ? err.message : 'Login failed.';
      if (/401|incorrect/i.test(message)) {
        setError('Email or password incorrect.');
      } else {
        setError(message);
      }
    }
  };

  const useDemo = () => {
    setEmail(DEMO_EMAIL);
    setPassword(DEMO_PASSWORD);
  };

  return (
    <div className="min-h-screen bg-dark-80 text-white antialiased flex flex-col font-sans">
      <div className="flex-1 flex items-center justify-center px-6 py-16">
        <div className="w-full max-w-md">
          <div className="flex flex-col items-center text-center mb-10">
            <Link
              href="/"
              className="mb-5 transition hover:opacity-90"
              aria-label={`Back to ${BRAND.product} home`}
            >
              <BrandLogo variant="lockup" size={118} priority />
            </Link>
            <h1 className="text-2xl font-gilroy-bold tracking-tight text-white">
              Sign in to {BRAND.shortName}
            </h1>
            <p className="text-sm text-amgray-40 mt-2 leading-relaxed font-gilroy-medium">
              Open-source AI SOC console. Use the demo credentials below or
              your own tenant&rsquo;s account.
            </p>
          </div>

          <div className="mb-6 rounded-[10px] border border-teal-20/30 bg-teal-20/5 px-4 py-3 text-sm">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-gilroy-semibold text-teal-10">Public demo</p>
                <p className="text-xs text-amgray-40 mt-0.5">
                  <code className="text-amgray-20">demo@tryaisoc.com</code> /{' '}
                  <code className="text-amgray-20">aisoc-demo</code>
                </p>
              </div>
              <button
                type="button"
                onClick={useDemo}
                className="shrink-0 rounded-[6px] border border-teal-20/40 bg-teal-20/10 px-3 py-1.5 text-xs font-gilroy-semibold text-teal-20 hover:bg-teal-20/20 transition"
              >
                Use demo
              </button>
            </div>
          </div>

          <form onSubmit={submit} className="space-y-4" noValidate>
            <label className="block">
              <span className="block text-xs uppercase tracking-wider text-amgray-50 mb-2 font-gilroy-medium">
                Email
              </span>
              <input
                type="email"
                autoComplete="username"
                inputMode="email"
                autoCapitalize="off"
                spellCheck={false}
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={phase === 'pending'}
                required
                className="w-full bg-dark-70 border border-[#374151] rounded-[10px] px-4 py-3 text-sm text-white placeholder:text-amgray-50 focus:outline-none focus:ring-2 focus:ring-teal-20/50 focus:border-teal-20/50 disabled:opacity-60 font-gilroy-medium"
              />
            </label>

            <label className="block">
              <span className="block text-xs uppercase tracking-wider text-amgray-50 mb-2 font-gilroy-medium">
                Password
              </span>
              <input
                type="password"
                autoComplete="current-password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={phase === 'pending'}
                required
                className="w-full bg-dark-70 border border-[#374151] rounded-[10px] px-4 py-3 text-sm text-white placeholder:text-amgray-50 focus:outline-none focus:ring-2 focus:ring-teal-20/50 focus:border-teal-20/50 disabled:opacity-60 font-gilroy-medium"
              />
            </label>

            <button
              type="submit"
              disabled={phase === 'pending' || !email || !password}
              className="w-full bg-teal-20 hover:bg-teal-10 active:bg-brand-600 text-dark-80 font-gilroy-semibold rounded-[6px] py-3 px-4 transition flex items-center justify-center gap-2 disabled:bg-dark-20 disabled:text-amgray-50 shadow-glow-teal"
            >
              {phase === 'pending' ? (
                <>
                  <svg
                    className="w-4 h-4 animate-spin"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="3"
                    />
                    <path
                      className="opacity-90"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
                    />
                  </svg>
                  <span>Signing in…</span>
                </>
              ) : (
                <span>Sign in</span>
              )}
            </button>

            {error ? (
              <div
                role="alert"
                className="rounded-[6px] border border-red-500/40 bg-red-500/10 px-3 py-2.5 text-xs text-red-300"
              >
                {error}
              </div>
            ) : null}
          </form>

          <div className="mt-8 space-y-3 text-center">
            <p className="text-xs text-amgray-50">
              On a phone?{' '}
              <Link
                href="/responder/login"
                className="text-teal-20 hover:text-teal-10 underline-offset-2 hover:underline"
              >
                Use the responder PWA
              </Link>{' '}
              with passkeys.
            </p>
            <p className="text-[11px] text-amgray-50">
              <Link
                href="/"
                className="hover:text-amgray-30 underline-offset-2 hover:underline"
              >
                ← Back to tryaisoc.com
              </Link>
            </p>
          </div>
        </div>
      </div>

      <div className="px-6 pb-[max(1rem,env(safe-area-inset-bottom))] pt-4 text-center">
        <p className="text-[10px] text-amgray-50 uppercase tracking-widest font-gilroy-medium">
          {BRAND.product} · MIT-licensed · Open-source AI SOC
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginInner />
    </Suspense>
  );
}
