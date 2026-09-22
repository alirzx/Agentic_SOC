import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const SESSION_COOKIE = 'aisoc.session';

const PROTECTED_PREFIXES = [
  '/dashboard',
  '/alerts',
  '/cases',
  '/hunt',
  '/detection',
  '/threat-intel',
  '/graph',
  '/copilot',
  '/playbooks',
  '/workflow-soc',
  '/marketplace',
  '/connectors',
  '/settings',
  '/compliance',
  '/audit',
  '/queue',
  '/investigate',
  '/onboarding',
  '/mssp',
  '/sla',
  '/fim',
  '/honeytokens',
  '/purple-team',
  '/easm',
  '/coverage-advisor',
  '/noise-tuning',
  '/explore',
  '/shifts',
  '/costs',
  '/analytics',
  '/reports',
  '/identity',
];

function isProtectedPath(pathname: string): boolean {
  return PROTECTED_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (!isProtectedPath(pathname)) {
    return NextResponse.next();
  }
  if (request.cookies.get(SESSION_COOKIE)?.value) {
    return NextResponse.next();
  }
  const url = request.nextUrl.clone();
  url.pathname = '/login';
  url.searchParams.set('next', pathname);
  return NextResponse.redirect(url);
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|api/).*)'],
};
