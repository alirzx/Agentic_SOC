import { AUTH_TOKEN_KEY, getActiveTenantId } from '@/lib/api';

/**
 * Authenticated JSON fetcher for SWR / ad-hoc browser calls.
 *
 * Console sessions store the JWT in ``localStorage`` (workspace login). Bare
 * ``fetch(url)`` omits that Bearer token and gets 401 from the API — which is
 * exactly how the Correlation graph modal was failing after auth rebinding.
 */
export function browserAuthHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Tenant-Id': getActiveTenantId(),
    ...extra,
  };
  if (typeof window === 'undefined') {
    return headers;
  }
  try {
    const token = window.localStorage.getItem(AUTH_TOKEN_KEY);
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  } catch {
    /* localStorage unavailable */
  }
  return headers;
}

export async function safeFetcher<T = unknown>(url: string): Promise<T> {
  const r = await fetch(url, { headers: browserAuthHeaders(), cache: 'no-store' });
  if (!r.ok) {
    const body = await r.text().catch(() => '');
    const error = new Error(`HTTP ${r.status} ${r.statusText} — ${body.slice(0, 120)}`) as Error & {
      status?: number;
    };
    error.status = r.status;
    throw error;
  }
  return r.json() as Promise<T>;
}
