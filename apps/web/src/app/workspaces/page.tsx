'use client';

/**
 * Post-login workspace picker.
 *
 * A workspace is a tenant isolation boundary. Connectors, alerts, and cases
 * for one workspace are never visible in another.
 */

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { FormEvent, Suspense, useCallback, useEffect, useState } from 'react';
import { BrandLogo } from '@/components/brand/BrandLogo';
import { BRAND } from '@/lib/brand';
import {
  authApi,
  workspacesApi,
  type WorkspaceSummary,
} from '@/lib/api';

export const dynamic = 'force-dynamic';

function sanitizeNext(raw: string | null | undefined): string {
  const fallback = '/dashboard';
  if (!raw) return fallback;
  if (raw.startsWith('//') || raw.startsWith('\\\\')) return fallback;
  if (!raw.startsWith('/')) return fallback;
  if (raw.startsWith('/workspaces')) return fallback;
  return raw;
}

function WorkspacesInner() {
  const router = useRouter();
  const search = useSearchParams();
  const next = sanitizeNext(search?.get('next'));

  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await workspacesApi.list();
      setWorkspaces(list);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load workspaces');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!authApi.isAuthenticated()) {
      router.replace(`/login?next=${encodeURIComponent('/workspaces')}`);
      return;
    }
    void reload();
  }, [reload, router]);

  const enterWorkspace = async (tenantId: string) => {
    if (busyId) return;
    setBusyId(tenantId);
    setError(null);
    try {
      await authApi.selectWorkspace(tenantId);
      router.replace(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not enter workspace');
      setBusyId(null);
    }
  };

  const createWorkspace = async (event: FormEvent) => {
    event.preventDefault();
    const name = newName.trim();
    if (name.length < 2 || creating) return;
    setCreating(true);
    setError(null);
    try {
      const created = await workspacesApi.create(name);
      setNewName('');
      await authApi.selectWorkspace(created.id);
      router.replace(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create workspace');
      setCreating(false);
    }
  };

  return (
    <div className="min-h-screen bg-dark-80 text-white antialiased flex flex-col font-sans">
      <div className="flex-1 flex items-center justify-center px-6 py-16">
        <div className="w-full max-w-lg">
          <div className="flex flex-col items-center text-center mb-10">
            <Link href="/" className="mb-5 transition hover:opacity-90" aria-label={`${BRAND.product} home`}>
              <BrandLogo variant="lockup" size={118} priority />
            </Link>
            <h1 className="text-2xl font-semibold tracking-tight">Choose a workspace</h1>
            <p className="mt-2 text-sm text-slate-400 max-w-sm">
              Connectors and security data stay isolated inside the workspace you select.
            </p>
          </div>

          {error ? (
            <div className="mb-4 rounded-lg border border-red-800/50 bg-red-950/40 px-3 py-2 text-sm text-red-200">
              {error}
            </div>
          ) : null}

          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 space-y-2">
            {loading ? (
              <p className="text-sm text-slate-400 py-6 text-center">Loading workspaces…</p>
            ) : workspaces.length === 0 ? (
              <p className="text-sm text-slate-400 py-4 text-center">
                No workspaces yet. Create one below.
              </p>
            ) : (
              workspaces.map((ws) => (
                <button
                  key={ws.id}
                  type="button"
                  disabled={busyId !== null}
                  onClick={() => void enterWorkspace(ws.id)}
                  className="w-full text-left rounded-lg border border-slate-700/80 bg-slate-950/40 px-4 py-3 hover:border-teal-600/60 hover:bg-slate-900 transition disabled:opacity-60"
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-medium text-slate-100">{ws.name}</div>
                      <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                        {ws.slug}
                        {ws.is_home ? ' · home' : ''}
                        {' · '}
                        {ws.membership_role}
                      </div>
                    </div>
                    <span className="text-xs text-teal-300 shrink-0">
                      {busyId === ws.id ? 'Entering…' : 'Enter'}
                    </span>
                  </div>
                </button>
              ))
            )}
          </div>

          <form onSubmit={(e) => void createWorkspace(e)} className="mt-6 rounded-xl border border-slate-800 bg-slate-900/50 p-4">
            <h2 className="text-sm font-semibold text-slate-200 mb-3">Create a workspace</h2>
            <div className="flex gap-2">
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g. Production SOC"
                maxLength={120}
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-teal-500"
              />
              <button
                type="submit"
                disabled={creating || newName.trim().length < 2}
                className="rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500 disabled:opacity-50"
              >
                {creating ? 'Creating…' : 'Create'}
              </button>
            </div>
          </form>

          <div className="mt-6 text-center">
            <button
              type="button"
              className="text-xs text-slate-500 underline hover:text-slate-300"
              onClick={() => {
                authApi.logout();
                router.replace('/login');
              }}
            >
              Sign out
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function WorkspacesPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-dark-80 flex items-center justify-center text-sm text-slate-400">
          Loading…
        </div>
      }
    >
      <WorkspacesInner />
    </Suspense>
  );
}
