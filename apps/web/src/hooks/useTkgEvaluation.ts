'use client';

/**
 * TKG second opinion: health, the latest stored evaluation, and the run action.
 *
 * A 404 from `latest` is the normal "never run" state, not an error — the panel
 * shows the button instead of an error box.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import useSWR from 'swr';

import { caseTkgApi, type TkgEvaluation, type TkgHealth, type TkgRunSnapshot } from '@/lib/caseTkg';

/** How often the panel asks where the run is. */
const POLL_MS = 800;
/**
 * A run waits for the graph to materialise what it queued. The wait has a server
 * cap (`AISOC_TKG_WAIT_TIMEOUT_S`, 10 minutes) and its own stop control; both only
 * end the wait, never the run — the panel still gets a judged, stored result,
 * which is the point of separating them from **Cancel run** (stores nothing).
 * No client-side timer: the server owns the cap so every client agrees.
 */

function statusOf(error: unknown): number | undefined {
  return (error as { status?: number } | undefined)?.status;
}

export function useTkgEvaluation(caseId: string | null, workspace: string) {
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [live, setLive] = useState<TkgRunSnapshot | null>(null);
  const runIdRef = useRef<string | null>(null);
  const polling = useRef<AbortController | null>(null);

  const health = useSWR<TkgHealth>(['case-tkg-health', workspace], () => caseTkgApi.health(), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  });

  const latest = useSWR<TkgEvaluation>(
    caseId ? ['case-tkg-evaluation', workspace, caseId] : null,
    () => caseTkgApi.latest(caseId as string),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      isPaused: () => running,
    }
  );

  const neverRun = statusOf(latest.error) === 404;

  // A run that could not reach the graph stores `unavailable`, and showing that
  // alone wiped a perfectly good evaluation off the screen because the TKG was
  // busy for one login. Only asked for when the newest row is unusable.
  const unusable = Boolean(latest.data && !['ok', 'partial'].includes(latest.data.status));
  const history = useSWR<TkgEvaluation[]>(
    caseId && unusable ? ['case-tkg-history', workspace, caseId] : null,
    () => caseTkgApi.history(caseId as string, 10),
    { revalidateOnFocus: false, shouldRetryOnError: false }
  );
  const lastUsable =
    (unusable && history.data?.find((row) => row.status === 'ok' || row.status === 'partial')) || null;

  /**
   * Start a run and follow it until it ends, is cancelled, or times out.
   *
   * The old version awaited one request: nothing moved on screen for the whole
   * duration and a slow run looked like a dead button. Now the panel gets a
   * snapshot every {@link POLL_MS}, so its stepper shows which stage is busy and
   * how much of it is done.
   */
  const run = useCallback(
    async (engineVerdict?: string | null, refresh = false) => {
      if (!caseId || polling.current) return null;
      const controller = new AbortController();
      polling.current = controller;
      setRunning(true);
      setRunError(null);
      try {
        let snapshot = await caseTkgApi.startRun(caseId, engineVerdict, refresh);
        if (controller.signal.aborted) return null;
        runIdRef.current = snapshot.run_id;
        setLive(snapshot);

        const deadline = Date.now() + 12 * 60_000;
        while (snapshot.state === 'running' && Date.now() < deadline) {
          await new Promise((resolve) => setTimeout(resolve, POLL_MS));
          if (controller.signal.aborted) return null;
          snapshot = await caseTkgApi.runSnapshot(caseId, snapshot.run_id, controller.signal);
          if (controller.signal.aborted) return null;
          setLive(snapshot);
        }

        if (snapshot.state === 'finished' && snapshot.result) {
          await latest.mutate(snapshot.result, { revalidate: false });
          return snapshot.result;
        }
        // A cancelled (or failed) run now stores what it had already scored as a
        // `partial` row, so the panel must re-read the latest one instead of
        // keeping the previous run on screen.
        if (snapshot.state === 'cancelled' || snapshot.state === 'failed') {
          await latest.mutate();
        }
        // A cancelled run says so in the live panel itself; only a failure needs
        // the error banner, because it has a reason the counters cannot show.
        if (snapshot.state === 'failed') {
          setRunError(snapshot.error ?? 'TKG evaluation failed');
        }
        if (snapshot.state === 'running') setRunError('Evaluation is still running on the server. Refresh to check again.');
        return null;
      } catch (error) {
        if (!controller.signal.aborted) setRunError(error instanceof Error ? error.message : 'TKG evaluation failed');
        return null;
      } finally {
        if (polling.current === controller) {
          polling.current = null;
          runIdRef.current = null;
          setRunning(false);
        }
      }
    },
    [caseId, latest]
  );

  /** Ask the server to stop the run at its next checkpoint. */
  const cancelRun = useCallback(async () => {
    const runId = runIdRef.current;
    if (!caseId || !runId) return;
    try {
      setLive(await caseTkgApi.cancelRun(caseId, runId));
    } catch {
      // The run may have finished between the click and the request.
    }
  }, [caseId]);

  /** Stop waiting for the graph; the run still judges and stores. */
  const skipWait = useCallback(async () => {
    const runId = runIdRef.current;
    if (!caseId || !runId) return;
    try {
      setLive(await caseTkgApi.skipWait(caseId, runId));
    } catch {
      // The wait may have ended between the click and the request.
    }
  }, [caseId]);

  // Leaving the page mid-run stops the polling; the job itself keeps going and
  // its result is stored, so returning to the case shows the finished run.
  useEffect(() => () => {
    polling.current?.abort();
    polling.current = null;
    runIdRef.current = null;
  }, [caseId, workspace]);

  return {
    health: health.data,
    healthLoading: health.isLoading,
    evaluation: latest.data ?? null,
    /** Previous usable run, offered when the newest attempt failed. */
    lastUsable,
    loading: latest.isLoading,
    neverRun,
    error: runError ?? (neverRun ? null : (latest.error as Error | undefined) ?? null),
    running,
    /** Live stage/counters while a run is in flight, null otherwise. */
    live,
    run,
    cancelRun,
    skipWait,
    refresh: latest.mutate,
  };
}
