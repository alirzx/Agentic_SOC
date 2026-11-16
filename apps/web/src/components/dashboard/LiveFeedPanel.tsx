'use client';

/**
 * LiveFeedPanel
 *
 * Subscribes to the realtime `alerts` channel and renders the most recent
 * fused alerts as a live-streaming list. When no events have arrived yet,
 * the panel shows an honest empty state — never fabricated demo events.
 *
 * The status pill reflects the actual WebSocket state:
 *   - "Live"          → connected and receiving
 *   - "Reconnecting"  → connecting / closing / closed (auto-retry)
 *   - "Waiting"       → connected (or idle) with no events yet
 */

import { useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import { useRealtimeChannel, type RealtimeStatus } from '@/lib/realtime';
import { Card, CardHeader } from './ui';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface LiveEvent {
  id: string;
  severity: Severity;
  text: string;
  source: string;
  receivedAt: number; // epoch ms
  isDemo?: boolean;
}

/**
 * Loose shape of the message broadcast by `services/realtime`. The realtime
 * service forwards Kafka messages from `aisoc.alerts.fused` so the inner
 * `payload` may carry either the full envelope or the unwrapped alert.
 */
interface RealtimeAlertMessage {
  type?: string;
  timestamp?: string;
  payload?: {
    alert?: AlertLike;
    tenant_id?: string;
    severity?: string;
    title?: string;
    description?: string;
    source?: string;
    source_system?: string;
  } & AlertLike;
}

interface AlertLike {
  id?: string;
  severity?: string;
  title?: string;
  description?: string;
  source?: string;
  source_system?: string;
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-[#FD4E4E]/15 text-[#FD4E4E] border border-[#FD4E4E]/70',
  high: 'bg-[#F98B3E]/15 text-[#F98B3E] border border-[#F98B3E]/70',
  medium: 'bg-[#F2BD57]/15 text-[#D99A1E] border border-[#F2BD57]/70',
  low: 'bg-teal-20/15 text-teal-10 border border-teal-20/70',
  info: 'bg-gray-500/15 text-fg-muted border border-gray-500/50',
};

const MAX_VISIBLE = 12;

function normalizeSeverity(value: unknown): Severity {
  const v = String(value ?? '').toLowerCase();
  if (v === 'critical' || v === 'high' || v === 'medium' || v === 'low' || v === 'info') {
    return v;
  }
  return 'info';
}

function relativeTime(receivedAt: number, now: number): string {
  const diff = Math.max(0, Math.floor((now - receivedAt) / 1000));
  if (diff < 1) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  const minutes = Math.floor(diff / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function statusToLabel(status: RealtimeStatus, hasReal: boolean): {
  label: string;
  tone: 'live' | 'reconnect' | 'waiting';
} {
  if (status === 'open' && hasReal) return { label: 'Live', tone: 'live' };
  if (status === 'open') return { label: 'Waiting', tone: 'waiting' };
  if (status === 'connecting') return { label: 'Connecting…', tone: 'reconnect' };
  if (status === 'closing' || status === 'closed' || status === 'error') {
    return { label: hasReal ? 'Reconnecting…' : 'Offline', tone: hasReal ? 'reconnect' : 'waiting' };
  }
  return { label: 'Waiting', tone: 'waiting' };
}

function eventFromMessage(msg: RealtimeAlertMessage, fallbackId: number): LiveEvent | null {
  if (!msg) return null;
  // The realtime service wraps payloads as { type: 'alert.fused', payload, timestamp }
  // but tests / older producers may send the alert directly.
  const payload = msg.payload ?? (msg as unknown as RealtimeAlertMessage['payload']);
  if (!payload) return null;

  const inner: AlertLike = (payload as { alert?: AlertLike }).alert ?? (payload as AlertLike);
  const title =
    inner.title ??
    inner.description ??
    (payload as { title?: string }).title ??
    (payload as { description?: string }).description ??
    'Security event received';
  const source =
    inner.source ??
    inner.source_system ??
    (payload as { source?: string }).source ??
    (payload as { source_system?: string }).source_system ??
    'AiSOC';

  const tsRaw = msg.timestamp ? Date.parse(msg.timestamp) : Date.now();
  const receivedAt = Number.isFinite(tsRaw) ? tsRaw : Date.now();

  return {
    id: inner.id ?? `live-${receivedAt}-${fallbackId}`,
    severity: normalizeSeverity(inner.severity ?? (payload as { severity?: string }).severity),
    text: title,
    source,
    receivedAt,
  };
}

export function LiveFeedPanel() {
  const { last, status } = useRealtimeChannel<RealtimeAlertMessage>('alerts');

  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const counterRef = useRef(0);

  // Append new realtime events to the top of the list, dedup by id.
  useEffect(() => {
    if (!last) return;
    counterRef.current += 1;
    const next = eventFromMessage(last, counterRef.current);
    if (!next) return;
    setEvents((prev) => {
      if (prev.some((e) => e.id === next.id)) return prev;
      return [next, ...prev].slice(0, MAX_VISIBLE);
    });
  }, [last]);

  // Tick the clock every second so relative timestamps stay current.
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, []);

  const hasReal = events.length > 0;
  const visible = events;
  const pill = statusToLabel(status, hasReal);

  return (
    <Card className="p-6">
      <CardHeader
        title="Live Feed"
        subtitle="Most recent alerts from connected sources"
        className="mb-4"
        action={
          <span
            className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-surface-border bg-surface-hover px-3 py-1 text-xs text-fg-muted"
            title={
              pill.tone === 'waiting'
                ? 'No fused alerts yet — connect Splunk (or another source) to start the feed'
                : `WebSocket: ${status}`
            }
          >
            <span
              className={clsx(
                'w-1.5 h-1.5 rounded-full',
                pill.tone === 'live' && 'bg-green-500 animate-pulse',
                pill.tone === 'reconnect' && 'bg-[#F2BD57] animate-pulse',
                pill.tone === 'waiting' && 'bg-gray-500',
              )}
            />
            {pill.label}
          </span>
        }
      />

      <div className="overflow-y-auto max-h-[272px] pr-1 divide-y divide-surface-border">
        {visible.length === 0 ? (
          <p className="text-xs text-fg-muted py-6 text-center">
            Waiting for live alerts from connected sources…
          </p>
        ) : (
          visible.map((event) => (
          <div key={event.id} className="flex items-center gap-3 py-2.5">
            <span
              className={clsx(
                'w-[66px] text-center text-xs py-1 rounded font-gilroy-medium shrink-0',
                SEVERITY_COLORS[event.severity],
              )}
            >
              {event.severity.toUpperCase().slice(0, 4)}
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-sm text-fg-secondary leading-tight truncate">{event.text}</p>
              <p className="text-[10px] text-fg-subtle mt-0.5">
                {event.source} · {relativeTime(event.receivedAt, now)}
              </p>
            </div>
          </div>
          ))
        )}
      </div>
    </Card>
  );
}
