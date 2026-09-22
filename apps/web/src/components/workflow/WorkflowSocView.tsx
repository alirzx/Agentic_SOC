'use client';

/**
 * Workflow SOC — executive animated view of the Agentic SOC lifecycle.
 * Start: connectors / ingest → End: Jira ticket. Presentational only.
 */

import { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { clsx } from 'clsx';

interface WorkflowStep {
  id: string;
  number: string;
  title: string;
  summary: string;
  detail: string;
  accent: string;
  glow: string;
  /** Percent along the pipe path (0–100) for the traveling pulse */
  pathPercent: number;
}

const STEPS: WorkflowStep[] = [
  {
    id: 'ingest',
    number: '01',
    title: 'Connectors & Ingest',
    summary: 'SIEM, EDR, cloud, and identity sources stream into AiSOC.',
    detail: 'Live connectors poll and push events into the ingest spine (OCSF normalize).',
    accent: 'text-sky-300',
    glow: 'bg-sky-400',
    pathPercent: 0,
  },
  {
    id: 'detect',
    number: '02',
    title: 'Detect & Fuse',
    summary: 'Rules and correlation promote noise into high-signal alerts.',
    detail: 'Fusion correlates related events, scores confidence, and attaches a narrative.',
    accent: 'text-emerald-300',
    glow: 'bg-emerald-400',
    pathPercent: 20,
  },
  {
    id: 'investigate',
    number: '03',
    title: 'AI Investigation',
    summary: 'DeepSeek agents run recon → forensic → responder → report.',
    detail: 'Every step is written to the case ledger with MITRE mapping and evidence.',
    accent: 'text-brand-300',
    glow: 'bg-brand-400',
    pathPercent: 40,
  },
  {
    id: 'decide',
    number: '04',
    title: 'Verdict & Copilot',
    summary: 'The agent proposes a verdict; analysts confirm in copilot mode.',
    detail: 'Default posture is human-approved — high-blast actions never auto-fire.',
    accent: 'text-cyan-300',
    glow: 'bg-cyan-400',
    pathPercent: 60,
  },
  {
    id: 'respond',
    number: '05',
    title: 'Approved Response',
    summary: 'Playbooks execute only after policy / analyst sign-off.',
    detail: 'Containment and remediation stay dry-run until autonomy policy allows.',
    accent: 'text-amber-300',
    glow: 'bg-amber-400',
    pathPercent: 80,
  },
  {
    id: 'jira',
    number: '06',
    title: 'Jira Ticket',
    summary: 'The enriched case is pushed to Jira for tracking and handoff.',
    detail: 'Ticket carries severity, MITRE, narrative, and recommended actions.',
    accent: 'text-orange-300',
    glow: 'bg-orange-400',
    pathPercent: 100,
  },
];

const PIPE_PATH =
  'M40 120 C 120 120, 140 60, 220 60 S 320 180, 400 180 S 520 60, 600 60 S 720 180, 800 180 S 920 60, 1000 60 L 1060 60';

const CYCLE_MS = 2800;

function StepIcon({ stepId, className }: { stepId: string; className?: string }) {
  const common = clsx('w-6 h-6', className);
  switch (stepId) {
    case 'ingest':
      return (
        <svg className={common} fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7h16M4 12h10M4 17h7" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M18 12v6m0 0l-2-2m2 2l2-2" />
        </svg>
      );
    case 'detect':
      return (
        <svg className={common} fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
          />
        </svg>
      );
    case 'investigate':
      return (
        <svg className={common} fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.847.813a4.5 4.5 0 00-3.09 3.09z"
          />
        </svg>
      );
    case 'decide':
      return (
        <svg className={common} fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M8.625 12a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H8.25m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H12m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 01-2.555-.337A5.972 5.972 0 015.25 20.25v-1.372c0-.516-.351-.966-.852-1.091A7.5 7.5 0 013 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25z"
          />
        </svg>
      );
    case 'respond':
      return (
        <svg className={common} fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
          />
        </svg>
      );
    case 'jira':
      return (
        <svg className={common} fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M16.5 3.75V16.5L12 21l-4.5-4.5V3.75m9 0H21A.75.75 0 0121.75 4.5v9.75a.75.75 0 01-.75.75h-4.5m-9-11.25H3A.75.75 0 002.25 4.5v9.75c0 .414.336.75.75.75h4.5"
          />
        </svg>
      );
    default:
      return null;
  }
}

export function WorkflowSocView() {
  const [activeIndex, setActiveIndex] = useState(0);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (paused) return;
    const timer = window.setInterval(() => {
      setActiveIndex((prev) => (prev + 1) % STEPS.length);
    }, CYCLE_MS);
    return () => window.clearInterval(timer);
  }, [paused]);

  const active = STEPS[activeIndex];
  const progress = useMemo(() => ((activeIndex + 1) / STEPS.length) * 100, [activeIndex]);

  return (
    <div className="h-full overflow-y-auto">
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        <header className="space-y-3">
          <p className="text-xs uppercase tracking-[0.2em] text-brand-400/80">Executive brief</p>
          <h1 className="text-2xl md:text-3xl font-semibold text-white tracking-tight">Workflow SOC</h1>
          <p className="text-sm text-gray-400 max-w-2xl leading-relaxed">
            End-to-end Agentic SOC lifecycle — from live connector ingest through AI investigation to an
            approved response and a tracked Jira ticket. Built for management walkthroughs.
          </p>
          <div className="flex flex-wrap items-center gap-3 pt-1">
            <button
              type="button"
              onClick={() => setPaused((value) => !value)}
              className="text-xs px-3 py-1.5 rounded-lg bg-dark-20 text-gray-300 hover:text-white hover:bg-dark-10 transition-colors border border-white/5"
            >
              {paused ? 'Resume animation' : 'Pause animation'}
            </button>
            <span className="text-xs text-gray-500">
              Active stage:{' '}
              <span className={clsx('font-medium', active.accent)}>{active.title}</span>
            </span>
          </div>
        </header>

        <div className="h-1.5 rounded-full bg-dark-20 overflow-hidden">
          <motion.div
            className="h-full bg-gradient-to-r from-sky-400 via-brand-400 to-orange-400"
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.45, ease: 'easeOut' }}
          />
        </div>

        {/* Desktop animated pipeline */}
        <div
          className="relative hidden lg:block rounded-2xl border border-white/5 bg-dark-80/40 px-4 pt-8 pb-5 overflow-hidden"
          onMouseEnter={() => setPaused(true)}
          onMouseLeave={() => setPaused(false)}
        >
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 opacity-40"
            style={{
              background:
                'radial-gradient(ellipse at 20% 40%, rgba(79,210,194,0.12), transparent 50%), radial-gradient(ellipse at 80% 60%, rgba(251,146,60,0.10), transparent 45%)',
            }}
          />
          <svg
            viewBox="0 0 1100 220"
            className="w-full h-[200px]"
            role="img"
            aria-label="Agentic SOC workflow pipeline"
          >
            <defs>
              <linearGradient id="workflowPipe" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#38bdf8" />
                <stop offset="25%" stopColor="#34d399" />
                <stop offset="50%" stopColor="#4FD2C2" />
                <stop offset="75%" stopColor="#fbbf24" />
                <stop offset="100%" stopColor="#fb923c" />
              </linearGradient>
              <filter id="workflowGlow" x="-40%" y="-40%" width="180%" height="180%">
                <feGaussianBlur stdDeviation="4" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            <path
              d={PIPE_PATH}
              fill="none"
              stroke="url(#workflowPipe)"
              strokeWidth="14"
              strokeLinecap="round"
              opacity="0.28"
            />
            <path
              d={PIPE_PATH}
              fill="none"
              stroke="url(#workflowPipe)"
              strokeWidth="6"
              strokeLinecap="round"
              filter="url(#workflowGlow)"
            />
            {/* Continuous flowing dashes */}
            <motion.path
              d={PIPE_PATH}
              fill="none"
              stroke="#6AF8E7"
              strokeWidth="2"
              strokeLinecap="round"
              strokeDasharray="10 18"
              opacity="0.7"
              animate={{ strokeDashoffset: [0, -56] }}
              transition={{ duration: 1.2, ease: 'linear', repeat: Infinity }}
            />
            <motion.circle
              r="9"
              fill="#6AF8E7"
              filter="url(#workflowGlow)"
              animate={{ offsetDistance: `${STEPS[activeIndex].pathPercent}%` }}
              transition={{ duration: 0.7, ease: 'easeInOut' }}
              style={{ offsetPath: `path('${PIPE_PATH}')` }}
            />
          </svg>

          <div className="grid grid-cols-6 gap-3 relative z-10">
            {STEPS.map((step, index) => {
              const isActive = index === activeIndex;
              const isDone = index < activeIndex;
              return (
                <button
                  key={step.id}
                  type="button"
                  onClick={() => {
                    setActiveIndex(index);
                    setPaused(true);
                  }}
                  className={clsx(
                    'text-left rounded-xl px-3 py-3 border transition-colors min-w-0',
                    isActive
                      ? 'bg-brand-500/10 border-brand-400/40 shadow-[0_0_24px_rgba(79,210,194,0.12)]'
                      : 'bg-dark-20/40 border-white/5 hover:border-white/15',
                  )}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span
                      className={clsx(
                        'w-8 h-8 rounded-full border flex items-center justify-center shrink-0',
                        isActive || isDone ? step.accent : 'text-gray-500',
                        isActive ? 'border-brand-400/50 bg-dark-10' : 'border-white/10 bg-dark-20',
                      )}
                    >
                      <StepIcon stepId={step.id} className="w-4 h-4" />
                    </span>
                    <span className="text-[10px] uppercase tracking-wider text-gray-500">
                      {step.number}
                    </span>
                  </div>
                  <p
                    className={clsx(
                      'text-xs font-semibold leading-snug',
                      isActive ? step.accent : 'text-gray-200',
                    )}
                  >
                    {step.title}
                  </p>
                  <p className="text-[11px] text-gray-500 mt-1.5 leading-relaxed line-clamp-3">
                    {step.summary}
                  </p>
                </button>
              );
            })}
          </div>
        </div>

        {/* Mobile vertical flow */}
        <div className="lg:hidden space-y-3">
          {STEPS.map((step, index) => {
            const isActive = index === activeIndex;
            return (
              <button
                key={step.id}
                type="button"
                onClick={() => {
                  setActiveIndex(index);
                  setPaused(true);
                }}
                className={clsx(
                  'w-full text-left rounded-xl border px-4 py-3 flex gap-3 transition-colors',
                  isActive ? 'border-brand-400/40 bg-brand-500/10' : 'border-white/5 bg-dark-80/50',
                )}
              >
                <div
                  className={clsx(
                    'w-10 h-10 rounded-full flex items-center justify-center shrink-0 border',
                    isActive ? 'border-brand-400/50 bg-dark-20' : 'border-white/10 bg-dark-20',
                    step.accent,
                  )}
                >
                  <StepIcon stepId={step.id} />
                </div>
                <div className="min-w-0">
                  <p className="text-[10px] uppercase tracking-wider text-gray-500">{step.number}</p>
                  <p className={clsx('text-sm font-semibold', isActive ? step.accent : 'text-white')}>
                    {step.title}
                  </p>
                  <p className="text-xs text-gray-400 mt-1 leading-relaxed">{step.summary}</p>
                </div>
              </button>
            );
          })}
        </div>

        <AnimatePresence mode="wait">
          <motion.section
            key={active.id}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.35 }}
            className="rounded-2xl border border-white/5 bg-dark-80/60 p-6 md:p-8"
          >
            <div className="flex flex-col md:flex-row md:items-start gap-6">
              <div
                className={clsx(
                  'w-16 h-16 rounded-2xl flex items-center justify-center border border-white/10 bg-dark-20 shrink-0',
                  active.accent,
                )}
              >
                <StepIcon stepId={active.id} className="w-8 h-8" />
              </div>
              <div className="min-w-0 flex-1 space-y-3">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="text-xs font-mono text-gray-500">{active.number}</span>
                  <span className={clsx('w-2 h-2 rounded-full animate-pulse', active.glow)} />
                  <h2 className="text-xl font-semibold text-white">{active.title}</h2>
                </div>
                <p className="text-sm text-gray-300 leading-relaxed">{active.summary}</p>
                <p className="text-sm text-gray-500 leading-relaxed">{active.detail}</p>
                {active.id === 'jira' && (
                  <div className="mt-4 inline-flex items-center gap-2 rounded-lg bg-orange-500/10 border border-orange-400/30 px-3 py-2 text-xs text-orange-200">
                    <span className="w-1.5 h-1.5 rounded-full bg-orange-400 animate-pulse" />
                    Outcome: enriched case opens as a Jira ticket for ITSM handoff
                  </div>
                )}
              </div>
            </div>
          </motion.section>
        </AnimatePresence>

        <section className="rounded-2xl border border-white/5 bg-dark-80/30 p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Lifecycle at a glance</h3>
          <ol className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {STEPS.map((step, index) => (
              <li
                key={step.id}
                className="flex items-start gap-3 rounded-xl bg-dark-20/40 px-3 py-3 border border-white/5"
              >
                <span className={clsx('text-xs font-mono mt-0.5', step.accent)}>{step.number}</span>
                <div className="min-w-0">
                  <p className="text-sm text-white font-medium">{step.title}</p>
                  <p className="text-xs text-gray-500 mt-1 leading-relaxed">{step.summary}</p>
                  {index < STEPS.length - 1 && (
                    <p className="text-[10px] text-gray-600 mt-2 uppercase tracking-wider">then →</p>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </section>
      </div>
    </div>
  );
}
