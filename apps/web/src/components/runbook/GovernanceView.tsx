'use client';

import type { FC } from 'react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Shield,
  AlertTriangle,
  BookOpen,
  Search,
  Zap,
  AlertCircle,
  TestTube,
  CheckCircle2,
  Info,
  X,
  Edit2,
  Power,
} from 'lucide-react';
import { request } from '@/lib/api';
import type {
  GovernanceActionEntry,
  BlastRadius,
  GovernanceCategory,
} from '@/components/runbook/runbook.types';

// ── Constants ─────────────────────────────────────────────────────────────────

const BLAST_COLORS: Record<BlastRadius, string> = {
  read:     'text-slate-400 bg-slate-500/10 border-slate-700/40',
  low:      'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  medium:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  high:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
};

const BLAST_LABELS: Record<BlastRadius, string> = {
  read:     'Affects this alert only',
  low:      'Affects this alert only',
  medium:   'May affect related alerts',
  high:     'May affect multiple related items or systems',
  critical: 'System-wide impact — affects many systems',
};

const CATEGORY_LABELS: Record<GovernanceCategory, string> = {
  read:        'Read / Enrich',
  case:        'Case Workflow',
  containment: 'Containment',
};

const CATEGORY_COLORS: Record<GovernanceCategory, string> = {
  read:        'text-blue-400 bg-blue-500/10',
  case:        'text-purple-400 bg-purple-500/10',
  containment: 'text-red-400 bg-red-500/10',
};

const PCT = (v: number) => `${Math.round(v * 100)}%`;

/**
 * Determine the action badge based on thresholds and category.
 * Returns a human-readable label, color, and icon for SOC managers.
 */
const getActionBadge = (entry: GovernanceActionEntry) => {
  // Check availability first — unavailable actions take precedence
  if (entry.available === false) {
    return { 
      label: 'Unavailable (Missing Connector)', 
      color: 'text-slate-400 bg-slate-800/40 border border-slate-700/60',
      icon: AlertCircle 
    };
  }
  if (entry.always_requires_approval) {
    return { 
      label: 'Always Requires Approval', 
      color: 'text-red-400 bg-red-500/20 border border-red-500/40',
      icon: AlertCircle 
    };
  }
  if (entry.category === 'containment') {
    return { 
      label: 'Requires Human Review', 
      color: 'text-orange-400 bg-orange-500/20 border border-orange-500/40',
      icon: AlertTriangle 
    };
  }
  if (entry.thresholds.auto === 0) {
    return { 
      label: 'Auto-Execute', 
      color: 'text-emerald-400 bg-emerald-500/20 border border-emerald-500/40',
      icon: CheckCircle2 
    };
  }
  return { 
    label: 'Review Required', 
    color: 'text-yellow-400 bg-yellow-500/20 border border-yellow-500/40',
    icon: AlertTriangle 
  };
};

// ── Info Banner ─────────────────────────────────────────────────────────────

const InfoBanner: FC<{ onClose: () => void }> = ({ onClose }) => (
  <div className="mb-6 flex gap-3 items-start p-4 rounded-lg border border-blue-500/30 bg-blue-500/5">
    <Info className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
    <div className="flex-1 min-w-0">
      <p className="text-sm text-slate-200 leading-relaxed">
        <strong>System Capabilities & Policies:</strong> These are the core security actions built into AiSOC. 
        You cannot delete or add new actions, but you can <strong>configure their governance policy</strong> (when they 
        run, who approves them) or temporarily disable them for your workspace.
      </p>
    </div>
    <button
      type="button"
      onClick={onClose}
      className="text-slate-400 hover:text-slate-200 transition-colors flex-shrink-0"
    >
      <X className="h-4 w-4" />
    </button>
  </div>
);

// ── Technical Details Accordion ───────────────────────────────────────────────

const TechnicalDetailsAccordion: FC<{ entry: GovernanceActionEntry }> = ({ entry }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="mt-4 border border-slate-800/40 rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between px-3 py-2.5 bg-slate-900/30 hover:bg-slate-900/50 transition-colors"
      >
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Technical Details</span>
        {expanded ? (
          <ChevronUp className="h-3.5 w-3.5 text-slate-500" />
        ) : (
          <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
        )}
      </button>
      {expanded && (
        <div className="px-3 py-3 bg-slate-950/40 border-t border-slate-800/40 space-y-3">
          <ContractPanel entry={entry} />
        </div>
      )}
    </div>
  );
};

// ── Contract detail panel ─────────────────────────────────────────────────────

const ContractPanel: FC<{ entry: GovernanceActionEntry }> = ({ entry }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">

    {/* Autonomy thresholds */}
    <div className="rounded border border-slate-800/60 bg-slate-900/40 p-3 space-y-1.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
        Autonomy thresholds
      </p>
      {([
        { label: 'Auto (no approval)', value: entry.thresholds.auto, color: 'text-emerald-400' },
        { label: 'Review queue', value: entry.thresholds.review, color: 'text-yellow-400' },
        { label: 'Escalate to on-call', value: entry.thresholds.escalation, color: 'text-orange-400' },
      ] as const).map(({ label, value, color }) => (
        <div key={label} className="flex items-center justify-between">
          <span className="text-slate-500 flex items-center gap-1">
            {label}
            {value === 0 && (
              <span
                className="text-slate-600 cursor-help"
                title={
                  entry.category === 'read'
                    ? '0% = always runs automatically. Read-only enrichment actions never need approval because they cannot change any system state.'
                    : '0% = no confidence floor. Review your policy configuration.'
                }
              >
                ⓘ
              </span>
            )}
          </span>
          <span className={`font-mono ${color}`}>{PCT(value)}</span>
        </div>
      ))}
      {entry.always_requires_approval && (
        <p className="text-[10px] text-red-400 pt-1">Always requires manual approval</p>
      )}
    </div>

    {/* Failure contract */}
    <div className="rounded border border-slate-800/60 bg-slate-900/40 p-3 space-y-1.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
        Failure contract
      </p>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">On failure</span>
        <span className="font-mono text-slate-200">{entry.failure.on_failure}</span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">Max attempts</span>
        <span className="font-mono text-slate-200">{entry.failure.max_attempts}</span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">Timeout</span>
        <span className="font-mono text-slate-200">{entry.failure.timeout_seconds}s</span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">Backoff</span>
        <span className="font-mono text-slate-200">{entry.failure.backoff_seconds}s</span>
      </div>
    </div>

    {/* Audit contract */}
    <div className="rounded border border-slate-800/60 bg-slate-900/40 p-3 space-y-1.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
        Audit contract
      </p>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">Records to ledger</span>
        <span className={entry.audit.record_ledger ? 'text-emerald-400' : 'text-slate-600'}>
          {entry.audit.record_ledger ? 'Yes' : 'No'}
        </span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">Legal audit log</span>
        <span className={
          entry.audit.audit_log
            ? 'text-emerald-400 flex items-center gap-1'
            : entry.category === 'containment'
              ? 'text-red-400 flex items-center gap-1'
              : 'text-slate-600'
        }>
          {entry.audit.audit_log ? 'Yes' : 'No'}
          {entry.category === 'containment' && !entry.audit.audit_log && (
            <span
              title="Warning: containment actions should always write to the legal audit log for compliance. Contact your administrator."
              className="cursor-help"
            >⚠</span>
          )}
          {entry.category === 'containment' && entry.audit.audit_log && (
            <span title="Required for containment actions — cannot be disabled." className="cursor-default text-[10px]">🔒</span>
          )}
        </span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">Logs input</span>
        <span className={entry.audit.include_input ? 'text-emerald-400' : 'text-slate-600'}>
          {entry.audit.include_input ? 'Yes' : 'No'}
        </span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">Logs output</span>
        <span className={entry.audit.include_output ? 'text-emerald-400' : 'text-slate-600'}>
          {entry.audit.include_output ? 'Yes' : 'No'}
        </span>
      </div>
    </div>

    {/* Data safety + cost */}
    <div className="rounded border border-slate-800/60 bg-slate-900/40 p-3 space-y-1.5">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
        Data safety &amp; cost
      </p>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">Allowed fields</span>
        <span className="font-mono text-slate-200 max-w-[160px] truncate text-right">
          {entry.data_safety.allowed_fields.join(', ')}
        </span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">Payload budget</span>
        <span className="font-mono text-slate-200">
          {(entry.data_safety.max_payload_bytes / 1024).toFixed(0)} KB
        </span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-slate-500">PII allowed</span>
        <span className={entry.data_safety.allow_pii ? 'text-amber-400' : 'text-slate-600'}>
          {entry.data_safety.allow_pii ? 'Yes' : 'No'}
        </span>
      </div>
      {entry.cost.max_usd_per_run !== null && (
        <div className="flex items-center justify-between">
          <span className="text-slate-500">Max LLM spend</span>
          <span className="font-mono text-slate-200">
            {entry.cost.max_usd_per_run === 0 ? 'none' : `$${entry.cost.max_usd_per_run}`}
          </span>
        </div>
      )}
    </div>
  </div>
);

// ── Test Policy Demo (Enhanced with Presets) ─────────────────────────────────

const TestPolicyButton: FC<{ entry: GovernanceActionEntry }> = ({ entry }) => {
  const [testing, setTesting] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);
  const [result, setResult] = useState<{ scenario: string; passed: boolean; decision: string } | null>(null);

  const scenarios = [
    { label: 'High-confidence alert (90%)', confidence: 0.90 },
    { label: 'Medium-confidence alert (70%)', confidence: 0.70 },
    { label: 'Low-confidence / Noise (40%)', confidence: 0.40 },
  ];

  const handleTest = (confidence: number, label: string) => {
    setTesting(true);
    setShowDropdown(false);
    
    setTimeout(() => {
      // Determine what happens with this alert
      let decision = 'queued for review';
      
      if (entry.always_requires_approval) {
        decision = 'requires manual approval';
      } else if (entry.category === 'containment') {
        decision = 'requires manual approval (dry-run by default)';
      } else if (confidence >= entry.thresholds.auto) {
        decision = 'executes automatically';
      } else if (confidence >= entry.thresholds.review) {
        decision = 'queued for analyst review';
      } else if (confidence >= entry.thresholds.escalation) {
        decision = 'escalated to on-call';
      } else {
        decision = 'rejected (confidence too low)';
      }

      setResult({
        scenario: label,
        passed: true,
        decision,
      });
      setTesting(false);
    }, 600);
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="relative inline-flex">
        <button
          type="button"
          onClick={() => setShowDropdown((v) => !v)}
          disabled={testing}
          className="inline-flex items-center gap-2 px-3 py-2 rounded border border-blue-500/30 bg-blue-500/10 text-xs font-medium text-blue-400 hover:bg-blue-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <TestTube className="h-3.5 w-3.5" />
          {testing ? 'Testing...' : 'Test Policy'}
          <ChevronDown className={`h-3 w-3 transition-transform ${showDropdown ? 'rotate-180' : ''}`} />
        </button>
        {showDropdown && !testing && (
          <div className="absolute top-full left-0 mt-1 rounded border border-slate-700 bg-slate-900 shadow-lg z-10 min-w-max">
            {scenarios.map((s) => (
              <button
                key={s.confidence}
                type="button"
                onClick={() => handleTest(s.confidence, s.label)}
                className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 first:rounded-t last:rounded-b transition-colors"
              >
                {s.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {result && (
        <div className="rounded border border-emerald-500/30 bg-emerald-500/10 p-3">
          <p className="text-[10px] text-emerald-300 font-medium mb-1">
            Scenario: {result.scenario}
          </p>
          <p className="text-xs text-emerald-200 font-medium">
            Result: Action will <span className="text-emerald-300">{result.decision}</span>.
          </p>
        </div>
      )}
    </div>
  );
};

// ── Policy Editor Modal ──────────────────────────────────────────────────────

const PolicyEditModal: FC<{
  entry: GovernanceActionEntry | null;
  onClose: () => void;
  onSave: (action: string, thresholds: { auto: number; review: number; escalation: number }, reason?: string) => void;
}> = ({ entry, onClose, onSave }) => {
  const [auto, setAuto] = useState(entry?.thresholds.auto ?? 0.5);
  const [review, setReview] = useState(entry?.thresholds.review ?? 0.4);
  const [escalation, setEscalation] = useState(entry?.thresholds.escalation ?? 0.2);
  const [reason, setReason] = useState('');
  const [saving, setSaving] = useState(false);

  if (!entry) return null;

  const handleSave = async () => {
    setSaving(true);
    try {
      await request(`/api/v1/autonomy-policy/${entry.name}`, {
        method: 'PUT',
        body: JSON.stringify({ auto, review, escalation, reason: reason || undefined }),
      });
      onSave(entry.name, { auto, review, escalation }, reason);
      onClose();
    } catch (err) {
      console.error('Failed to save policy:', err);
    } finally {
      setSaving(false);
    }
  };

  const isValid = escalation <= review && review <= auto;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 rounded-lg border border-slate-800 p-6 max-w-md w-full max-h-[90vh] overflow-y-auto">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h3 className="text-lg font-bold text-slate-100">{entry.label}</h3>
            <p className="text-xs font-mono text-slate-500 mt-1">{entry.name}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              Auto-Execute Threshold: {PCT(auto)}
            </label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.01"
              value={auto}
              onChange={(e) => setAuto(Math.max(review, Number(e.target.value)))}
              className="w-full"
            />
            <p className="text-[10px] text-slate-500 mt-1">
              Actions execute automatically when alert confidence meets this floor.
            </p>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              Review Queue Threshold: {PCT(review)}
            </label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.01"
              value={review}
              onChange={(e) => setReview(Math.min(auto, Math.max(escalation, Number(e.target.value))))}
              className="w-full"
            />
            <p className="text-[10px] text-slate-500 mt-1">
              Actions queue for analyst review between this and the auto threshold.
            </p>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              Escalation Threshold: {PCT(escalation)}
            </label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.01"
              value={escalation}
              onChange={(e) => setEscalation(Math.min(review, Number(e.target.value)))}
              className="w-full"
            />
            <p className="text-[10px] text-slate-500 mt-1">
              Actions escalate to on-call below this threshold.
            </p>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2">
              Change Reason (optional)
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why are you adjusting these thresholds?"
              maxLength={500}
              className="w-full rounded border border-slate-700 bg-slate-800 p-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500 resize-none"
              rows={3}
            />
          </div>

          {!isValid && (
            <div className="rounded border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-300">
              Invalid: escalation ≤ review ≤ auto
            </div>
          )}
        </div>

        <div className="flex gap-2 mt-6">
          <button
            type="button"
            onClick={onClose}
            disabled={saving}
            className="flex-1 px-3 py-2 rounded border border-slate-700 text-xs font-medium text-slate-300 hover:text-slate-100 transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={!isValid || saving}
            className="flex-1 px-3 py-2 rounded bg-blue-500/20 border border-blue-500/40 text-xs font-medium text-blue-300 hover:bg-blue-500/30 disabled:opacity-50 transition-colors"
          >
            {saving ? 'Saving…' : 'Save Changes'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ── Action Card Row (Updated for SOC Manager View) ──────────────────────────

const GovernanceRow: FC<{ 
  entry: GovernanceActionEntry;
  onToggleEnabled?: (action: string, enabled: boolean) => void;
}> = ({ entry, onToggleEnabled }) => {
  const [expanded, setExpanded] = useState(false);
  const [isEnabled, setIsEnabled] = useState(entry.enabled ?? true);
  const [editingEntry, setEditingEntry] = useState<GovernanceActionEntry | null>(null);
  const badge = getActionBadge(entry);
  const BadgeIcon = badge.icon;
  const isContainment = entry.category === 'containment';

  const handleToggle = () => {
    const newState = !isEnabled;
    setIsEnabled(newState);
    onToggleEnabled?.(entry.name, newState);
  };

  const handleSavePolicy = (action: string, thresholds: { auto: number; review: number; escalation: number }, reason?: string) => {
    // Update the entry with new thresholds
    const updatedEntry = {
      ...entry,
      thresholds,
    };
    console.log(`Policy saved for ${action}:`, updatedEntry);
  };

  return (
    <div className={`border rounded-lg overflow-hidden transition-all ${
      isContainment
        ? 'border-red-500/40 bg-red-500/5'
        : isEnabled
          ? 'border-slate-800/60 bg-slate-900/40'
          : 'border-slate-800/40 bg-slate-950/60'
    } ${!isEnabled ? 'opacity-75' : ''}`}>
      {/* Header row with title, badges, and controls */}
      <div className="flex items-start gap-3 px-4 py-4">
        {/* Left section: Title, status badge, category badge */}
        <div className="flex-1 min-w-0">
          <div className="flex items-start gap-3 mb-3 flex-wrap">
            <div className="flex-1">
              <h3 className={`text-sm font-semibold ${isEnabled ? 'text-slate-200' : 'text-slate-400'}`}>
                {entry.label}
              </h3>
              {isContainment && isEnabled && (
                <p className="text-xs text-red-400 font-medium flex items-center gap-1 mt-1">
                  <AlertCircle className="h-3 w-3" />
                  Requires Human Approval
                </p>
              )}
            </div>
            {/* System Core badge */}
            <span className="inline-block px-2 py-1 rounded text-[10px] font-medium bg-purple-500/20 text-purple-300 border border-purple-500/30 whitespace-nowrap">
              System Core
            </span>
          </div>

          {/* Main action badge (Auto-Execute / Review Required / etc.) */}
          <div className="mb-3 flex items-center gap-2">
            <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded font-medium text-xs whitespace-nowrap ${badge.color}`}>
              <BadgeIcon className="h-3.5 w-3.5" />
              {badge.label}
            </div>
            
            {/* Impact description (human-readable replacement for blast_radius jargon) */}
            <p className="text-xs text-slate-400">
              <span className="text-slate-500 font-medium">Impact:</span> {BLAST_LABELS[entry.blast_radius]}
            </p>
          </div>

          {/* Category badge */}
          <span className={`inline-block text-[10px] px-2 py-1 rounded font-medium ${CATEGORY_COLORS[entry.category]}`}>
            {CATEGORY_LABELS[entry.category]}
          </span>

          <p className="text-[10px] font-mono text-slate-600 mt-2">{entry.name}</p>
        </div>

        {/* Right section: Toggle + Expand button */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Enable/Disable toggle */}
          <button
            type="button"
            onClick={handleToggle}
            disabled={entry.available === false}
            className={`p-2 rounded transition-colors ${
              entry.available === false
                ? 'bg-slate-800/40 text-slate-600 cursor-not-allowed opacity-50'
                : isEnabled
                  ? 'bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30'
                  : 'bg-slate-800/60 text-slate-500 hover:bg-slate-800'
            }`}
            title={
              entry.available === false
                ? 'Action unavailable — required connectors not configured'
                : (isEnabled ? 'Disable this action for your workspace' : 'Enable this action')
            }
            aria-label={`${isEnabled ? 'Disable' : 'Enable'} ${entry.label}`}
          >
            <Power className="h-4 w-4" />
          </button>

          {/* Expand details button */}
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="p-2 text-slate-500 hover:text-slate-300 transition-colors"
            aria-label={expanded ? 'Collapse details' : 'Expand details'}
          >
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Expanded content */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-800/40 space-y-4 pt-4">
          {/* Unavailable action notice */}
          {entry.available === false && (
            <div className="rounded border border-slate-600/40 bg-slate-800/30 p-3">
              <p className="text-xs text-slate-300 flex items-start gap-2">
                <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                <span>
                  This action requires an active data connector (e.g. <span className="font-mono text-slate-400">firewall</span>, <span className="font-mono text-slate-400">edr</span>, or <span className="font-mono text-slate-400">splunk</span>) which is not currently configured for this workspace.
                </span>
              </p>
            </div>
          )}

          {/* Edit Policy section with button */}
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-semibold text-slate-300 mb-2">
                Policy Configuration
              </p>
              <p className="text-xs text-slate-400">
                Thresholds: Auto @ {PCT(entry.thresholds.auto)} • Review @ {PCT(entry.thresholds.review)} • Escalate @ {PCT(entry.thresholds.escalation)}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setEditingEntry(entry)}
              disabled={entry.available === false}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded border text-xs font-medium shrink-0 transition-colors ${
                entry.available === false
                  ? 'border-slate-700/40 bg-slate-800/30 text-slate-500 cursor-not-allowed opacity-50'
                  : 'border-blue-500/30 bg-blue-500/10 text-blue-400 hover:bg-blue-500/20'
              }`}
              title={entry.available === false ? 'Cannot edit policy for unavailable action' : 'Edit policy thresholds'}
            >
              <Edit2 className="h-3.5 w-3.5" />
              Edit Policy
            </button>
          </div>

          {/* Test Policy section */}
          <div>
            <p className="text-xs font-semibold text-slate-300 mb-2">
              Test Policy Behavior
            </p>
            <TestPolicyButton entry={entry} />
          </div>

          {/* Technical Details (collapsed accordion within expanded section) */}
          <TechnicalDetailsAccordion entry={entry} />

          {/* Containment safety info */}
          {isContainment && (
            <div className="rounded border border-red-500/30 bg-red-500/5 p-3">
              <p className="text-xs text-red-300 flex items-start gap-2">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                <span>
                  Containment actions are <span className="font-semibold">always executed in dry-run mode by default</span> and require human approval before real execution.
                </span>
              </p>
            </div>
          )}

          {/* Disabled state notice */}
          {!isEnabled && (
            <div className="rounded border border-slate-700/40 bg-slate-800/30 p-3">
              <p className="text-xs text-slate-400 flex items-start gap-2">
                <span>🔒 This action is currently disabled for your workspace. Toggle the enable button above to reactivate it.</span>
              </p>
            </div>
          )}
        </div>
      )}

      {/* Edit Policy Modal */}
      <PolicyEditModal
        entry={editingEntry}
        onClose={() => setEditingEntry(null)}
        onSave={handleSavePolicy}
      />
    </div>
  );
};

// ── Main View ────────────────────────────────────────────────────────────────

type FilterCategory = 'all' | GovernanceCategory;

export const GovernanceView: FC = () => {
  const [catalog, setCatalog] = useState<GovernanceActionEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterCategory>('all');
  const [search, setSearch] = useState('');
  const [bannerDismissed, setBannerDismissed] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await request<GovernanceActionEntry[]>('/api/v1/runbook/governance');
      setCatalog(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return catalog.filter((entry) => {
      if (filter !== 'all' && entry.category !== filter) return false;
      if (!needle) return true;
      const haystack = [
        entry.label,
        entry.name,
        CATEGORY_LABELS[entry.category] ?? entry.category,
        entry.blast_radius,
      ]
        .join(' ')
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [catalog, filter, search]);

  const counts: Record<GovernanceCategory, number> = catalog.reduce(
    (acc, e) => ({ ...acc, [e.category]: (acc[e.category] ?? 0) + 1 }),
    { read: 0, case: 0, containment: 0 } as Record<GovernanceCategory, number>,
  );

  const handleToggleAction = useCallback((actionName: string, enabled: boolean) => {
    // Call API to persist enable/disable state
    request(`/api/v1/autonomy-policy/${actionName}/enabled`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    }).catch((err) => {
      console.error(`Failed to toggle ${actionName}:`, err);
    });
  }, []);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Shield className="h-5 w-5 text-purple-400" />
          <h2 className="text-2xl font-bold text-slate-100">Governance Policies</h2>
        </div>
        <p className="text-sm text-slate-400">
          Configure system capabilities and approval policies for your security team
        </p>
      </div>

      {/* Info Banner */}
      {!bannerDismissed && (
        <InfoBanner onClose={() => setBannerDismissed(true)} />
      )}

      {/* Manager-friendly explanation */}
      <div className="rounded-lg border border-slate-800/60 bg-slate-950/20 p-4">
        <div className="flex items-start gap-3">
          <BookOpen className="h-4 w-4 text-slate-500 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-400 space-y-2">
            <p>
              Each action below shows whether it will be <span className="text-emerald-300 font-medium">automatically executed</span>, 
              <span className="text-yellow-300 font-medium"> queued for your review</span>, or 
              <span className="text-orange-300 font-medium"> escalated to on-call</span> based on alert confidence.
            </p>
            <p className="text-slate-500">
              <span className="font-medium text-slate-300">💡 Pro Tip:</span> Toggle actions on/off to quickly enable or disable capabilities for your workspace. Use &quot;Edit Policy&quot; to customize approval thresholds.
            </p>
          </div>
        </div>
      </div>

      {/* Search + Filters */}
      <div className="space-y-3">
        {/* Search bar */}
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search actions by name, impact, or category…"
            aria-label="Search governance actions"
            className="w-full rounded border border-slate-700/60 bg-slate-800/60 py-2 pl-10 pr-3 text-sm text-slate-200 placeholder-slate-600 focus:border-blue-500/50 focus:outline-none focus:ring-1 focus:ring-blue-500/20"
          />
        </div>

        {/* Category filters */}
        <div className="flex items-center gap-2 flex-wrap">
          {(['all', 'read', 'case', 'containment'] as const).map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setFilter(cat)}
              className={[
                'px-3 py-1.5 text-xs rounded font-medium transition-colors',
                filter === cat
                  ? 'bg-slate-700 text-slate-100'
                  : 'bg-slate-800/60 text-slate-500 hover:text-slate-300 hover:bg-slate-800',
              ].join(' ')}
            >
              {cat === 'all' ? `All (${catalog.length})` : `${CATEGORY_LABELS[cat]} (${counts[cat]})`}
            </button>
          ))}
          {!loading && (search.trim() || filter !== 'all') && (
            <span className="text-xs text-slate-500 ml-auto">
              {visible.length} of {catalog.length}
            </span>
          )}
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="flex items-start gap-3 rounded border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
          {error}
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <Zap className="h-4 w-4 animate-pulse" />
            Loading governance policies…
          </div>
        </div>
      )}

      {/* Empty state */}
      {!loading && visible.length === 0 && !error && (
        <div className="rounded-lg border border-slate-800/60 bg-slate-950/20 p-8 text-center">
          <AlertCircle className="h-8 w-8 text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-400 mb-3">
            {search.trim()
              ? `No policies match "${search.trim()}"`
              : 'No actions in this category.'}
          </p>
          {(search.trim() || filter !== 'all') && (
            <button
              type="button"
              onClick={() => {
                setSearch('');
                setFilter('all');
              }}
              className="rounded border border-slate-700/60 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200 hover:border-slate-600 transition-colors"
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      {/* Action rows */}
      {!loading && visible.length > 0 && (
        <div className="space-y-3">
          {visible.map((entry) => (
            <GovernanceRow 
              key={entry.name} 
              entry={entry}
              onToggleEnabled={handleToggleAction}
            />
          ))}
        </div>
      )}
    </div>
  );
};
