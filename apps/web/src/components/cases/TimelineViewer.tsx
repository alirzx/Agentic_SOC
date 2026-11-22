/**
 * TimelineViewer Component — Phase 3 Feature (Enhanced)
 *
 * Visualizes the temporal sequence of alerts in a case.
 * Shows when alerts occurred and their time deltas.
 *
 * Features:
 * - Chronological ordering (oldest to newest)
 * - Time delta highlighting (gaps between events)
 * - Severity color coding
 * - Interactive: click alerts to pivot
 * - Group by hour/day (configurable)
 */

'use client'

import { useState } from 'react'
import useSWR from 'swr'
import { format, parseISO } from 'date-fns'
import { clsx } from 'clsx'
import { safeFetcher } from '@/lib/fetcher'
import toast from 'react-hot-toast'

interface TimelineEvent {
  id: string
  type: string
  timestamp: string
  title: string
  description: string | null
  actor: string | null
}

interface TimelineResponse {
  events: TimelineEvent[]
}

interface TimelineViewerProps {
  caseId: string
  onAlertClick?: (alertId: string) => void
  groupBy?: 'hour' | 'day' | 'none'
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
  info: 'bg-blue-500',
}

function getTypeIcon(type: string): string {
  switch (type) {
    case 'created':
      return '📋'
    case 'status_change':
      return '🔄'
    case 'comment':
      return '💬'
    case 'alert_linked':
      return '🚨'
    case 'task':
      return '✓'
    default:
      return '•'
  }
}

function formatTimeDelta(seconds: number | null): string {
  if (!seconds) return ''

  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)

  if (hours > 0) {
    return `+${hours}h ${minutes}m`
  }
  if (minutes > 0) {
    return `+${minutes}m`
  }
  return '+<1m'
}

function extractSeverityFromDescription(description: string | null): string | null {
  if (!description) return null

  const match = description.match(/\b(critical|high|medium|low|info)\b/i)
  return match ? match[1].toLowerCase() : null
}

export function TimelineViewer({
  caseId,
  onAlertClick,
  groupBy = 'day',
}: TimelineViewerProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  // Fetch timeline data
  const { data: timelineData, error: timelineError, isLoading } = useSWR<TimelineResponse>(
    caseId ? `/api/v1/cases/${caseId}/timeline` : null,
    safeFetcher,
    { revalidateOnFocus: false, dedupingInterval: 60000 }
  )

  const toggleExpanded = (eventId: string) => {
    const newExpanded = new Set(expanded)
    if (newExpanded.has(eventId)) {
      newExpanded.delete(eventId)
    } else {
      newExpanded.add(eventId)
    }
    setExpanded(newExpanded)
  }

  if (timelineError) {
    return (
      <div className="flex items-center justify-center bg-red-50 border border-red-200 rounded-lg p-4">
        <span className="text-red-700">Failed to load timeline</span>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex gap-3 p-3 bg-gray-50 rounded-lg animate-pulse">
            <div className="w-8 h-8 bg-gray-200 rounded-full" />
            <div className="flex-1 space-y-2">
              <div className="h-4 bg-gray-200 rounded w-2/3" />
              <div className="h-3 bg-gray-200 rounded w-1/2" />
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (!timelineData || timelineData.events.length === 0) {
    return (
      <div className="flex items-center justify-center bg-gray-50 border border-gray-200 rounded-lg p-8">
        <span className="text-gray-400">No timeline events</span>
      </div>
    )
  }

  // Sort events chronologically
  const events = [...timelineData.events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )

  // Group events by time period if needed
  const groupedEvents: Record<string, TimelineEvent[]> = {}
  if (groupBy !== 'none') {
    for (const event of events) {
      const date = parseISO(event.timestamp)
      const key = groupBy === 'hour'
        ? format(date, 'yyyy-MM-dd HH:00')
        : format(date, 'yyyy-MM-dd')
      
      if (!groupedEvents[key]) {
        groupedEvents[key] = []
      }
      groupedEvents[key].push(event)
    }
  } else {
    for (const event of events) {
      groupedEvents[event.id] = [event]
    }
  }

  return (
    <div className="space-y-0">
      {Object.entries(groupedEvents).map(([groupKey, groupEvents], groupIndex) => (
        <div key={groupKey}>
          {/* Group Header */}
          {groupBy !== 'none' && (
            <div className="sticky top-0 bg-gray-50 border-y border-gray-200 px-4 py-2 z-10">
              <p className="text-xs font-semibold text-gray-600">
                {groupKey}
              </p>
            </div>
          )}

          {/* Events in Group */}
          <div className="space-y-0">
            {groupEvents.map((event, index) => {
              const isExpanded = expanded.has(event.id)
              const severity = extractSeverityFromDescription(event.description)
              const prevEvent = events[events.indexOf(event) - 1]
              const timeDelta =
                prevEvent && event.timestamp
                  ? Math.floor(
                      (new Date(event.timestamp).getTime() -
                        new Date(prevEvent.timestamp).getTime()) /
                        1000
                    )
                  : null

              return (
                <div key={event.id}>
                  {/* Time Delta Indicator */}
                  {timeDelta && timeDelta > 60 && (
                    <div className="flex items-center gap-2 px-4 py-2 text-xs text-gray-400">
                      <div className="flex-1 border-t border-gray-200" />
                      <span className="font-mono">
                        {formatTimeDelta(timeDelta)}
                      </span>
                      <div className="flex-1 border-t border-gray-200" />
                    </div>
                  )}

                  {/* Event */}
                  <div
                    className={clsx(
                      'flex gap-3 px-4 py-3 border-l-4 cursor-pointer hover:bg-gray-50 transition-colors',
                      severity
                        ? SEVERITY_COLORS[severity]?.replace('bg-', 'border-l-') || 'border-l-gray-300'
                        : 'border-l-gray-300'
                    )}
                    onClick={() => toggleExpanded(event.id)}
                  >
                    {/* Icon */}
                    <div className="flex-shrink-0 text-lg w-6">
                      {getTypeIcon(event.type)}
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900">
                        {event.title}
                      </p>
                      <div className="flex flex-wrap gap-2 mt-1">
                        <p className="text-xs text-gray-500">
                          {format(parseISO(event.timestamp), 'HH:mm:ss')}
                        </p>
                        {event.actor && (
                          <p className="text-xs text-gray-400">
                            by {event.actor}
                          </p>
                        )}
                      </div>

                      {/* Expandable Description */}
                      {event.description && (
                        <>
                          {!isExpanded && (
                            <p className="text-xs text-gray-600 mt-2 line-clamp-2">
                              {event.description}
                            </p>
                          )}
                          {isExpanded && (
                            <div className="mt-2 p-2 bg-gray-50 rounded text-xs text-gray-700 border border-gray-200">
                              {event.description}
                            </div>
                          )}
                        </>
                      )}
                    </div>

                    {/* Expand Icon */}
                    {event.description && (
                      <div className="flex-shrink-0 text-gray-400">
                        {isExpanded ? '▼' : '▶'}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}
