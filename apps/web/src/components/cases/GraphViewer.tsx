/**
 * GraphViewer Component — Phase 3 Feature
 *
 * Visualizes entity correlations from a case using Cytoscape.js.
 *
 * Features:
 * - Force-directed graph layout (fcose)
 * - Node styling by entity type (ip, host, user, domain)
 * - Edge styling by relationship strength
 * - Interactive: click nodes to pivot, zoom/pan
 * - Loading states and error handling
 */

'use client'

import { useEffect, useRef, useState } from 'react'
import cytoscape, { Core } from 'cytoscape'
import fcose from 'cytoscape-fcose'
import useSWR from 'swr'
import { clsx } from 'clsx'
import toast from 'react-hot-toast'

// Register layout algorithm
if (typeof window !== 'undefined') {
  cytoscape.use(fcose)
}

interface GraphNode {
  id: string
  label: string
  entity_type: string
  severity: string | null
  count: number
}

interface GraphEdge {
  source: string
  target: string
  relationship_type: string
  strength: number
}

interface GraphResponse {
  nodes: GraphNode[]
  edges: GraphEdge[]
  total_entities: number
}

interface GraphViewerProps {
  caseId: string
  onEntityClick?: (entityId: string) => void
  height?: string
}

const NODE_TYPE_COLORS: Record<string, string> = {
  ip: '#3b82f6',      // blue
  host: '#8b5cf6',    // purple
  user: '#ec4899',    // pink
  domain: '#f59e0b',  // amber
  process: '#10b981', // emerald
  unknown: '#6b7280', // gray
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',  // red
  high: '#ea580c',      // orange
  medium: '#eab308',    // yellow
  low: '#22c55e',       // green
}

export function GraphViewer({
  caseId,
  onEntityClick,
  height = '400px',
}: GraphViewerProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const [isInitialized, setIsInitialized] = useState(false)

  // Fetch graph data
  const { data: graphData, error: graphError, isLoading } = useSWR<GraphResponse>(
    caseId ? `/api/v1/cases/${caseId}/graph` : null,
    async (url) => {
      const res = await fetch(url)
      if (!res.ok) throw new Error('Failed to fetch graph')
      return res.json()
    },
    { revalidateOnFocus: false, dedupingInterval: 60000 }
  )

  // Initialize Cytoscape
  useEffect(() => {
    if (!containerRef.current || !graphData || isInitialized) return

    try {
      // Build Cytoscape elements
      const elements: cytoscape.ElementDefinition[] = []

      // Add nodes
      for (const node of graphData.nodes) {
        elements.push({
          data: {
            id: node.id,
            label: node.label,
            entityType: node.entity_type,
            severity: node.severity,
            count: node.count,
          },
        })
      }

      // Add edges
      for (const edge of graphData.edges) {
        elements.push({
          data: {
            id: `${edge.source}-${edge.target}`,
            source: edge.source,
            target: edge.target,
            relationshipType: edge.relationship_type,
            strength: edge.strength,
          },
        })
      }

      // Initialize Cytoscape
      const cy = cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': (ele: any) => {
                const severity = ele.data('severity')
                if (severity) return SEVERITY_COLORS[severity] || SEVERITY_COLORS.low
                
                const entityType = ele.data('entityType')
                return NODE_TYPE_COLORS[entityType] || NODE_TYPE_COLORS.unknown
              },
              'label': 'data(label)',
              'width': (ele: any) => {
                const count = ele.data('count')
                return Math.min(80, 30 + count * 10)
              },
              'height': (ele: any) => {
                const count = ele.data('count')
                return Math.min(80, 30 + count * 10)
              },
              'font-size': 10,
              'text-valign': 'center',
              'text-halign': 'center',
              'color': '#fff',
              'text-outline-width': 2,
              'text-outline-color': '#000',
              'border-width': 2,
              'border-color': '#000',
              'z-index': 10,
            } as any,
          },
          {
            selector: 'edge',
            style: {
              'stroke-width': (ele: any) => {
                const strength = ele.data('strength')
                return Math.max(1, strength * 3)
              },
              'stroke-opacity': (ele: any) => {
                const strength = ele.data('strength')
                return Math.min(1, 0.3 + strength * 0.7)
              },
              'stroke': '#888',
              'line-style': 'solid',
              'curve-style': 'bezier',
              'target-arrow-shape': 'none',
              'text-opacity': (ele: any) => {
                const strength = ele.data('strength')
                return strength > 0.5 ? 1 : 0
              },
              'font-size': 8,
              'label': (ele: any) => {
                const strength = ele.data('strength')
                return strength > 0.5 ? `${(strength * 100).toFixed(0)}%` : ''
              },
            } as any,
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': 4,
              'border-color': '#60a5fa',
              'z-index': 20,
            } as any,
          },
          {
            selector: 'edge:selected',
            style: {
              'stroke': '#60a5fa',
              'stroke-width': (ele: any) => {
                const strength = ele.data('strength')
                return Math.max(3, strength * 3)
              },
              'z-index': 15,
            } as any,
          },
        ] as any,
        layout: {
          name: 'fcose',
          animate: true,
          animationDuration: 500,
          randomize: false,
          fit: true,
          padding: 30,
        } as any,
      })

      // Handle node clicks
      cy.on('tap', 'node', (evt: any) => {
        const node = evt.target
        const entityId = node.id()
        if (onEntityClick) {
          onEntityClick(entityId)
        }
      })

      cyRef.current = cy
      setIsInitialized(true)
    } catch (err) {
      console.error('Failed to initialize Cytoscape:', err)
      toast.error('Failed to render graph')
    }
  }, [graphData, isInitialized, onEntityClick])

  // Cleanup
  useEffect(() => {
    return () => {
      if (cyRef.current) {
        cyRef.current.destroy()
        cyRef.current = null
      }
    }
  }, [])

  if (graphError) {
    return (
      <div className="flex items-center justify-center bg-red-50 border border-red-200 rounded-lg p-4">
        <span className="text-red-700">Failed to load entity graph</span>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center bg-gray-100 rounded-lg animate-pulse" style={{ height }}>
        <span className="text-gray-500">Loading graph...</span>
      </div>
    )
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="flex items-center justify-center bg-gray-50 border border-gray-200 rounded-lg p-8" style={{ height }}>
        <span className="text-gray-400">No entities to visualize</span>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-xs px-2">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: NODE_TYPE_COLORS.ip }}></div>
          <span>IP</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: NODE_TYPE_COLORS.host }}></div>
          <span>Host</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: NODE_TYPE_COLORS.user }}></div>
          <span>User</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: NODE_TYPE_COLORS.domain }}></div>
          <span>Domain</span>
        </div>
        <div className="flex items-center gap-2 ml-auto text-gray-500">
          {graphData.total_entities} entities
        </div>
      </div>

      {/* Graph Container */}
      <div
        ref={containerRef}
        className="rounded-lg border border-gray-200 bg-white"
        style={{ height, overflow: 'hidden' }}
      />

      {/* Help Text */}
      <p className="text-xs text-gray-400 px-2">
        💡 Click nodes to pivot • Scroll to zoom • Drag to pan
      </p>
    </div>
  )
}
