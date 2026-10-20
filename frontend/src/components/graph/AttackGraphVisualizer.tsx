import { useState, useEffect, useRef, useCallback } from 'react';
import cytoscape from 'cytoscape';
import type { Core, NodeSingular, EventObject } from 'cytoscape';
import {
  graphApi,
  type GraphNode,
  type GraphEdge,
  type PatientZero,
  type BlastRadius,
  type IncidentGraphResponse,
} from '../../services/api';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  X,
  AlertTriangle,
  Target,
  Shield,
  Network,
  Crosshair,
} from 'lucide-react';

// ─── Type Helpers ───────────────────────────────────────────────────────────

/** Maps entity type strings to display-friendly icon names */
const TYPE_LABELS: Record<string, string> = {
  host: 'Host',
  ip: 'IP Address',
  user: 'User Account',
  application: 'Application',
  domain: 'Domain',
  process: 'Process',
  database: 'Database',
  incident: 'Incident',
  alert: 'Alert',
  threat_actor: 'Threat Actor',
};

/** Color palette for node types */
const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  incident: { bg: '#7c3aed', border: '#a78bfa', text: '#ede9fe' },
  alert: { bg: '#dc2626', border: '#f87171', text: '#fef2f2' },
  threat_actor: { bg: '#ea580c', border: '#fb923c', text: '#fff7ed' },
  host: { bg: '#0891b2', border: '#22d3ee', text: '#ecfeff' },
  ip: { bg: '#0d9488', border: '#2dd4bf', text: '#f0fdfa' },
  user: { bg: '#2563eb', border: '#60a5fa', text: '#eff6ff' },
  application: { bg: '#7c3aed', border: '#a78bfa', text: '#f5f3ff' },
  process: { bg: '#059669', border: '#34d399', text: '#ecfdf5' },
  domain: { bg: '#4f46e5', border: '#818cf8', text: '#eef2ff' },
  database: { bg: '#b45309', border: '#fbbf24', text: '#fffbeb' },
  default: { bg: '#475569', border: '#94a3b8', text: '#f1f5f9' },
};

// ─── Subcomponents ──────────────────────────────────────────────────────────

interface NodeDetailModalProps {
  node: GraphNode | null;
  isPatientZero: boolean;
  onClose: () => void;
}

function NodeDetailModal({ node, isPatientZero, onClose }: NodeDetailModalProps) {
  if (!node) return null;

  const typeLabel = TYPE_LABELS[node.type] || node.type;
  const colors = NODE_COLORS[node.type] || NODE_COLORS.default;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-lg rounded-2xl border border-[#334155] bg-[#0f172a] p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
        style={{
          boxShadow: isPatientZero
            ? '0 0 40px rgba(239, 68, 68, 0.25), 0 0 80px rgba(239, 68, 68, 0.1)'
            : '0 0 40px rgba(34, 211, 238, 0.15)',
        }}
      >
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute right-4 top-4 rounded-lg p-1.5 text-[#64748b] transition hover:bg-[#1e293b] hover:text-[#f1f5f9]"
        >
          <X className="h-4 w-4" />
        </button>

        {/* Header */}
        <div className="flex items-start gap-3">
          <div
            className="flex h-10 w-10 items-center justify-center rounded-xl"
            style={{ backgroundColor: `${colors.bg}30`, border: `1px solid ${colors.border}50` }}
          >
            {node.type === 'incident' && <Shield className="h-5 w-5" style={{ color: colors.border }} />}
            {node.type === 'alert' && <AlertTriangle className="h-5 w-5" style={{ color: colors.border }} />}
            {node.type === 'threat_actor' && <Crosshair className="h-5 w-5" style={{ color: colors.border }} />}
            {!['incident', 'alert', 'threat_actor'].includes(node.type) && (
              <Network className="h-5 w-5" style={{ color: colors.border }} />
            )}
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-[#f1f5f9]">{node.label}</h3>
              {isPatientZero && (
                <span className="animate-pulse rounded-full bg-red-500/20 px-2 py-0.5 text-[10px] font-bold uppercase text-red-400 border border-red-500/40">
                  Patient Zero
                </span>
              )}
            </div>
            <p className="mt-0.5 font-mono text-xs text-[#64748b]">
              <span
                className="inline-block rounded px-1.5 py-0.5 text-[10px] font-bold uppercase"
                style={{ backgroundColor: `${colors.bg}30`, color: colors.border }}
              >
                {typeLabel}
              </span>
              <span className="ml-2 text-[#475569]">ID: {node.id}</span>
            </p>
          </div>
        </div>

        {/* Properties table */}
        {node.properties && Object.keys(node.properties).length > 0 && (
          <div className="mt-5 rounded-lg border border-[#334155] bg-[#030712]/60 p-3">
            <h4 className="mb-2 font-mono text-[10px] font-bold uppercase tracking-wider text-[#64748b]">
              Entity Attributes
            </h4>
            <div className="space-y-1.5">
              {Object.entries(node.properties).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between gap-4 font-mono text-xs">
                  <span className="text-[#94a3b8]">{key}</span>
                  <span className="max-w-[260px] truncate text-right text-[#f1f5f9]">
                    {typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="mt-4 flex items-center justify-between border-t border-[#334155] pt-3">
          <span className="font-mono text-[10px] text-[#475569]">GRAPH ENTITY INSPECTOR</span>
          <button
            onClick={onClose}
            className="rounded-lg bg-[#1e293b] px-3 py-1.5 text-xs font-medium text-[#f1f5f9] transition hover:bg-[#334155]"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Metric Cards ───────────────────────────────────────────────────────────

interface MetricCardProps {
  label: string;
  value: string | number;
  sublabel?: string;
  icon: typeof Target;
  accentColor: string;
  glowing?: boolean;
}

function MetricCard({ label, value, sublabel, icon: Icon, accentColor, glowing }: MetricCardProps) {
  return (
    <div
      className="relative rounded-xl border border-[#334155] bg-[#0f172a]/80 p-3 transition hover:border-opacity-70"
      style={{
        borderColor: glowing ? accentColor : undefined,
        boxShadow: glowing ? `0 0 20px ${accentColor}20, 0 0 40px ${accentColor}10` : undefined,
      }}
    >
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4" style={{ color: accentColor }} />
        <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-[#64748b]">{label}</span>
      </div>
      <div className="mt-1.5 text-xl font-bold" style={{ color: accentColor }}>
        {value}
      </div>
      {sublabel && (
        <span className="font-mono text-[10px] text-[#475569]">{sublabel}</span>
      )}
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────

interface AttackGraphVisualizerProps {
  incidentId: string;
  tenantId?: string;
}

export function AttackGraphVisualizer({ incidentId, tenantId }: AttackGraphVisualizerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const [graphData, setGraphData] = useState<IncidentGraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [isPatientZeroSelected, setIsPatientZeroSelected] = useState(false);

  // ─── Data Fetching ──────────────────────────────────────────────────────

  const fetchGraph = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await graphApi.getIncidentGraph(incidentId, tenantId);
      setGraphData(res.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to load attack graph topology.');
    } finally {
      setLoading(false);
    }
  }, [incidentId, tenantId]);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  // ─── Patient Zero ID Resolution ────────────────────────────────────────

  const resolvePatientZeroId = useCallback((pz: PatientZero | null): string | null => {
    if (!pz) return null;
    return pz.id || pz.entity_id || null;
  }, []);

  // ─── Cytoscape Initialization ───────────────────────────────────────────

  useEffect(() => {
    if (!graphData || !containerRef.current) return;
    if (graphData.nodes.length === 0) return;

    const patientZeroId = resolvePatientZeroId(graphData.patient_zero);

    // Build cytoscape elements
    const elements: cytoscape.ElementDefinition[] = [];

    // Add nodes
    graphData.nodes.forEach((node: GraphNode) => {
      const isPZ = node.id === patientZeroId;
      const isCompromised = node.type === 'alert' || node.type === 'threat_actor';
      const colors = NODE_COLORS[node.type] || NODE_COLORS.default;

      elements.push({
        group: 'nodes',
        data: {
          id: node.id,
          label: node.label.length > 28 ? node.label.substring(0, 25) + '…' : node.label,
          fullLabel: node.label,
          nodeType: node.type,
          properties: node.properties || {},
          isPatientZero: isPZ,
          isCompromised,
          bgColor: isPZ ? '#dc2626' : isCompromised ? '#991b1b' : colors.bg,
          borderColor: isPZ ? '#fbbf24' : isCompromised ? '#f87171' : colors.border,
          textColor: isPZ ? '#fef2f2' : isCompromised ? '#fecaca' : colors.text,
          nodeWidth: isPZ ? 70 : node.type === 'incident' ? 65 : 50,
          nodeHeight: isPZ ? 70 : node.type === 'incident' ? 65 : 50,
          borderWidth: isPZ ? 4 : isCompromised ? 3 : 2,
          fontSize: isPZ ? 11 : 10,
        },
      });
    });

    // Add edges
    graphData.edges.forEach((edge: GraphEdge) => {
      elements.push({
        group: 'edges',
        data: {
          id: `${edge.source}-${edge.target}-${edge.relation}`,
          source: edge.source,
          target: edge.target,
          relation: edge.relation,
          weight: edge.weight,
          lineColor: edge.relation === 'ATTRIBUTED_TO' ? '#ea580c'
            : edge.relation === 'TRIGGERED' ? '#22d3ee'
            : edge.relation === 'PART_OF' ? '#a78bfa'
            : '#475569',
        },
      });
    });

    // Destroy previous instance
    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(bgColor)',
            'border-color': 'data(borderColor)',
            'border-width': 'data(borderWidth)' as any,
            width: 'data(nodeWidth)' as any,
            height: 'data(nodeHeight)' as any,
            label: 'data(label)',
            color: 'data(textColor)',
            'font-size': 'data(fontSize)' as any,
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 8,
            'font-family': "'Inter', sans-serif",
            'text-wrap': 'ellipsis' as any,
            'text-max-width': '120px',
            'overlay-opacity': 0,
            'text-outline-color': '#030712',
            'text-outline-width': 2,
          },
        },
        {
          selector: 'node[?isPatientZero]',
          style: {
            'background-color': '#dc2626',
            'border-color': '#fbbf24',
            'border-width': 5,
            'border-style': 'double',
            'shadow-blur': 30,
            'shadow-color': '#ef4444',
            'shadow-opacity': 0.6,
            'shadow-offset-x': 0,
            'shadow-offset-y': 0,
          } as any,
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': 'data(lineColor)',
            'target-arrow-color': 'data(lineColor)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            opacity: 0.7,
            label: 'data(relation)',
            'font-size': 8,
            color: '#475569',
            'text-rotation': 'autorotate',
            'text-margin-y': -10,
            'font-family': "'JetBrains Mono', monospace",
            'text-outline-color': '#030712',
            'text-outline-width': 1.5,
          },
        },
        {
          selector: 'edge:hover',
          style: {
            width: 3,
            opacity: 1,
          } as any,
        },
        {
          selector: 'node:active',
          style: {
            'overlay-opacity': 0.1,
            'overlay-color': '#22d3ee',
          },
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 800,
        randomize: false,
        componentSpacing: 80,
        nodeRepulsion: () => 8000,
        idealEdgeLength: () => 120,
        edgeElasticity: () => 100,
        nestingFactor: 1.2,
        gravity: 0.25,
        numIter: 1000,
        fit: true,
        padding: 50,
      } as any,
      minZoom: 0.2,
      maxZoom: 4,
      wheelSensitivity: 0.3,
    });

    // Node click handler — show detail modal
    cy.on('tap', 'node', (evt: EventObject) => {
      const tappedNode = evt.target as NodeSingular;
      const nodeData = tappedNode.data();
      const originalNode = graphData.nodes.find((n: GraphNode) => n.id === nodeData.id);
      if (originalNode) {
        setSelectedNode(originalNode);
        setIsPatientZeroSelected(nodeData.isPatientZero === true);
      }
    });

    // Node hover cursor
    cy.on('mouseover', 'node', () => {
      if (containerRef.current) containerRef.current.style.cursor = 'pointer';
    });
    cy.on('mouseout', 'node', () => {
      if (containerRef.current) containerRef.current.style.cursor = 'default';
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graphData, resolvePatientZeroId]);

  // ─── Controls ───────────────────────────────────────────────────────────

  const handleZoomIn = () => {
    if (cyRef.current) {
      cyRef.current.zoom({ level: cyRef.current.zoom() * 1.3, renderedPosition: { x: containerRef.current!.clientWidth / 2, y: containerRef.current!.clientHeight / 2 } });
    }
  };

  const handleZoomOut = () => {
    if (cyRef.current) {
      cyRef.current.zoom({ level: cyRef.current.zoom() / 1.3, renderedPosition: { x: containerRef.current!.clientWidth / 2, y: containerRef.current!.clientHeight / 2 } });
    }
  };

  const handleFit = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 50);
    }
  };

  // ─── Blast Radius Metrics ─────────────────────────────────────────────

  const blastRadius: BlastRadius | null = graphData?.blast_radius || null;
  const patientZero: PatientZero | null = graphData?.patient_zero || null;

  const blastScore = blastRadius?.score ?? blastRadius?.reached_count ?? blastRadius?.total_entities ?? 0;

  // ─── Render ─────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center rounded-xl border border-[#334155] bg-[#0f172a]">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="h-6 w-6 animate-spin text-[#22d3ee]" />
          <span className="font-mono text-xs text-[#94a3b8]">Loading attack graph topology…</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex h-96 flex-col items-center justify-center gap-3 rounded-xl border border-red-500/30 bg-[#0f172a]">
        <AlertTriangle className="h-6 w-6 text-red-400" />
        <span className="text-sm text-red-400">{error}</span>
        <button
          onClick={fetchGraph}
          className="mt-2 rounded-lg bg-[#1e293b] px-4 py-2 text-xs font-medium text-[#f1f5f9] transition hover:bg-[#334155]"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="flex h-96 flex-col items-center justify-center gap-3 rounded-xl border border-[#334155] bg-[#0f172a]">
        <Network className="h-8 w-8 text-[#475569]" />
        <span className="text-sm text-[#94a3b8]">No graph topology data available for this incident.</span>
      </div>
    );
  }

  return (
    <div className="space-y-4 animate-fade-in">
      {/* ── Metrics Row ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          label="Patient Zero"
          value={patientZero?.label || patientZero?.identifier || '—'}
          sublabel={patientZero?.type || patientZero?.entity_type || undefined}
          icon={Crosshair}
          accentColor="#ef4444"
          glowing
        />
        <MetricCard
          label="Blast Radius"
          value={blastScore}
          sublabel="Affected entities"
          icon={Target}
          accentColor="#f59e0b"
          glowing
        />
        <MetricCard
          label="Graph Nodes"
          value={graphData.nodes.length}
          sublabel={`${graphData.edges.length} edges`}
          icon={Network}
          accentColor="#22d3ee"
        />
        <MetricCard
          label="Attack Vectors"
          value={graphData.edges.filter((e: GraphEdge) => e.relation === 'TRIGGERED').length}
          sublabel="Entity-to-alert links"
          icon={Shield}
          accentColor="#a78bfa"
        />
      </div>

      {/* ── Blast Radius Detail Bar ──────────────────────────────────── */}
      {blastRadius && (
        <div className="flex flex-wrap items-center gap-4 rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-2.5">
          <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-amber-400">
            BLAST RADIUS BREAKDOWN
          </span>
          {blastRadius.affected_hosts !== undefined && (
            <span className="font-mono text-xs text-[#94a3b8]">
              Hosts: <span className="font-bold text-amber-300">{blastRadius.affected_hosts}</span>
            </span>
          )}
          {blastRadius.affected_users !== undefined && (
            <span className="font-mono text-xs text-[#94a3b8]">
              Users: <span className="font-bold text-amber-300">{blastRadius.affected_users}</span>
            </span>
          )}
          {blastRadius.affected_ips !== undefined && (
            <span className="font-mono text-xs text-[#94a3b8]">
              IPs: <span className="font-bold text-amber-300">{blastRadius.affected_ips}</span>
            </span>
          )}
          {blastRadius.reached_count !== undefined && (
            <span className="font-mono text-xs text-[#94a3b8]">
              Reached: <span className="font-bold text-amber-300">{blastRadius.reached_count}</span>
              {blastRadius.potential_reach_count !== undefined && (
                <span className="text-[#475569]"> / {blastRadius.potential_reach_count} potential</span>
              )}
            </span>
          )}
        </div>
      )}

      {/* ── Graph Canvas ────────────────────────────────────────────── */}
      <div className="relative overflow-hidden rounded-xl border border-[#334155] bg-[#030712]">
        {/* Toolbar */}
        <div className="absolute left-3 top-3 z-10 flex flex-col gap-1.5">
          <button
            onClick={handleZoomIn}
            className="rounded-lg border border-[#334155] bg-[#0f172a]/90 p-2 text-[#94a3b8] backdrop-blur-sm transition hover:border-[#22d3ee] hover:text-[#22d3ee]"
            title="Zoom In"
          >
            <ZoomIn className="h-4 w-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="rounded-lg border border-[#334155] bg-[#0f172a]/90 p-2 text-[#94a3b8] backdrop-blur-sm transition hover:border-[#22d3ee] hover:text-[#22d3ee]"
            title="Zoom Out"
          >
            <ZoomOut className="h-4 w-4" />
          </button>
          <button
            onClick={handleFit}
            className="rounded-lg border border-[#334155] bg-[#0f172a]/90 p-2 text-[#94a3b8] backdrop-blur-sm transition hover:border-[#22d3ee] hover:text-[#22d3ee]"
            title="Fit to Canvas"
          >
            <Maximize2 className="h-4 w-4" />
          </button>
          <button
            onClick={fetchGraph}
            className="rounded-lg border border-[#334155] bg-[#0f172a]/90 p-2 text-[#94a3b8] backdrop-blur-sm transition hover:border-[#22d3ee] hover:text-[#22d3ee]"
            title="Refresh Graph"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>

        {/* Legend */}
        <div className="absolute right-3 top-3 z-10 rounded-lg border border-[#334155] bg-[#0f172a]/90 p-2.5 backdrop-blur-sm">
          <span className="mb-1.5 block font-mono text-[9px] font-bold uppercase tracking-wider text-[#64748b]">
            LEGEND
          </span>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="block h-2.5 w-2.5 rounded-full bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.6)]" />
              <span className="font-mono text-[9px] text-[#94a3b8]">Patient Zero</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="block h-2.5 w-2.5 rounded-full bg-red-900 border border-red-500" />
              <span className="font-mono text-[9px] text-[#94a3b8]">Compromised</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="block h-2.5 w-2.5 rounded-full bg-cyan-600 border border-cyan-400" />
              <span className="font-mono text-[9px] text-[#94a3b8]">Entity Node</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="block h-2.5 w-2.5 rounded-full bg-purple-600 border border-purple-400" />
              <span className="font-mono text-[9px] text-[#94a3b8]">Incident</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="block h-2.5 w-2.5 rounded-full bg-orange-600 border border-orange-400" />
              <span className="font-mono text-[9px] text-[#94a3b8]">Threat Actor</span>
            </div>
          </div>
        </div>

        {/* Cytoscape container */}
        <div
          ref={containerRef}
          className="h-[520px] w-full"
          style={{ background: 'radial-gradient(ellipse at center, #0f172a 0%, #030712 100%)' }}
        />

        {/* Bottom info bar */}
        <div className="flex items-center justify-between border-t border-[#334155] bg-[#0f172a]/80 px-4 py-2">
          <span className="font-mono text-[10px] text-[#475569]">
            GRAPH ENGINE: CYTOSCAPE.JS / COSE LAYOUT
          </span>
          <span className="font-mono text-[10px] text-[#475569]">
            INCIDENT: {graphData.incident_id} • CLICK NODE FOR DETAILS
          </span>
        </div>
      </div>

      {/* ── Node Detail Modal ────────────────────────────────────────── */}
      {selectedNode && (
        <NodeDetailModal
          node={selectedNode}
          isPatientZero={isPatientZeroSelected}
          onClose={() => {
            setSelectedNode(null);
            setIsPatientZeroSelected(false);
          }}
        />
      )}
    </div>
  );
}

export default AttackGraphVisualizer;
