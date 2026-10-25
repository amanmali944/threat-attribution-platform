import { useState, useEffect, useRef, useCallback } from 'react';
import cytoscape from 'cytoscape';
import type { Core, NodeSingular, EventObject } from 'cytoscape';
import {
  graphApi,
  type GraphNode,
  type GraphEdge,
  type PatientZero,
  type IncidentGraphResponse,
} from '../../services/api';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  X,
  Target,
  Shield,
  Crosshair,
  Server,
} from 'lucide-react';

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

interface NodeDetailModalProps {
  node: GraphNode | null;
  isPatientZero: boolean;
  onClose: () => void;
}

function NodeDetailModal({ node, isPatientZero, onClose }: NodeDetailModalProps) {
  if (!node) return null;
  const typeLabel = TYPE_LABELS[node.type] || node.type;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-lg border border-[#1f1f1f] bg-black p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
        style={{
          boxShadow: isPatientZero ? '0 0 30px rgba(200, 27, 28, 0.4)' : '0 0 20px rgba(0, 0, 0, 0.8)',
          borderLeft: isPatientZero ? '4px solid #c81b1c' : '1px solid #1f1f1f',
        }}
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute right-4 top-4 border border-[#222222] bg-[#0a0a0a] p-1.5 text-[#949494] hover:border-[#c81b1c] hover:text-white"
        >
          <X className="h-4 w-4" />
        </button>

        {/* Header */}
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 items-center justify-center border border-[#c81b1c] bg-[#1a0505] text-[#c81b1c]">
            {node.type === 'incident' && <Shield className="h-5 w-5" />}
            {node.type === 'threat_actor' && <Crosshair className="h-5 w-5" />}
            {node.type !== 'incident' && node.type !== 'threat_actor' && <Server className="h-5 w-5" />}
          </div>
          <div className="flex-1 pr-6">
            <div className="flex items-center gap-2">
              <h3 className="font-sg text-base font-bold text-white uppercase tracking-wider">{node.label}</h3>
              {isPatientZero && (
                <span className="border border-[#c81b1c] bg-[#c81b1c] px-2 py-0.5 font-jb text-[10px] font-bold uppercase text-white">
                  Patient Zero
                </span>
              )}
            </div>
            <p className="mt-1 font-jb text-xs text-[#949494]">
              <span className="border border-[#282828] bg-[#111111] px-1.5 py-0.5 text-[10px] font-bold uppercase text-white">
                {typeLabel}
              </span>
              <span className="ml-2">NODE_ID: {node.id}</span>
            </p>
          </div>
        </div>

        {/* Properties table */}
        {node.properties && Object.keys(node.properties).length > 0 && (
          <div className="mt-5 border border-[#1f1f1f] bg-[#0a0a0a] p-3">
            <h4 className="mb-2 font-sg text-[11px] font-bold uppercase tracking-wider text-[#949494]">
              Entity Telemetry Attributes
            </h4>
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {Object.entries(node.properties).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between gap-4 font-jb text-xs border-b border-[#141414] pb-1">
                  <span className="text-[#949494]">{key}</span>
                  <span className="max-w-[260px] truncate text-right text-white font-medium">
                    {typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="mt-5 flex items-center justify-between border-t border-[#1f1f1f] pt-4">
          <span className="font-jb text-[10px] text-[#949494] uppercase tracking-widest">
            FORENSIC TOPOLOGY INSPECTOR
          </span>
          <button
            onClick={onClose}
            className="btn btn-outline btn-sm"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

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

  const resolvePatientZeroId = useCallback((pz: PatientZero | null): string | null => {
    if (!pz) return null;
    return pz.id || pz.entity_id || null;
  }, []);

  useEffect(() => {
    if (!graphData || !containerRef.current) return;
    if (graphData.nodes.length === 0) return;

    const patientZeroId = resolvePatientZeroId(graphData.patient_zero);
    const elements: cytoscape.ElementDefinition[] = [];

    // Add nodes
    graphData.nodes.forEach((node: GraphNode) => {
      const isPZ = node.id === patientZeroId;
      const isCompromised = node.type === 'alert' || node.type === 'threat_actor';

      elements.push({
        group: 'nodes',
        data: {
          id: node.id,
          label: node.label.length > 24 ? node.label.substring(0, 22) + '…' : node.label,
          fullLabel: node.label,
          nodeType: node.type,
          properties: node.properties || {},
          isPatientZero: isPZ,
          isCompromised,
          bgColor: isPZ ? '#c81b1c' : isCompromised ? '#1c0505' : '#0a0a0a',
          borderColor: isPZ ? '#ffffff' : isCompromised ? '#c81b1c' : '#282828',
          textColor: '#ffffff',
          nodeWidth: isPZ ? 78 : node.type === 'incident' ? 70 : 58,
          nodeHeight: isPZ ? 78 : node.type === 'incident' ? 70 : 58,
          borderWidth: isPZ ? 3 : isCompromised ? 2 : 1,
          fontSize: isPZ ? 13 : 12,
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
          lineColor: edge.relation === 'ATTRIBUTED_TO' ? '#c81b1c' : edge.relation === 'TRIGGERED' ? '#c81b1c' : '#334155',
        },
      });
    });

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
            shape: 'rectangle',
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
            'font-family': "'Inter', system-ui, sans-serif",
            'font-weight': 'bold',
            'text-wrap': 'ellipsis' as any,
            'text-max-width': '110px',
            'overlay-opacity': 0,
            'text-outline-color': '#000000',
            'text-outline-width': 2,
          },
        },
        {
          selector: 'node[?isPatientZero]',
          style: {
            shape: 'rectangle',
            'background-color': '#c81b1c',
            'border-color': '#ffffff',
            'border-width': 3,
            'shadow-blur': 25,
            'shadow-color': '#c81b1c',
            'shadow-opacity': 0.8,
            'shadow-offset-x': 0,
            'shadow-offset-y': 0,
          } as any,
        },
        {
          selector: 'edge',
          style: {
            width: 1.5,
            'line-color': 'data(lineColor)',
            'target-arrow-color': 'data(lineColor)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            opacity: 0.85,
            label: 'data(relation)',
            'font-size': 8,
            color: '#949494',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'font-family': "'JetBrains Mono', monospace",
            'text-outline-color': '#000000',
            'text-outline-width': 1.5,
          },
        },
        {
          selector: 'edge:hover',
          style: {
            width: 2.5,
            opacity: 1,
            'line-color': '#c81b1c',
            'target-arrow-color': '#c81b1c',
          } as any,
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 600,
        randomize: false,
        componentSpacing: 70,
        nodeRepulsion: () => 7000,
        idealEdgeLength: () => 110,
        edgeElasticity: () => 100,
        nestingFactor: 1.2,
        gravity: 0.25,
        numIter: 800,
        fit: true,
        padding: 40,
      } as any,
      minZoom: 0.2,
      maxZoom: 4,
      wheelSensitivity: 0.3,
    });

    cy.on('tap', 'node', (evt: EventObject) => {
      const tappedNode = evt.target as NodeSingular;
      const nodeData = tappedNode.data();
      const originalNode = graphData.nodes.find((n: GraphNode) => n.id === nodeData.id);
      if (originalNode) {
        setSelectedNode(originalNode);
        setIsPatientZeroSelected(nodeData.isPatientZero === true);
      }
    });

    cyRef.current = cy;

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [graphData, resolvePatientZeroId]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 35);
  const handleReset = () => {
    if (cyRef.current) {
      cyRef.current.layout({ name: 'cose', animate: true, padding: 40 } as any).run();
    }
  };

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center gap-3 border border-[#1f1f1f] bg-black/90 p-8">
        <RefreshCw className="h-6 w-6 animate-spin text-[#c81b1c]" />
        <span className="font-jb text-xs text-[#949494] uppercase tracking-wider">
          Rendering causal attack topology...
        </span>
      </div>
    );
  }

  if (error || !graphData || graphData.nodes.length === 0) {
    return (
      <div className="border border-[#1f1f1f] bg-black/90 p-8 text-center">
        <Target className="mx-auto h-8 w-8 text-[#c81b1c]" />
        <h4 className="mt-2 font-sg text-sm font-bold uppercase text-white">Topology Unavailable</h4>
        <p className="mt-1 font-jb text-xs text-[#949494]">{error || 'No graph entities found for this incident.'}</p>
        <button onClick={fetchGraph} className="btn btn-outline btn-sm mt-4">
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Retry</span>
        </button>
      </div>
    );
  }

  const pz = graphData.patient_zero;
  const blast = graphData.blast_radius;

  return (
    <div className="flex flex-col gap-4">
      {/* Metric Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="border border-[#222222] bg-[#0c0c0c] p-4 space-y-1">
          <span className="font-sg text-xs font-bold uppercase text-[#94a3b8] tracking-wider block">
            Patient Zero
          </span>
          <span className="font-mono text-base lg:text-lg font-bold text-[#c81b1c] truncate block">
            {pz?.label || pz?.identifier || 'IDENTIFIED'}
          </span>
          <span className="text-xs text-[#94a3b8] block">Root of Causal Graph</span>
        </div>

        <div className="border border-[#222222] bg-[#0c0c0c] p-4 space-y-1">
          <span className="font-sg text-xs font-bold uppercase text-[#94a3b8] tracking-wider block">
            Blast Radius Score
          </span>
          <span className="font-mono text-xl lg:text-2xl font-bold text-white block">
            {blast?.score !== undefined ? `${(blast.score * 100).toFixed(0)}%` : 'HIGH'}
          </span>
          <span className="text-xs text-[#94a3b8] block">
            Reached: {blast?.reached_count ?? 1} / {blast?.potential_reach_count ?? 6} Nodes
          </span>
        </div>

        <div className="border border-[#222222] bg-[#0c0c0c] p-4 space-y-1">
          <span className="font-sg text-xs font-bold uppercase text-[#94a3b8] tracking-wider block">
            Topology Nodes
          </span>
          <span className="font-mono text-xl lg:text-2xl font-bold text-white block">
            {graphData.nodes.length}
          </span>
          <span className="text-xs text-[#94a3b8] block">Assets & Analytical Alerts</span>
        </div>

        <div className="border border-[#222222] bg-[#0c0c0c] p-4 space-y-1">
          <span className="font-sg text-xs font-bold uppercase text-[#94a3b8] tracking-wider block">
            Causal Edges
          </span>
          <span className="font-mono text-xl lg:text-2xl font-bold text-white block">
            {graphData.edges.length}
          </span>
          <span className="text-xs text-[#94a3b8] block">Lateral Transitions</span>
        </div>
      </div>

      {/* Visualizer Canvas Container */}
      <div className="relative border border-[#222222] bg-black">
        {/* Controls Overlay */}
        <div className="absolute left-4 top-4 z-20 flex flex-col gap-1.5">
          <button
            onClick={handleZoomIn}
            className="border border-[#334155] bg-black/90 p-2 text-white hover:border-[#c81b1c] hover:text-[#c81b1c] transition"
            title="Zoom In"
          >
            <ZoomIn className="h-4 w-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="border border-[#334155] bg-black/90 p-2 text-white hover:border-[#c81b1c] hover:text-[#c81b1c] transition"
            title="Zoom Out"
          >
            <ZoomOut className="h-4 w-4" />
          </button>
          <button
            onClick={handleFit}
            className="border border-[#334155] bg-black/90 p-2 text-white hover:border-[#c81b1c] hover:text-[#c81b1c] transition"
            title="Fit to Canvas"
          >
            <Maximize2 className="h-4 w-4" />
          </button>
          <button
            onClick={handleReset}
            className="border border-[#334155] bg-black/90 p-2 text-white hover:border-[#c81b1c] hover:text-[#c81b1c] transition"
            title="Relayout"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>

        {/* Legend */}
        <div className="absolute right-4 top-4 z-20 hidden sm:flex items-center gap-4 border border-[#262626] bg-black/90 px-4 py-2 text-xs">
          <span className="flex items-center gap-2">
            <span className="h-3 w-3 bg-[#c81b1c] inline-block border border-white" />
            <span className="text-white font-medium">Patient Zero</span>
          </span>
          <span className="flex items-center gap-2">
            <span className="h-3 w-3 bg-[#1c0505] inline-block border border-[#c81b1c]" />
            <span className="text-[#c81b1c] font-medium">Compromised</span>
          </span>
          <span className="flex items-center gap-2">
            <span className="h-3 w-3 bg-[#0a0a0a] inline-block border border-[#334155]" />
            <span className="text-[#94a3b8] font-medium">Asset / Entity</span>
          </span>
        </div>

        {/* Cytoscape Canvas */}
        <div ref={containerRef} className="h-[560px] w-full bg-black cursor-grab active:cursor-grabbing" />
      </div>

      {/* Node Inspector Modal */}
      <NodeDetailModal
        node={selectedNode}
        isPatientZero={isPatientZeroSelected}
        onClose={() => setSelectedNode(null)}
      />
    </div>
  );
}

export default AttackGraphVisualizer;
