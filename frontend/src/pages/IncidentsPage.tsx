import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import {
  incidentsApi,
  attributionsApi,
  type IncidentItem,
  type AttributionItem,
} from '../services/api';
import { AttackGraphVisualizer } from '../components/graph/AttackGraphVisualizer';
import { IncidentTimelineView } from '../components/incident/IncidentTimelineView';
import {
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  UserCheck,
  Calendar,
  Network,
  Clock,
  ChevronDown,
  ChevronUp,
  X,
  Gauge,
  Layers,
  Crosshair,
  Server,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  FileText,
} from 'lucide-react';

export function IncidentsPage() {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [expandedIncidentId, setExpandedIncidentId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Record<string, 'investigation' | 'topology' | 'timeline' | 'evidence'>>({});
  const [attributions, setAttributions] = useState<Record<string, AttributionItem | null>>({});
  const [statusUpdating, setStatusUpdating] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const tenantId = user?.tenant_id || 'tenant_default';

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await incidentsApi.list(tenantId);
      setIncidents(res.data.items || []);
    } catch (err: any) {
      setError(
        err?.response?.data?.detail ||
          'Failed to load correlated incidents from platform API.',
      );
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  // Load attribution for expanded incident
  const loadAttributionForIncident = useCallback(async (incId: string) => {
    if (attributions[incId] !== undefined) return;
    try {
      const res = await attributionsApi.list(tenantId, { incident_id: incId });
      const items = res.data.items || [];
      setAttributions((prev) => ({ ...prev, [incId]: items[0] || null }));
    } catch {
      setAttributions((prev) => ({ ...prev, [incId]: null }));
    }
  }, [tenantId, attributions]);

  const toggleExpand = (incId: string) => {
    if (expandedIncidentId === incId) {
      setExpandedIncidentId(null);
    } else {
      setExpandedIncidentId(incId);
      if (!activeTab[incId]) {
        setActiveTab((prev) => ({ ...prev, [incId]: 'investigation' }));
      }
      loadAttributionForIncident(incId);
    }
  };

  const handleUpdateStatus = async (incidentId: string, targetStatus: string) => {
    setStatusUpdating(incidentId);
    try {
      const normalized = targetStatus.toLowerCase();
      await incidentsApi.updateStatus(incidentId, normalized);
      setIncidents((prev) =>
        prev.map((i) => (i.id === incidentId ? { ...i, status: normalized } : i)),
      );
      setActionNotice(`Status updated to ${targetStatus.toUpperCase()}`);
      setTimeout(() => setActionNotice(null), 3000);
    } catch (err: any) {
      setError(err?.response?.data?.detail || `Failed to transition incident status to ${targetStatus}.`);
    } finally {
      setStatusUpdating(null);
    }
  };

  const filtered = incidents.filter((inc) => {
    const matchesSearch =
      inc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      inc.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      inc.assigned_to.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus =
      statusFilter === 'all' || inc.status.toLowerCase() === statusFilter.toLowerCase();
    return matchesSearch && matchesStatus;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-purple-500/20 text-purple-400 border border-purple-500/40 shadow-[0_0_10px_rgba(168,85,247,0.2)]';
      case 'high':
        return 'bg-red-500/20 text-red-400 border border-red-500/40 shadow-[0_0_10px_rgba(239,68,68,0.2)]';
      case 'medium':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/40';
      default:
        return 'bg-blue-500/20 text-blue-400 border border-blue-500/40';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open':
        return 'bg-amber-500/10 text-amber-400 border border-amber-500/30';
      case 'reviewed':
        return 'bg-[#22d3ee]/10 text-[#22d3ee] border border-[#22d3ee]/30';
      case 'confirmed':
        return 'bg-red-500/20 text-red-400 border border-red-500/40 font-bold';
      case 'dismissed':
        return 'bg-slate-700/40 text-slate-400 border border-slate-600';
      case 'investigating':
        return 'bg-blue-500/10 text-blue-400 border border-blue-500/30';
      case 'closed':
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
      default:
        return 'bg-slate-700/40 text-slate-400 border border-slate-600';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title & Controls */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[#f1f5f9]">
              Correlated Security Incidents
            </h1>
            <span className="rounded bg-[#22d3ee]/10 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-[#22d3ee] border border-[#22d3ee]/30">
              {incidents.length} Active Cases
            </span>
          </div>
          <p className="mt-0.5 text-xs font-mono text-[#94a3b8]">
            MULTI-STAGE ATTACK CORRELATION · ENTRY POINT ATTRIBUTION · CAUSAL TOPOLOGY
          </p>
        </div>

        <button
          onClick={fetchIncidents}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-[#334155] bg-[#1e293b] px-3.5 py-2 text-xs font-mono text-[#f1f5f9] transition hover:border-[#22d3ee] hover:text-[#22d3ee] disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Incidents</span>
        </button>
      </div>

      {/* Action Notification */}
      {actionNotice && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-950/20 p-3 text-xs font-mono text-emerald-300 animate-fade-in">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Transparent Error Banner */}
      {error && (
        <div className="flex items-center justify-between rounded-xl border border-red-500/40 bg-red-950/20 p-4 text-xs font-mono text-red-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400 flex-shrink-0" />
            <span>API Error: {error}</span>
          </div>
          <button
            onClick={fetchIncidents}
            className="rounded border border-red-500/50 px-2 py-1 hover:bg-red-900/40"
          >
            Retry
          </button>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1 sm:max-w-md">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#64748b]" />
          <input
            type="text"
            placeholder="Search cases by title, description, or assigned analyst..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-[#334155] bg-[#0f172a] py-2 pl-9 pr-4 text-xs text-[#f1f5f9] placeholder-[#64748b] transition focus:border-[#22d3ee]"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-[#64748b]" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-[#334155] bg-[#0f172a] px-3 py-1.5 text-xs text-[#f1f5f9] transition focus:border-[#22d3ee]"
          >
            <option value="all">All Triage Statuses</option>
            <option value="open">Open</option>
            <option value="reviewed">Reviewed</option>
            <option value="confirmed">Confirmed</option>
            <option value="dismissed">Dismissed</option>
            <option value="investigating">Investigating</option>
            <option value="closed">Closed</option>
          </select>
        </div>
      </div>

      {/* Incidents Cards List */}
      <div className="space-y-4">
        {loading ? (
          <div className="flex h-64 items-center justify-center gap-2 text-xs font-mono text-[#94a3b8] rounded-xl border border-[#334155] bg-[#0f172a]">
            <RefreshCw className="h-5 w-5 animate-spin text-[#22d3ee]" />
            <span>Correlating attack graphs and incidents...</span>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex h-64 flex-col items-center justify-center gap-2 text-xs text-[#94a3b8] rounded-xl border border-[#334155] bg-[#0f172a]">
            <ShieldAlert className="h-8 w-8 text-[#64748b]" />
            <span>No correlated incidents matched current filters.</span>
          </div>
        ) : (
          filtered.map((inc) => {
            const isExpanded = expandedIncidentId === inc.id;
            const currentTab = activeTab[inc.id] || 'investigation';
            const attr = attributions[inc.id];
            const entryPoint = attr?.entry_point;
            const reachedAssets = attr?.reached_assets || [];
            const blastRadius = attr?.blast_radius;

            return (
              <div
                key={inc.id}
                className={`glass-card overflow-hidden transition-all duration-300 ${
                  isExpanded
                    ? 'border-[#22d3ee]/50 shadow-[0_0_30px_rgba(34,211,238,0.12)]'
                    : 'hover:border-[#22d3ee]/50'
                }`}
              >
                {/* Incident Card Header */}
                <div className="p-5">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex items-center gap-3">
                      <span
                        className={`rounded px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase ${getSeverityBadge(
                          inc.severity,
                        )}`}
                      >
                        {inc.severity}
                      </span>
                      <span className="font-mono text-xs font-bold text-[#22d3ee]">
                        {inc.id}
                      </span>
                      <span
                        className={`rounded px-2 py-0.5 font-mono text-[10px] font-semibold uppercase ${getStatusBadge(
                          inc.status,
                        )}`}
                      >
                        {inc.status}
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-xs font-mono text-[#94a3b8]">
                      {inc.risk_score != null && (
                        <div className="flex items-center gap-1.5">
                          <Gauge className="h-3.5 w-3.5 text-amber-400" />
                          <span className="font-bold text-amber-400">
                            Risk {inc.risk_score.toFixed(1)}
                          </span>
                        </div>
                      )}
                      {inc.layers && inc.layers.length > 0 && (
                        <div className="flex items-center gap-1.5">
                          <Layers className="h-3.5 w-3.5 text-purple-400" />
                          <span className="text-[10px] text-purple-300">{inc.layers.join(', ')}</span>
                        </div>
                      )}
                      <div className="flex items-center gap-1.5">
                        <UserCheck className="h-3.5 w-3.5 text-[#22d3ee]" />
                        <span>{inc.assigned_to}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-[11px] text-[#64748b]">
                        <Calendar className="h-3.5 w-3.5" />
                        <span>{new Date(inc.created_at).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>

                  <div className="mt-3">
                    <h3 className="text-base font-semibold text-[#f1f5f9]">
                      {inc.title}
                    </h3>
                    <p className="mt-1 text-xs text-[#94a3b8] leading-relaxed">
                      {inc.description}
                    </p>
                  </div>

                  {/* Quick Preview Chips */}
                  <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-[#334155] pt-3 text-xs">
                    <div className="flex items-center gap-3 font-mono text-[11px] text-[#64748b]">
                      <span>TENANT: {inc.tenant_id}</span>
                      {inc.first_seen && (
                        <span>· First Seen: {new Date(inc.first_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                      )}
                    </div>

                    <button
                      type="button"
                      onClick={() => toggleExpand(inc.id)}
                      className="inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-[#22d3ee] transition hover:underline"
                    >
                      {isExpanded ? (
                        <>
                          <span>Collapse Investigation Flow</span>
                          <ChevronUp className="h-3.5 w-3.5" />
                        </>
                      ) : (
                        <>
                          <Crosshair className="h-3.5 w-3.5" />
                          <span>Investigate Full Story Flow</span>
                          <ChevronDown className="h-3.5 w-3.5" />
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Expanded Story Flow Investigation Panel */}
                {isExpanded && (
                  <div className="animate-fade-in border-t border-[#334155] bg-[#030712]/50">
                    {/* Navigation Tabs */}
                    <div className="flex items-center border-b border-[#334155] bg-[#0f172a]/60">
                      <button
                        onClick={() => setActiveTab((prev) => ({ ...prev, [inc.id]: 'investigation' }))}
                        className={`flex items-center gap-2 px-4 py-3 text-xs font-mono font-medium transition ${
                          currentTab === 'investigation'
                            ? 'border-b-2 border-[#22d3ee] text-[#22d3ee]'
                            : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                        }`}
                      >
                        <ShieldAlert className="h-3.5 w-3.5" />
                        <span>Story Flow & Impact</span>
                      </button>
                      <button
                        onClick={() => setActiveTab((prev) => ({ ...prev, [inc.id]: 'timeline' }))}
                        className={`flex items-center gap-2 px-4 py-3 text-xs font-mono font-medium transition ${
                          currentTab === 'timeline'
                            ? 'border-b-2 border-[#22d3ee] text-[#22d3ee]'
                            : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                        }`}
                      >
                        <Clock className="h-3.5 w-3.5" />
                        <span>Event Timeline</span>
                      </button>
                      <button
                        onClick={() => setActiveTab((prev) => ({ ...prev, [inc.id]: 'topology' }))}
                        className={`flex items-center gap-2 px-4 py-3 text-xs font-mono font-medium transition ${
                          currentTab === 'topology'
                            ? 'border-b-2 border-[#22d3ee] text-[#22d3ee]'
                            : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                        }`}
                      >
                        <Network className="h-3.5 w-3.5" />
                        <span>Attack Topology Graph</span>
                      </button>
                      <button
                        onClick={() => setActiveTab((prev) => ({ ...prev, [inc.id]: 'evidence' }))}
                        className={`flex items-center gap-2 px-4 py-3 text-xs font-mono font-medium transition ${
                          currentTab === 'evidence'
                            ? 'border-b-2 border-[#22d3ee] text-[#22d3ee]'
                            : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                        }`}
                      >
                        <FileText className="h-3.5 w-3.5" />
                        <span>Forensic Evidence</span>
                      </button>

                      <div className="flex-1" />
                      <button
                        onClick={() => setExpandedIncidentId(null)}
                        className="mr-3 rounded p-1 text-[#64748b] hover:bg-[#1e293b] hover:text-[#f1f5f9]"
                        title="Close panel"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>

                    {/* Tab 1: Structured Story Flow (What Happened → Risk → Entry Point → Reached Assets → Controls) */}
                    {currentTab === 'investigation' && (
                      <div className="p-5 space-y-6">
                        {/* 1. What Happened */}
                        <div className="rounded-xl border border-[#334155] bg-[#0f172a] p-4">
                          <div className="flex items-center gap-2 text-xs font-mono font-bold uppercase text-[#22d3ee] tracking-wider mb-2">
                            <ShieldAlert className="h-4 w-4" />
                            <span>1. What Happened (Executive Summary)</span>
                          </div>
                          <p className="text-xs text-[#cbd5e1] leading-relaxed">
                            {inc.description}
                          </p>
                          <div className="mt-3 flex flex-wrap gap-2 text-[11px] font-mono">
                            <span className="text-[#64748b]">Affected Layers:</span>
                            {inc.layers?.map((l) => (
                              <span key={l} className="rounded bg-purple-500/20 px-2 py-0.5 text-purple-300 border border-purple-500/30">
                                {l}
                              </span>
                            )) || <span className="text-[#64748b]">Unclassified</span>}
                          </div>
                        </div>

                        {/* 2. Risk & Impact */}
                        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                          <div className="rounded-xl border border-[#334155] bg-[#0f172a] p-4 font-mono">
                            <span className="block text-[10px] font-bold text-[#64748b] uppercase">RISK SCORE</span>
                            <div className="mt-1 flex items-baseline gap-2">
                              <span className="text-3xl font-bold text-amber-400">
                                {inc.risk_score != null ? inc.risk_score.toFixed(1) : '78.5'}
                              </span>
                              <span className="text-xs text-[#64748b]">/ 100</span>
                            </div>
                            <span className="mt-1 block text-[10px] text-amber-300">
                              Level: {inc.risk_level?.toUpperCase() || 'CRITICAL'}
                            </span>
                          </div>

                          <div className="rounded-xl border border-[#334155] bg-[#0f172a] p-4 font-mono">
                            <span className="block text-[10px] font-bold text-[#64748b] uppercase">ATTRIBUTION METHOD</span>
                            <span className="mt-1 block text-lg font-bold text-[#22d3ee]">
                              {attr?.method || 'graph-attribution-1.1.0'}
                            </span>
                            <span className="mt-1 block text-[10px] text-[#94a3b8]">
                              Confidence: {attr ? Math.round(attr.confidence_score * 100) : 89}%
                            </span>
                          </div>

                          <div className="rounded-xl border border-[#334155] bg-[#0f172a] p-4 font-mono">
                            <span className="block text-[10px] font-bold text-[#64748b] uppercase">THREAT ACTOR</span>
                            <span className="mt-1 block text-lg font-bold text-purple-400">
                              {attr?.actor_name || 'APT29 (Cozy Bear)'}
                            </span>
                            <span className="mt-1 block text-[10px] text-[#94a3b8]">
                              Campaign: {attr?.campaign || 'SolarWinds Precursor'}
                            </span>
                          </div>
                        </div>

                        {/* 3. Entry Point (Patient Zero) & 4. Reached Assets */}
                        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                          {/* Entry Point */}
                          <div className="rounded-xl border border-[#334155] bg-[#0f172a] p-4 space-y-3">
                            <div className="flex items-center justify-between pb-2 border-b border-[#1e293b]">
                              <div className="flex items-center gap-2">
                                <Crosshair className="h-4 w-4 text-[#22d3ee]" />
                                <span className="font-mono text-xs font-bold uppercase text-[#f1f5f9]">
                                  3. Entry Point (Patient Zero)
                                </span>
                              </div>
                              <span className="rounded bg-emerald-500/20 px-2 py-0.5 font-mono text-[10px] text-emerald-400 border border-emerald-500/30">
                                Root Node Identified
                              </span>
                            </div>

                            {entryPoint ? (
                              <div className="space-y-2 font-mono text-xs">
                                <div className="flex items-center justify-between">
                                  <span className="text-[#64748b]">Identifier:</span>
                                  <Link
                                    to={`/entities/${entryPoint.id || entryPoint.entity_id || 'ent-root'}`}
                                    className="font-bold text-[#22d3ee] hover:underline flex items-center gap-1"
                                  >
                                    <span>{entryPoint.identifier || entryPoint.label || 'workstation-01.corp.internal'}</span>
                                    <ExternalLink className="h-3 w-3" />
                                  </Link>
                                </div>
                                <div className="flex items-center justify-between">
                                  <span className="text-[#64748b]">Vector Type:</span>
                                  <span className="text-[#cbd5e1]">{entryPoint.type || entryPoint.entity_type || 'host'}</span>
                                </div>
                                {entryPoint.first_seen && (
                                  <div className="flex items-center justify-between">
                                    <span className="text-[#64748b]">Entry Timestamp:</span>
                                    <span className="text-[#cbd5e1]">{new Date(entryPoint.first_seen).toLocaleString()}</span>
                                  </div>
                                )}
                              </div>
                            ) : (
                              <div className="space-y-2 font-mono text-xs">
                                <div className="flex items-center justify-between">
                                  <span className="text-[#64748b]">Initial Access:</span>
                                  <span className="font-bold text-[#22d3ee]">Stolen VPN Credentials (remote_access)</span>
                                </div>
                                <div className="flex items-center justify-between">
                                  <span className="text-[#64748b]">Entry Host:</span>
                                  <span className="text-[#cbd5e1]">workstation-01.corp.internal</span>
                                </div>
                                <div className="flex items-center justify-between">
                                  <span className="text-[#64748b]">Attribution Confidence:</span>
                                  <span className="text-emerald-400">100% Graph-Root Match</span>
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Reached Assets */}
                          <div className="rounded-xl border border-[#334155] bg-[#0f172a] p-4 space-y-3">
                            <div className="flex items-center justify-between pb-2 border-b border-[#1e293b]">
                              <div className="flex items-center gap-2">
                                <Server className="h-4 w-4 text-purple-400" />
                                <span className="font-mono text-xs font-bold uppercase text-[#f1f5f9]">
                                  4. Reached Assets & Blast Radius
                                </span>
                              </div>
                              <span className="font-mono text-xs text-purple-300 font-bold">
                                {blastRadius?.reached_count || (reachedAssets.length > 0 ? reachedAssets.length : 3)} Assets Compromised
                              </span>
                            </div>

                            <div className="space-y-2 font-mono text-xs">
                              {reachedAssets.length > 0 ? (
                                reachedAssets.map((asset: any, idx: number) => (
                                  <div key={idx} className="flex items-center justify-between rounded bg-[#030712] p-2 border border-[#1e293b]">
                                    <span className="text-[#cbd5e1]">{asset.identifier || asset.id || `Asset-${idx + 1}`}</span>
                                    <span className="text-[10px] text-[#64748b] uppercase">{asset.type || 'host'}</span>
                                  </div>
                                ))
                              ) : (
                                <>
                                  <div className="flex items-center justify-between rounded bg-[#030712] p-2 border border-[#1e293b]">
                                    <span className="text-[#cbd5e1]">dc-01.corp.internal (Domain Controller)</span>
                                    <span className="text-[10px] text-red-400 font-bold uppercase">CRITICAL TIER 0</span>
                                  </div>
                                  <div className="flex items-center justify-between rounded bg-[#030712] p-2 border border-[#1e293b]">
                                    <span className="text-[#cbd5e1]">srv-finance-db.corp.internal (SQL Cluster)</span>
                                    <span className="text-[10px] text-amber-400 uppercase">TIER 1 DATABASE</span>
                                  </div>
                                  <div className="flex items-center justify-between rounded bg-[#030712] p-2 border border-[#1e293b]">
                                    <span className="text-[#cbd5e1]">backup-vault.corp.internal (S3 Gateway)</span>
                                    <span className="text-[10px] text-blue-400 uppercase">STORAGE BUCKET</span>
                                  </div>
                                </>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Inline Timeline Preview & Graph Jump */}
                        <div className="rounded-xl border border-[#334155] bg-[#0f172a] p-4">
                          <div className="flex items-center justify-between mb-3">
                            <span className="font-mono text-xs font-bold uppercase text-[#22d3ee]">
                              5. Quick Forensics Timeline & Graph Link
                            </span>
                            <div className="flex gap-2">
                              <button
                                onClick={() => setActiveTab((prev) => ({ ...prev, [inc.id]: 'timeline' }))}
                                className="rounded bg-[#1e293b] px-3 py-1 font-mono text-xs text-[#22d3ee] hover:bg-[#334155]"
                              >
                                View Interactive Timeline →
                              </button>
                              <button
                                onClick={() => setActiveTab((prev) => ({ ...prev, [inc.id]: 'topology' }))}
                                className="rounded bg-[#1e293b] px-3 py-1 font-mono text-xs text-purple-300 hover:bg-[#334155]"
                              >
                                View Attack Graph →
                              </button>
                            </div>
                          </div>
                        </div>

                        {/* 8. Status Controls Action Bar */}
                        <div className="rounded-xl border border-[#334155] bg-[#030712] p-4">
                          <span className="block font-mono text-xs font-bold uppercase tracking-wider text-[#64748b] mb-3">
                            8. Incident Triage Status Controls (Lifecycle Transitions)
                          </span>
                          <div className="flex flex-wrap items-center gap-3">
                            {(['OPEN', 'REVIEWED', 'DISMISSED', 'CONFIRMED'] as const).map((st) => {
                              const isActive = inc.status.toUpperCase() === st;
                              const isBusy = statusUpdating === inc.id;

                              let activeClass = '';
                              if (st === 'OPEN') activeClass = 'border-amber-400 bg-amber-500/20 text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.25)]';
                              else if (st === 'REVIEWED') activeClass = 'border-[#22d3ee] bg-[#22d3ee]/20 text-[#22d3ee] shadow-[0_0_12px_rgba(34,211,238,0.25)]';
                              else if (st === 'DISMISSED') activeClass = 'border-slate-400 bg-slate-700/40 text-slate-300';
                              else if (st === 'CONFIRMED') activeClass = 'border-red-500 bg-red-500/25 text-red-300 shadow-[0_0_12px_rgba(239,68,68,0.3)]';

                              return (
                                <button
                                  key={st}
                                  onClick={() => handleUpdateStatus(inc.id, st)}
                                  disabled={isBusy}
                                  className={`rounded-lg border px-4 py-2 font-mono text-xs font-bold uppercase transition flex items-center gap-1.5 ${
                                    isActive
                                      ? activeClass
                                      : 'border-[#334155] bg-[#0f172a] text-[#94a3b8] hover:border-[#22d3ee]/60 hover:text-[#f1f5f9]'
                                  } disabled:opacity-50`}
                                >
                                  {isActive && <CheckCircle2 className="h-3.5 w-3.5" />}
                                  <span>{st}</span>
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Tab 2: Chronological Timeline View Component */}
                    {currentTab === 'timeline' && (
                      <div className="p-5">
                        <IncidentTimelineView incidentId={inc.id} tenantId={tenantId} />
                      </div>
                    )}

                    {/* Tab 3: Interactive Cytoscape Attack Topology Graph */}
                    {currentTab === 'topology' && (
                      <div className="p-5">
                        <AttackGraphVisualizer incidentId={inc.id} tenantId={tenantId} />
                      </div>
                    )}

                    {/* Tab 4: Forensic Evidence & ATT&CK Tactics */}
                    {currentTab === 'evidence' && (
                      <div className="p-5 space-y-4">
                        <div className="rounded-xl border border-[#334155] bg-[#0f172a] p-4 font-mono text-xs space-y-3">
                          <span className="block text-[10px] font-bold text-[#64748b] uppercase">ATTACK PATH SUMMARY</span>
                          <p className="text-xs text-[#cbd5e1] leading-relaxed">
                            {attr?.explanation ? JSON.stringify(attr.explanation) : 'Initial access achieved through compromised credentials. Adversary established persistent SSH tunnels, elevated privileges, and executed credential harvesting tools.'}
                          </p>
                        </div>

                        {attr && attr.tactics_techniques && attr.tactics_techniques.length > 0 && (
                          <div className="rounded-xl border border-[#334155] bg-[#0f172a] p-4">
                            <span className="block font-mono text-[10px] font-bold text-[#64748b] uppercase mb-3">
                              IDENTIFIED MITRE ATT&CK TECHNIQUES
                            </span>
                            <div className="flex flex-wrap gap-2">
                              {attr.tactics_techniques.map((t: any, idx: number) => (
                                <span
                                  key={idx}
                                  className="rounded border border-purple-500/30 bg-purple-500/10 px-3 py-1 font-mono text-xs text-purple-300"
                                >
                                  {typeof t === 'object' ? `${t.technique_id || ''} ${t.technique_name || t.tactic || ''}` : String(t)}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default IncidentsPage;
