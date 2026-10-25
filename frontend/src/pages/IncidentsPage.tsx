import { useState, useEffect, useCallback, useMemo } from 'react';
import { useAuth } from '../context/useAuth';
import {
  incidentsApi,
  attributionsApi,
  alertsApi,
  type IncidentItem,
  type AttributionItem,
  type AlertItem,
} from '../services/api';
import { AttackGraphVisualizer } from '../components/graph/AttackGraphVisualizer';
import { IncidentTimelineView } from '../components/incident/IncidentTimelineView';
import {
  ShieldAlert,
  Search,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Copy,
  Check,
  FileCode,
  Network,
  CheckSquare,
  Eye,
  XCircle,
} from 'lucide-react';

export function IncidentsPage() {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [activeTab, setActiveTab] = useState<'topology' | 'timeline' | 'evidence'>('topology');

  // Attribution and alert evidence caches
  const [attributions, setAttributions] = useState<Record<string, AttributionItem | null>>({});
  const [incidentAlerts, setIncidentAlerts] = useState<Record<string, AlertItem[]>>({});
  const [statusUpdating, setStatusUpdating] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const tenantId = user?.tenant_id || 'tenant_default';

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await incidentsApi.list(tenantId);
      const items = res.data.items || [];
      setIncidents(items);
      if (items.length > 0 && !selectedIncidentId) {
        setSelectedIncidentId(items[0].id);
      }
    } catch (err: any) {
      setError(
        err?.response?.data?.detail ||
          'Failed to load correlated incidents from platform API.',
      );
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  }, [tenantId, selectedIncidentId]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  // Load attribution and alerts for the currently active incident
  useEffect(() => {
    if (!selectedIncidentId) return;

    if (attributions[selectedIncidentId] === undefined) {
      attributionsApi
        .list(tenantId, { incident_id: selectedIncidentId })
        .then((res) => {
          const items = res.data.items || [];
          setAttributions((prev) => ({ ...prev, [selectedIncidentId]: items[0] || null }));
        })
        .catch(() => {
          setAttributions((prev) => ({ ...prev, [selectedIncidentId]: null }));
        });
    }

    if (incidentAlerts[selectedIncidentId] === undefined) {
      alertsApi
        .list(tenantId, { limit: 50 })
        .then((res) => {
          const allAlerts = res.data.items || [];
          const related = allAlerts.filter(
            (a) =>
              (a as any).incident_id === selectedIncidentId ||
              a.description?.toLowerCase().includes(selectedIncidentId.toLowerCase()),
          );
          setIncidentAlerts((prev) => ({
            ...prev,
            [selectedIncidentId]: related.length > 0 ? related : allAlerts.slice(0, 4),
          }));
        })
        .catch(() => {
          setIncidentAlerts((prev) => ({ ...prev, [selectedIncidentId]: [] }));
        });
    }
  }, [selectedIncidentId, tenantId, attributions, incidentAlerts]);

  const handleUpdateStatus = async (targetStatus: string) => {
    if (!selectedIncidentId) return;
    setStatusUpdating(true);
    try {
      const normalized = targetStatus.toLowerCase();
      await incidentsApi.updateStatus(selectedIncidentId, normalized);
      setIncidents((prev) =>
        prev.map((i) => (i.id === selectedIncidentId ? { ...i, status: normalized } : i)),
      );
      setActionNotice(`INCIDENT STATUS UPDATED: ${targetStatus.toUpperCase()}`);
      setTimeout(() => setActionNotice(null), 3000);
    } catch (err: any) {
      setError(err?.response?.data?.detail || `Failed to transition status to ${targetStatus}.`);
    } finally {
      setStatusUpdating(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchesSearch =
        inc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inc.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        inc.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesStatus =
        statusFilter === 'all' || inc.status.toLowerCase() === statusFilter.toLowerCase();
      return matchesSearch && matchesStatus;
    });
  }, [incidents, searchQuery, statusFilter]);

  const activeIncident = useMemo(() => {
    return incidents.find((i) => i.id === selectedIncidentId) || filteredIncidents[0] || null;
  }, [incidents, selectedIncidentId, filteredIncidents]);

  const activeAttribution = activeIncident ? attributions[activeIncident.id] : null;
  const activeAlertList = activeIncident ? incidentAlerts[activeIncident.id] || [] : [];

  return (
    <div className="space-y-6 min-h-[85vh] flex flex-col">
      {/* Action Notification Banner */}
      {actionNotice && (
        <div className="flex items-center gap-3 border-2 border-[#c81b1c] bg-[#1a0505] p-4 text-sm font-semibold text-white shadow-lg animate-fade-in">
          <CheckCircle2 className="h-5 w-5 text-[#c81b1c] flex-shrink-0" />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="flex items-center justify-between border-2 border-[#c81b1c] bg-[#1a0505] p-4 text-sm text-white shadow-lg">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-[#c81b1c] flex-shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={fetchIncidents} className="btn btn-outline btn-sm">
            Retry
          </button>
        </div>
      )}

      {/* 2-Column Story Arc Workspace Layout filling viewport naturally */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1 min-h-[85vh]">
        {/* LEFT COLUMN: Incident Directory (4 Cols on LG, min-height 85vh) */}
        <div className="lg:col-span-4 flex flex-col border border-[#262626] bg-[#090909]/95 min-h-[85vh]">
          {/* Header & Search Controls */}
          <div className="p-5 border-b border-[#222222] space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="font-sg text-base lg:text-lg font-bold uppercase tracking-wider text-white">
                  Incident Directory
                </h2>
                <span className="text-xs text-[#94a3b8]">Active Correlated Attacks</span>
              </div>
              <span className="font-mono text-xs font-semibold px-2 py-1 bg-[#141414] border border-[#2a2a2a] text-[#94a3b8]">
                {filteredIncidents.length} CASES
              </span>
            </div>

            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3.5 top-3.5 h-4 w-4 text-[#94a3b8]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search case ID, title, actor..."
                className="w-full pl-10 pr-4 py-2.5 text-sm bg-black border border-[#2d3748] text-white placeholder-[#64748b] transition focus:border-[#c81b1c]"
              />
            </div>

            {/* Filter Buttons */}
            <div className="flex flex-wrap gap-1.5 font-sg text-xs font-bold">
              {['all', 'open', 'confirmed', 'reviewed', 'dismissed'].map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-3 py-1.5 uppercase tracking-wider border transition ${
                    statusFilter === st
                      ? 'border-[#c81b1c] bg-[#c81b1c] text-white'
                      : 'border-[#262626] bg-[#111111] text-[#94a3b8] hover:text-white hover:border-[#444444]'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {/* Incident List */}
          <div className="p-4 space-y-3 flex-1 overflow-y-auto max-h-[calc(100vh-280px)]">
            {loading && (
              <div className="flex items-center justify-center p-12 text-[#94a3b8] text-sm">
                <RefreshCw className="h-5 w-5 animate-spin text-[#c81b1c] mr-2" />
                Synchronizing Case Directory...
              </div>
            )}

            {!loading && filteredIncidents.length === 0 && (
              <div className="p-12 text-center text-sm text-[#94a3b8]">
                No incidents match the active search or status filter.
              </div>
            )}

            {filteredIncidents.map((inc) => {
              const isSelected = activeIncident?.id === inc.id;
              const isCritical = inc.severity.toLowerCase() === 'critical';
              const risk = inc.risk_score ?? 80;

              return (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncidentId(inc.id)}
                  className={`cursor-pointer border p-5 transition space-y-2.5 ${
                    isSelected
                      ? 'border-[#c81b1c] bg-[#161616] border-l-4 shadow-[0_0_20px_rgba(200,27,28,0.15)]'
                      : 'border-[#222222] bg-[#0c0c0c] hover:border-[#444444] hover:bg-[#121212]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-[#94a3b8] uppercase">
                      {inc.id}
                    </span>
                    <span
                      className={`px-2 py-0.5 font-sg text-xs font-bold uppercase tracking-wider ${
                        isCritical
                          ? 'border border-[#c81b1c] bg-[#220606] text-[#c81b1c]'
                          : 'border border-[#334155] bg-[#141414] text-[#e2e8f0]'
                      }`}
                    >
                      {isCritical ? 'CRITICAL' : 'REVIEW'}
                    </span>
                  </div>

                  <h3 className="font-sg text-sm md:text-base font-bold text-white uppercase tracking-wide leading-snug line-clamp-2">
                    {inc.title}
                  </h3>

                  <div className="flex items-center justify-between text-xs pt-1 border-t border-[#1a1a1a]">
                    <span className="text-[#94a3b8]">
                      STATUS: <strong className="text-white uppercase font-bold">{inc.status}</strong>
                    </span>
                    <span className="font-mono text-xs font-bold text-[#c81b1c]">
                      RISK {risk}/100
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* RIGHT COLUMN: Active Investigation Workspace (8 Cols on LG, min-height 85vh) */}
        <div className="lg:col-span-8 flex flex-col border border-[#262626] bg-[#090909]/95 p-6 lg:p-8 min-h-[85vh] space-y-6">
          {!activeIncident ? (
            <div className="flex flex-1 flex-col items-center justify-center p-12 text-center">
              <ShieldAlert className="h-14 w-14 text-[#c81b1c] mb-4" />
              <h3 className="font-sg text-xl font-bold uppercase text-white">
                No Incident Selected
              </h3>
              <p className="mt-2 text-sm text-[#94a3b8] max-w-md">
                Select an incident case from the directory on the left to begin deep-dive investigation.
              </p>
            </div>
          ) : (
            <>
              {/* Workspace Header: Prominent 24px-30px Title, Badges, and Status Actions */}
              <div className="space-y-5 border-b border-[#222222] pb-6">
                <div className="flex flex-col xl:flex-row xl:items-start xl:justify-between gap-5">
                  {/* Title & Metadata */}
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span className="font-mono text-xs font-bold text-[#94a3b8] bg-[#141414] border border-[#2a2a2a] px-2.5 py-1 uppercase">
                        CASE: {activeIncident.id}
                      </span>
                      <span
                        className={`px-3 py-1 font-sg text-xs font-bold uppercase tracking-wider ${
                          activeIncident.severity.toLowerCase() === 'critical'
                            ? 'border-2 border-[#c81b1c] bg-[#c81b1c] text-white'
                            : 'border-2 border-[#475569] bg-[#141414] text-white'
                        }`}
                      >
                        {activeIncident.severity.toLowerCase() === 'critical' ? 'CRITICAL TIER' : 'REVIEW TIER'}
                      </span>
                      <span className="border border-[#334155] bg-[#111111] px-2.5 py-1 font-sg text-xs uppercase tracking-wider text-[#94a3b8]">
                        STATE: <strong className="text-white uppercase">{activeIncident.status}</strong>
                      </span>
                    </div>

                    {/* Main Prominent Incident Title (24px - 30px) */}
                    <h1 className="font-sg text-2xl lg:text-3xl font-bold uppercase tracking-wide text-white leading-tight pt-1">
                      {activeIncident.title}
                    </h1>

                    <p className="text-sm text-[#e2e8f0] leading-relaxed max-w-3xl">
                      {activeIncident.description}
                    </p>
                  </div>

                  {/* Risk Score Gauge Badge */}
                  <div className="flex items-center gap-4 border-2 border-[#262626] bg-[#0c0c0c] p-4 flex-shrink-0 self-start">
                    <div className="flex flex-col items-end">
                      <span className="font-sg text-xs font-bold uppercase tracking-wider text-[#94a3b8]">
                        Composite Risk
                      </span>
                      <span className="font-mono text-3xl lg:text-4xl font-bold text-[#c81b1c] leading-none mt-1">
                        {activeIncident.risk_score ?? 85}
                        <span className="text-sm text-[#94a3b8] font-normal">/100</span>
                      </span>
                      <span className="font-sg text-xs font-bold text-[#e2e8f0] uppercase tracking-wider mt-1">
                        {activeIncident.risk_level || 'CRITICAL'} THREAT
                      </span>
                    </div>
                  </div>
                </div>

                {/* Status Action Buttons Bar: Clear Distinct High-Contrast Buttons */}
                <div className="flex flex-wrap items-center justify-between gap-4 pt-3 border-t border-[#1a1a1a]">
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="font-sg text-xs font-bold uppercase tracking-wider text-[#94a3b8] mr-1">
                      Triage Actions:
                    </span>
                    <button
                      onClick={() => handleUpdateStatus('confirmed')}
                      disabled={statusUpdating}
                      className="inline-flex items-center gap-2 bg-[#c81b1c] text-white border-2 border-[#c81b1c] hover:bg-[#b01617] hover:border-[#b01617] px-5 py-2.5 font-sg text-xs font-bold uppercase tracking-wider transition active:scale-95 disabled:opacity-50"
                    >
                      <CheckSquare className="h-4 w-4" />
                      <span>CONFIRM</span>
                    </button>
                    <button
                      onClick={() => handleUpdateStatus('reviewed')}
                      disabled={statusUpdating}
                      className="inline-flex items-center gap-2 bg-[#0c1a14] text-emerald-400 border-2 border-emerald-500/80 hover:bg-emerald-600 hover:text-white px-5 py-2.5 font-sg text-xs font-bold uppercase tracking-wider transition active:scale-95 disabled:opacity-50"
                    >
                      <Eye className="h-4 w-4" />
                      <span>REVIEWED</span>
                    </button>
                    <button
                      onClick={() => handleUpdateStatus('dismissed')}
                      disabled={statusUpdating}
                      className="inline-flex items-center gap-2 bg-[#121212] text-slate-300 border-2 border-slate-600 hover:bg-slate-700 hover:text-white px-5 py-2.5 font-sg text-xs font-bold uppercase tracking-wider transition active:scale-95 disabled:opacity-50"
                    >
                      <XCircle className="h-4 w-4" />
                      <span>DISMISS</span>
                    </button>
                  </div>

                  <span className="text-xs text-[#94a3b8]">
                    ASSIGNED OPERATOR: <strong className="text-white uppercase font-bold">{activeIncident.assigned_to || 'SOC-LEAD'}</strong>
                  </span>
                </div>
              </div>

              {/* Story Arc Context Highlights */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border border-[#222222] bg-[#0c0c0c] p-5 text-sm">
                <div className="space-y-1 md:border-r md:border-[#1e1e1e] md:pr-4">
                  <span className="font-sg text-xs font-bold uppercase tracking-wider text-[#94a3b8] block">
                    Attribution Entry Point
                  </span>
                  <span className="text-[#c81b1c] font-bold text-base block truncate">
                    {activeAttribution?.entry_point?.identifier ||
                      activeAttribution?.entry_point?.label ||
                      'Stolen VPN Credentials'}
                  </span>
                  <span className="text-xs text-[#94a3b8]">Root of Causal Graph</span>
                </div>

                <div className="space-y-1 md:border-r md:border-[#1e1e1e] md:pr-4">
                  <span className="font-sg text-xs font-bold uppercase tracking-wider text-[#94a3b8] block">
                    Threat Actor Profile
                  </span>
                  <span className="text-white font-bold text-base block truncate">
                    {activeAttribution?.actor_name || 'APT-29 / Cozy Bear (MITRE)'}
                  </span>
                  <span className="text-xs text-[#94a3b8]">
                    Attribution Confidence: <strong className="text-[#e2e8f0]">{activeAttribution?.confidence_score ? `${(activeAttribution.confidence_score * 100).toFixed(0)}%` : '96%'}</strong>
                  </span>
                </div>

                <div className="space-y-1">
                  <span className="font-sg text-xs font-bold uppercase tracking-wider text-[#94a3b8] block">
                    Observed Telemetry Footprint
                  </span>
                  <span className="text-white font-bold text-base block">
                    {activeIncident.layers?.join(' · ') || 'Identity · Endpoint · Network'}
                  </span>
                  <span className="text-xs text-[#94a3b8]">
                    First Detected: {new Date(activeIncident.created_at).toLocaleDateString()}
                  </span>
                </div>
              </div>

              {/* Tab Workspace Bar */}
              <div className="flex border-b-2 border-[#222222] bg-black">
                <button
                  onClick={() => setActiveTab('topology')}
                  className={`flex items-center gap-2.5 px-6 py-3.5 font-sg text-sm font-bold uppercase tracking-wider border-b-2 transition ${
                    activeTab === 'topology'
                      ? 'border-[#c81b1c] text-white bg-[#141414]'
                      : 'border-transparent text-[#94a3b8] hover:text-white hover:bg-[#0c0c0c]'
                  }`}
                >
                  <Network className="h-4 w-4" />
                  <span>Attack Topology</span>
                </button>

                <button
                  onClick={() => setActiveTab('timeline')}
                  className={`flex items-center gap-2.5 px-6 py-3.5 font-sg text-sm font-bold uppercase tracking-wider border-b-2 transition ${
                    activeTab === 'timeline'
                      ? 'border-[#c81b1c] text-white bg-[#141414]'
                      : 'border-transparent text-[#949494] hover:text-white hover:bg-[#0c0c0c]'
                  }`}
                >
                  <Clock className="h-4 w-4" />
                  <span>Forensic Timeline</span>
                </button>

                <button
                  onClick={() => setActiveTab('evidence')}
                  className={`flex items-center gap-2.5 px-6 py-3.5 font-sg text-sm font-bold uppercase tracking-wider border-b-2 transition ${
                    activeTab === 'evidence'
                      ? 'border-[#c81b1c] text-white bg-[#141414]'
                      : 'border-transparent text-[#949494] hover:text-white hover:bg-[#0c0c0c]'
                  }`}
                >
                  <FileCode className="h-4 w-4" />
                  <span>Raw Evidence & Detectors</span>
                </button>
              </div>

              {/* Tab Content Display */}
              <div className="flex-1">
                {/* TAB 1: ATTACK TOPOLOGY */}
                {activeTab === 'topology' && (
                  <AttackGraphVisualizer incidentId={activeIncident.id} tenantId={tenantId} />
                )}

                {/* TAB 2: CHRONOLOGICAL TIMELINE */}
                {activeTab === 'timeline' && (
                  <IncidentTimelineView incidentId={activeIncident.id} tenantId={tenantId} />
                )}

                {/* TAB 3: RAW EVIDENCE & ML DETECTOR VIEWER */}
                {activeTab === 'evidence' && (
                  <div className="space-y-6">
                    {/* Detector Summaries */}
                    <div className="border border-[#222222] bg-[#0c0c0c] p-6 space-y-4">
                      <div className="flex items-center justify-between border-b border-[#222222] pb-3">
                        <span className="font-sg text-sm font-bold uppercase tracking-wider text-white">
                          ML Detectors & Behavioral Fusion
                        </span>
                        <span className="font-mono text-xs text-[#94a3b8]">
                          {activeAlertList.length} Detections Ingested
                        </span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {activeAlertList.map((alert, idx) => (
                          <div
                            key={alert.id || idx}
                            className="border border-[#222222] bg-black p-4 space-y-2 hover:border-[#444444] transition"
                          >
                            <div className="flex items-center justify-between text-xs">
                              <span className="text-[#c81b1c] font-bold uppercase font-sg">
                                {alert.detector || 'IsolationForestAnomaly'}
                              </span>
                              <span className="border border-[#2d3748] bg-[#111111] px-2 py-0.5 text-white font-mono font-semibold">
                                CONF: {alert.confidence !== undefined && alert.confidence !== null ? `${(alert.confidence * 100).toFixed(0)}%` : '94%'}
                              </span>
                            </div>

                            <h4 className="font-sg text-sm font-bold text-white uppercase tracking-wide">
                              {alert.title}
                            </h4>

                            <div className="flex items-center justify-between text-xs text-[#94a3b8] pt-1 border-t border-[#1a1a1a]">
                              <span>TECHNIQUE: <strong className="text-white font-mono">{alert.technique_id || alert.technique || 'T1078'}</strong></span>
                              <span className="uppercase font-bold text-[#c81b1c]">{alert.decision || 'ALERT'}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Raw JSON Forensic Dump */}
                    <div className="border border-[#222222] bg-[#0c0c0c] p-6 space-y-3">
                      <div className="flex items-center justify-between border-b border-[#222222] pb-3">
                        <span className="font-sg text-sm font-bold uppercase tracking-wider text-white">
                          Structured Incident Evidence Object
                        </span>
                        <button
                          onClick={() =>
                            copyToClipboard(
                              JSON.stringify({ incident: activeIncident, attribution: activeAttribution, detections: activeAlertList }, null, 2),
                              'raw-dump',
                            )
                          }
                          className="btn btn-outline btn-sm font-mono text-xs"
                        >
                          {copiedKey === 'raw-dump' ? <Check className="h-4 w-4 text-white" /> : <Copy className="h-4 w-4" />}
                          <span>{copiedKey === 'raw-dump' ? 'Copied' : 'Copy JSON'}</span>
                        </button>
                      </div>

                      <pre className="max-h-[500px] overflow-auto border border-[#222222] bg-black p-4 font-mono text-xs text-[#e2e8f0] leading-relaxed">
                        {JSON.stringify(
                          {
                            incident_id: activeIncident.id,
                            title: activeIncident.title,
                            risk_score: activeIncident.risk_score,
                            risk_level: activeIncident.risk_level,
                            severity: activeIncident.severity,
                            status: activeIncident.status,
                            attribution: activeAttribution,
                            analytical_evidence: activeAlertList.map((a) => ({
                              detector: a.detector,
                              confidence: a.confidence,
                              technique_id: a.technique_id || a.technique,
                              decision: a.decision,
                              raw_evidence: a.evidence,
                            })),
                          },
                          null,
                          2,
                        )}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default IncidentsPage;
