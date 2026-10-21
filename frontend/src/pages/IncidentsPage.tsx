import { useState, useEffect, useCallback, useMemo } from 'react';
import { useAuth } from '../context/useAuth';
import { incidentsApi, type IncidentItem } from '../services/api';
import { AttackGraphVisualizer } from '../components/graph/AttackGraphVisualizer';
import {
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  UserCheck,
  Calendar,
  Network,
  List,
  ChevronDown,
  ChevronUp,
  X,
  Gauge,
  Layers,
} from 'lucide-react';

export function IncidentsPage() {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [expandedIncidentId, setExpandedIncidentId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Record<string, 'details' | 'topology'>>({});

  const tenantId = user?.tenant_id || 'tenant_default';

  const defaultMockIncidents: IncidentItem[] = useMemo(() => [
    {
      id: 'inc-901',
      tenant_id: tenantId,
      title: 'Multi-Stage Active Directory Domain Compromise',
      description: 'Correlated credential dumping, lateral movement via PsExec, and unauthorized DCSync replication request.',
      severity: 'critical',
      status: 'open',
      assigned_to: 'analyst',
      created_at: '2026-10-09T08:00:00Z',
      updated_at: '2026-10-09T08:30:00Z',
    },
    {
      id: 'inc-902',
      tenant_id: tenantId,
      title: 'Ransomware Precursor — Cobalt Strike Infiltration',
      description: 'C2 beaconing followed by PowerShell encoded staging commands on finance workstation.',
      severity: 'high',
      status: 'investigating',
      assigned_to: 'admin',
      created_at: '2026-10-08T14:00:00Z',
      updated_at: '2026-10-09T07:45:00Z',
    },
    {
      id: 'inc-903',
      tenant_id: tenantId,
      title: 'Suspicious Cloud API Exfiltration from S3 Storage',
      description: 'Anomalous bulk download of proprietary model weights from AWS S3 bucket via compromised IAM key.',
      severity: 'medium',
      status: 'contained',
      assigned_to: 'analyst',
      created_at: '2026-10-07T11:00:00Z',
      updated_at: '2026-10-08T18:00:00Z',
    },
  ], [tenantId]);

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const res = await incidentsApi.list(tenantId);
      setIncidents(res.data.items || []);
    } catch {
      setIncidents(defaultMockIncidents);
    } finally {
      setLoading(false);
    }
  }, [tenantId, defaultMockIncidents]);

  useEffect(() => {
    let ignore = false;
    incidentsApi
      .list(tenantId)
      .then((res) => {
        if (!ignore) {
          setIncidents(res.data.items || []);
          setLoading(false);
        }
      })
      .catch(() => {
        if (!ignore) {
          setIncidents(defaultMockIncidents);
          setLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [tenantId, defaultMockIncidents]);

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
        return 'bg-purple-500/20 text-purple-400 border border-purple-500/40';
      case 'high':
        return 'bg-red-500/20 text-red-400 border border-red-500/40';
      case 'medium':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/40';
      default:
        return 'bg-blue-500/20 text-blue-400 border border-blue-500/40';
    }
  };

  const toggleExpand = (incId: string) => {
    if (expandedIncidentId === incId) {
      setExpandedIncidentId(null);
    } else {
      setExpandedIncidentId(incId);
      // Default to topology tab when opening
      setActiveTab((prev) => ({ ...prev, [incId]: 'topology' }));
    }
  };

  const setTabForIncident = (incId: string, tab: 'details' | 'topology') => {
    setActiveTab((prev) => ({ ...prev, [incId]: tab }));
  };

  return (
    <div className="space-y-6">
      {/* Page Title & Controls */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#f1f5f9]">
            Correlated Incidents
          </h1>
          <p className="text-xs font-mono text-[#94a3b8]">
            MULTI-STAGE ATTACK CAMPAIGNS & INVESTIGATION CASES
          </p>
        </div>
        <button
          onClick={fetchIncidents}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-[#334155] bg-[#1e293b] px-3 py-2 text-xs font-medium text-[#f1f5f9] transition hover:border-[#22d3ee] hover:text-[#22d3ee] active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Cases</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1 sm:max-w-md">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#64748b]" />
          <input
            type="text"
            placeholder="Search incidents by title, description, or owner..."
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
            className="rounded-lg border border-[#334155] bg-[#0f172a] px-3 py-2 text-xs text-[#f1f5f9] transition focus:border-[#22d3ee]"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="closed">Closed</option>
          </select>
        </div>
      </div>

      {/* Incidents Cards List */}
      <div className="space-y-4">
        {loading ? (
          <div className="flex items-center justify-center rounded-xl border border-[#334155] bg-[#0f172a] p-12 text-[#94a3b8]">
            <div className="flex items-center gap-2">
              <RefreshCw className="h-5 w-5 animate-spin text-[#22d3ee]" />
              <span className="font-mono text-xs">Loading correlated incidents...</span>
            </div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-xl border border-[#334155] bg-[#0f172a] p-12 text-[#94a3b8]">
            <ShieldAlert className="h-8 w-8 text-[#64748b]" />
            <span className="mt-2 text-sm font-medium">No incidents matched filters.</span>
          </div>
        ) : (
          filtered.map((inc) => {
            const isExpanded = expandedIncidentId === inc.id;
            const currentTab = activeTab[inc.id] || 'topology';

            return (
              <div
                key={inc.id}
                className={`glass-card overflow-hidden transition-all duration-300 ${
                  isExpanded ? 'border-[#22d3ee]/40 shadow-[0_0_30px_rgba(34,211,238,0.08)]' : 'hover:border-[#22d3ee]/60'
                }`}
              >
                {/* Card Header */}
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
                      <span className="font-mono text-xs text-[#22d3ee]">
                        {inc.id}
                      </span>
                      <span className="rounded bg-[#1e293b] px-2 py-0.5 font-mono text-[11px] uppercase text-[#94a3b8]">
                        {inc.status}
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-xs text-[#94a3b8]">
                      {inc.risk_score != null && (
                        <div className="flex items-center gap-1.5">
                          <Gauge className="h-3.5 w-3.5 text-amber-400" />
                          <span className="font-mono font-bold text-amber-400">{inc.risk_score.toFixed(1)}</span>
                        </div>
                      )}
                      {inc.layers && inc.layers.length > 0 && (
                        <div className="flex items-center gap-1.5">
                          <Layers className="h-3.5 w-3.5 text-purple-400" />
                          <span className="font-mono text-[10px] text-purple-300">{inc.layers.join(', ')}</span>
                        </div>
                      )}
                      <div className="flex items-center gap-1.5">
                        <UserCheck className="h-3.5 w-3.5 text-[#22d3ee]" />
                        <span className="font-mono">{inc.assigned_to}</span>
                      </div>
                      <div className="flex items-center gap-1.5 font-mono text-[11px]">
                        <Calendar className="h-3.5 w-3.5 text-[#64748b]" />
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

                  <div className="mt-4 flex items-center justify-between border-t border-[#334155] pt-3 text-xs">
                    <span className="font-mono text-[10px] text-[#64748b]">
                      TENANT: {inc.tenant_id}
                    </span>
                    <button
                      type="button"
                      onClick={() => toggleExpand(inc.id)}
                      className="flex items-center gap-1.5 text-[#22d3ee] transition hover:underline"
                    >
                      {isExpanded ? (
                        <>
                          <span>Close Investigation Panel</span>
                          <ChevronUp className="h-3.5 w-3.5" />
                        </>
                      ) : (
                        <>
                          <Network className="h-3.5 w-3.5" />
                          <span>Open Attack Topology & Graph</span>
                          <ChevronDown className="h-3.5 w-3.5" />
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Expandable Investigation Panel */}
                {isExpanded && (
                  <div className="animate-fade-in border-t border-[#334155] bg-[#030712]/40">
                    {/* Tab Bar */}
                    <div className="flex items-center border-b border-[#334155] bg-[#0f172a]/50">
                      <button
                        onClick={() => setTabForIncident(inc.id, 'topology')}
                        className={`flex items-center gap-2 px-5 py-3 text-xs font-medium transition ${
                          currentTab === 'topology'
                            ? 'border-b-2 border-[#22d3ee] text-[#22d3ee]'
                            : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                        }`}
                      >
                        <Network className="h-3.5 w-3.5" />
                        <span>Attack Topology</span>
                      </button>
                      <button
                        onClick={() => setTabForIncident(inc.id, 'details')}
                        className={`flex items-center gap-2 px-5 py-3 text-xs font-medium transition ${
                          currentTab === 'details'
                            ? 'border-b-2 border-[#22d3ee] text-[#22d3ee]'
                            : 'text-[#94a3b8] hover:text-[#f1f5f9]'
                        }`}
                      >
                        <List className="h-3.5 w-3.5" />
                        <span>Incident Details</span>
                      </button>
                      <div className="flex-1" />
                      <button
                        onClick={() => setExpandedIncidentId(null)}
                        className="mr-3 rounded-lg p-1.5 text-[#64748b] transition hover:bg-[#1e293b] hover:text-[#f1f5f9]"
                        title="Close panel"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>

                    {/* Tab Content */}
                    <div className="p-5">
                      {currentTab === 'topology' ? (
                        <AttackGraphVisualizer
                          incidentId={inc.id}
                          tenantId={tenantId}
                        />
                      ) : (
                        /* Details tab — incident metadata summary */
                        <div className="space-y-4">
                          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                            <DetailField label="Incident ID" value={inc.id} />
                            <DetailField label="Severity" value={inc.severity} />
                            <DetailField label="Status" value={inc.status} />
                            <DetailField label="Assigned To" value={inc.assigned_to} />
                            <DetailField label="Risk Score" value={inc.risk_score != null ? inc.risk_score.toString() : '—'} />
                            <DetailField label="Risk Level" value={inc.risk_level || '—'} />
                            <DetailField label="Created" value={new Date(inc.created_at).toLocaleString()} />
                            <DetailField label="Updated" value={new Date(inc.updated_at).toLocaleString()} />
                            {inc.first_seen && <DetailField label="First Seen" value={new Date(inc.first_seen).toLocaleString()} />}
                            {inc.last_seen && <DetailField label="Last Seen" value={new Date(inc.last_seen).toLocaleString()} />}
                          </div>
                          {inc.layers && inc.layers.length > 0 && (
                            <div className="rounded-lg border border-[#334155] bg-[#0f172a] p-3">
                              <span className="mb-2 block font-mono text-[10px] font-bold uppercase tracking-wider text-[#64748b]">
                                AFFECTED LAYERS
                              </span>
                              <div className="flex flex-wrap gap-2">
                                {inc.layers.map((layer) => (
                                  <span
                                    key={layer}
                                    className="rounded-full bg-purple-500/10 px-3 py-1 font-mono text-[11px] font-medium text-purple-300 border border-purple-500/30"
                                  >
                                    {layer}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                          <div className="rounded-lg border border-[#334155] bg-[#0f172a] p-3">
                            <span className="mb-2 block font-mono text-[10px] font-bold uppercase tracking-wider text-[#64748b]">
                              DESCRIPTION
                            </span>
                            <p className="text-xs leading-relaxed text-[#94a3b8]">{inc.description}</p>
                          </div>
                        </div>
                      )}
                    </div>
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

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[#334155] bg-[#0f172a] p-3">
      <span className="block font-mono text-[10px] font-bold uppercase tracking-wider text-[#64748b]">{label}</span>
      <span className="mt-1 block text-sm font-medium text-[#f1f5f9]">{value}</span>
    </div>
  );
}

export default IncidentsPage;
