import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { alertsApi, type AlertItem } from '../services/api';
import {
  BellRing,
  Search,
  Filter,
  RefreshCw,
  AlertTriangle,
  HelpCircle,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Cpu,
  Zap,
} from 'lucide-react';

export function AlertsPage() {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [decisionFilter, setDecisionFilter] = useState('all');
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  const tenantId = user?.tenant_id || 'tenant_default';

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await alertsApi.list(tenantId);
      setAlerts(res.data.items || []);
    } catch (err: any) {
      setError(
        err?.response?.data?.detail ||
          'Failed to load analytical alerts from platform API.',
      );
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      alert.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (alert.technique && alert.technique.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (alert.detector && alert.detector.toLowerCase().includes(searchQuery.toLowerCase())) ||
      alert.description.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity =
      severityFilter === 'all' || alert.severity.toLowerCase() === severityFilter.toLowerCase();

    const matchesDecision =
      decisionFilter === 'all' ||
      (alert.decision && alert.decision.toLowerCase() === decisionFilter.toLowerCase());

    return matchesSearch && matchesSeverity && matchesDecision;
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

  const getDecisionBadge = (decision?: string | null) => {
    const dec = (decision || 'alert').toLowerCase();
    if (dec === 'review') {
      return (
        <span
          className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/60 bg-amber-500/20 px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.3)] animate-pulse"
          title="Playbook Requirement: Review decision represents an uncertain analytical state requiring manual analyst validation."
        >
          <HelpCircle className="h-3 w-3 text-amber-400" />
          <span>REVIEW (UNCERTAIN)</span>
        </span>
      );
    }
    if (dec === 'suppress') {
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-slate-600 bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-400">
          <span>SUPPRESSED</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/50 bg-emerald-500/10 px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase text-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.2)]">
        <Zap className="h-3 w-3 text-emerald-400" />
        <span>ACTIONABLE ALERT</span>
      </span>
    );
  };

  const toggleExpand = (id: string) => {
    setExpandedAlertId(expandedAlertId === id ? null : id);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-[#f1f5f9]">
              ML Detections & Alerts
            </h1>
            <span className="rounded bg-[#22d3ee]/10 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-[#22d3ee] border border-[#22d3ee]/30">
              {alerts.length} Total Hits
            </span>
          </div>
          <p className="mt-0.5 text-xs font-mono text-[#94a3b8]">
            RULES ENGINE · ISOLATION FOREST · LOGREG FUSION · CALIBRATED PROBABILITIES
          </p>
        </div>

        <button
          onClick={fetchAlerts}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-[#334155] bg-[#1e293b] px-3.5 py-2 text-xs font-mono font-medium text-[#f1f5f9] transition hover:border-[#22d3ee] hover:text-[#22d3ee] disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Alerts</span>
        </button>
      </div>

      {/* Error State Banner */}
      {error && (
        <div className="flex items-center justify-between rounded-xl border border-red-500/40 bg-red-950/20 p-4 text-xs font-mono text-red-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400 flex-shrink-0" />
            <span>API Error: {error}</span>
          </div>
          <button
            onClick={fetchAlerts}
            className="rounded border border-red-500/50 px-2 py-1 hover:bg-red-900/40"
          >
            Retry
          </button>
        </div>
      )}

      {/* Controls & Search */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1 sm:max-w-md">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#64748b]" />
          <input
            type="text"
            placeholder="Search by title, rule, MITRE technique, or detector..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-[#334155] bg-[#0f172a] py-2 pl-9 pr-4 text-xs text-[#f1f5f9] placeholder-[#64748b] transition focus:border-[#22d3ee]"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Severity Filter */}
          <div className="flex items-center gap-2">
            <Filter className="h-3.5 w-3.5 text-[#64748b]" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-lg border border-[#334155] bg-[#0f172a] px-3 py-1.5 text-xs text-[#f1f5f9] transition focus:border-[#22d3ee]"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Decision Filter */}
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            className="rounded-lg border border-[#334155] bg-[#0f172a] px-3 py-1.5 text-xs text-[#f1f5f9] transition focus:border-[#22d3ee]"
          >
            <option value="all">All Decisions</option>
            <option value="alert">Actionable (Alert)</option>
            <option value="review">Review State (Uncertain)</option>
          </select>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="flex h-64 items-center justify-center gap-2 text-xs font-mono text-[#94a3b8]">
            <RefreshCw className="h-5 w-5 animate-spin text-[#22d3ee]" />
            <span>Streaming analytical detections from database...</span>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="flex h-64 flex-col items-center justify-center gap-2 text-xs text-[#94a3b8]">
            <BellRing className="h-8 w-8 text-[#64748b]" />
            <span>No analytical alerts matched current filters.</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#334155] bg-[#030712]/50 font-mono text-[11px] uppercase tracking-wider text-[#64748b]">
                <tr>
                  <th className="py-3 pl-4 pr-3">Alert / Technique</th>
                  <th className="py-3 px-3">Detector</th>
                  <th className="py-3 px-3">Severity</th>
                  <th className="py-3 px-3">Confidence</th>
                  <th className="py-3 px-3">Decision State</th>
                  <th className="py-3 px-3">Entity</th>
                  <th className="py-3 pr-4 text-right">Observed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e293b]">
                {filteredAlerts.map((alt) => {
                  const isExpanded = expandedAlertId === alt.id;
                  const conf =
                    alt.confidence !== undefined && alt.confidence !== null
                      ? alt.confidence
                      : alt.score !== undefined && alt.score !== null
                      ? alt.score
                      : null;
                  const confPct = conf != null ? Math.round(conf * 100) : null;

                  return (
                    <tr key={alt.id} className="group hover:bg-[#1e293b]/50 transition">
                      {/* Alert Info */}
                      <td className="py-3.5 pl-4 pr-3">
                        <div className="flex items-start gap-2">
                          <button
                            onClick={() => toggleExpand(alt.id)}
                            className="mt-0.5 text-[#64748b] hover:text-[#22d3ee]"
                          >
                            {isExpanded ? (
                              <ChevronDown className="h-3.5 w-3.5" />
                            ) : (
                              <ChevronRight className="h-3.5 w-3.5" />
                            )}
                          </button>
                          <div>
                            <div className="font-semibold text-[#f1f5f9] group-hover:text-[#22d3ee] transition">
                              {alt.title}
                            </div>
                            <div className="mt-0.5 flex flex-wrap items-center gap-2 font-mono text-[10px] text-[#64748b]">
                              <span>ID: {alt.id}</span>
                              <span>·</span>
                              <span className="text-purple-300 font-medium">
                                {alt.technique || alt.technique_id || 'T1059'}
                              </span>
                            </div>
                            {isExpanded && (
                              <div className="mt-3 space-y-2 rounded-lg border border-[#334155] bg-[#030712] p-3 text-xs font-mono">
                                <div className="text-[#cbd5e1]">{alt.description}</div>
                                {alt.evidence && (
                                  <div>
                                    <span className="text-[10px] font-bold uppercase text-[#64748b]">
                                      FORENSIC EVIDENCE DETAILS:
                                    </span>
                                    <pre className="mt-1 max-h-40 overflow-auto rounded bg-[#0b0f19] p-2 text-[10px] text-[#22d3ee]">
                                      {JSON.stringify(alt.evidence, null, 2)}
                                    </pre>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Detector */}
                      <td className="py-3.5 px-3 font-mono text-xs">
                        <div className="flex items-center gap-1.5">
                          <Cpu className="h-3.5 w-3.5 text-[#22d3ee]" />
                          <span className="text-[#cbd5e1]">{alt.detector || 'rules-1.2.0'}</span>
                        </div>
                        {alt.detector_version && (
                          <div className="text-[10px] text-[#64748b]">{alt.detector_version}</div>
                        )}
                      </td>

                      {/* Severity */}
                      <td className="py-3.5 px-3">
                        <span
                          className={`rounded px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase ${getSeverityBadge(
                            alt.severity,
                          )}`}
                        >
                          {alt.severity}
                        </span>
                      </td>

                      {/* Calibrated Confidence */}
                      <td className="py-3.5 px-3 font-mono text-xs">
                        {confPct != null ? (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between text-[11px]">
                              <span className="text-[#22d3ee] font-semibold">{confPct}%</span>
                            </div>
                            <div className="h-1.5 w-16 rounded-full bg-[#1e293b] overflow-hidden">
                              <div
                                className={`h-full rounded-full ${
                                  confPct >= 80 ? 'bg-[#22d3ee]' : confPct >= 50 ? 'bg-amber-400' : 'bg-slate-400'
                                }`}
                                style={{ width: `${confPct}%` }}
                              />
                            </div>
                          </div>
                        ) : (
                          <span className="text-[#64748b]">—</span>
                        )}
                      </td>

                      {/* Decision State */}
                      <td className="py-3.5 px-3">
                        {getDecisionBadge(alt.decision)}
                      </td>

                      {/* Entity Association */}
                      <td className="py-3.5 px-3 font-mono text-xs">
                        {alt.entity_id ? (
                          <Link
                            to={`/entities/${alt.entity_id}`}
                            className="inline-flex items-center gap-1 text-[#22d3ee] hover:underline"
                          >
                            <span>{alt.entity_id}</span>
                            <ExternalLink className="h-3 w-3" />
                          </Link>
                        ) : (
                          <span className="text-[#64748b]">Unmapped</span>
                        )}
                      </td>

                      {/* Observed Timestamp */}
                      <td className="py-3.5 pr-4 text-right font-mono text-[11px] text-[#64748b]">
                        {new Date(alt.observed_at).toLocaleString(undefined, {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default AlertsPage;
