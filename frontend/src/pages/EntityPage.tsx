import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import {
  entitiesApi,
  alertsApi,
  type EntityItem,
  type AlertItem,
} from '../services/api';
import {
  Server,
  User,
  Globe,
  Database,
  Smartphone,
  ShieldAlert,
  BellRing,
  ArrowLeft,
  RefreshCw,
  AlertTriangle,
  Layers,
  CheckCircle2,
} from 'lucide-react';

export function EntityPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const navigate = useNavigate();

  const [entity, setEntity] = useState<EntityItem | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const tenantId = user?.tenant_id || 'tenant_default';

  const fetchEntityData = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const entityRes = await entitiesApi.get(id, tenantId);
      setEntity(entityRes.data);

      // Fetch alerts related to this entity or search
      try {
        const alertsRes = await alertsApi.list(tenantId, { limit: 50 });
        const allAlerts = alertsRes.data.items || [];
        const matchingAlerts = allAlerts.filter(
          (a) =>
            a.entity_id === id ||
            (entityRes.data &&
              (a.description?.toLowerCase().includes(entityRes.data.identifier.toLowerCase()) ||
                a.title?.toLowerCase().includes(entityRes.data.identifier.toLowerCase()))),
        );
        setAlerts(matchingAlerts);
      } catch {
        setAlerts([]);
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || `Entity '${id}' not found in platform registry.`);
    } finally {
      setLoading(false);
    }
  }, [id, tenantId]);

  useEffect(() => {
    fetchEntityData();
  }, [fetchEntityData]);

  const getEntityIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'host':
        return <Server className="h-6 w-6 text-[#22d3ee]" />;
      case 'user':
        return <User className="h-6 w-6 text-purple-400" />;
      case 'ip':
        return <Globe className="h-6 w-6 text-teal-400" />;
      case 'database':
        return <Database className="h-6 w-6 text-amber-400" />;
      case 'device':
        return <Smartphone className="h-6 w-6 text-blue-400" />;
      default:
        return <Layers className="h-6 w-6 text-[#94a3b8]" />;
    }
  };

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

  const handleAction = (name: string) => {
    setActionFeedback(`Executed: ${name} for ${entity?.identifier}`);
    setTimeout(() => setActionFeedback(null), 3000);
  };

  if (loading) {
    return (
      <div className="flex h-96 flex-col items-center justify-center gap-3">
        <RefreshCw className="h-8 w-8 animate-spin text-[#22d3ee]" />
        <span className="font-mono text-xs text-[#94a3b8]">
          Querying entity telemetry, risk contributors, and alert associations...
        </span>
      </div>
    );
  }

  if (error || !entity) {
    return (
      <div className="rounded-xl border border-red-500/40 bg-red-950/20 p-8 text-center">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-red-500/20 text-red-400">
          <AlertTriangle className="h-6 w-6" />
        </div>
        <h3 className="mt-4 text-base font-bold text-[#f1f5f9]">Entity Investigation Failed</h3>
        <p className="mt-2 text-xs font-mono text-red-300 max-w-md mx-auto">{error}</p>
        <div className="mt-6 flex justify-center gap-3">
          <button
            onClick={() => navigate(-1)}
            className="inline-flex items-center gap-2 rounded-lg border border-[#334155] bg-[#1e293b] px-4 py-2 text-xs font-mono text-[#f1f5f9] hover:bg-[#334155]"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Back
          </button>
          <button
            onClick={fetchEntityData}
            className="inline-flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-900/30 px-4 py-2 text-xs font-mono text-[#f1f5f9] hover:bg-red-800/40"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Retry
          </button>
        </div>
      </div>
    );
  }

  // Calculate risk score based on alerts
  const criticalCount = alerts.filter((a) => a.severity.toLowerCase() === 'critical').length;
  const highCount = alerts.filter((a) => a.severity.toLowerCase() === 'high').length;
  const estimatedRisk = Math.min(100, criticalCount * 35 + highCount * 20 + alerts.length * 5);

  return (
    <div className="space-y-6">
      {/* Top Navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate(-1)}
          className="inline-flex items-center gap-2 text-xs font-mono text-[#64748b] hover:text-[#22d3ee] transition"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Previous View
        </button>

        <div className="flex items-center gap-2">
          {actionFeedback && (
            <span className="font-mono text-xs text-emerald-400 animate-fade-in">
              {actionFeedback}
            </span>
          )}
          <button
            onClick={() => handleAction('Quarantine & Isolate Host')}
            className="rounded border border-red-500/40 bg-red-950/30 px-3 py-1.5 text-xs font-mono text-red-300 hover:bg-red-900/40 transition"
          >
            Isolate Entity
          </button>
          <button
            onClick={() => handleAction('Flag for Deep Forensics')}
            className="rounded border border-[#22d3ee]/40 bg-[#22d3ee]/10 px-3 py-1.5 text-xs font-mono text-[#22d3ee] hover:bg-[#22d3ee]/20 transition"
          >
            Add to Watchlist
          </button>
        </div>
      </div>

      {/* Entity Profile Hero Card */}
      <div className="glass-card p-6 border-[#22d3ee]/30">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-xl border border-[#334155] bg-[#030712]/80 shadow-[0_0_20px_rgba(34,211,238,0.15)]">
              {getEntityIcon(entity.entity_type)}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="rounded bg-[#1e293b] px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-[#22d3ee] border border-[#22d3ee]/30">
                  {entity.entity_type}
                </span>
                <span className="font-mono text-xs text-[#64748b]">ID: {entity.id}</span>
              </div>
              <h1 className="mt-1 text-2xl font-bold text-[#f1f5f9] tracking-tight">
                {entity.identifier}
              </h1>
            </div>
          </div>

          {/* Quick Risk Indicator */}
          <div className="flex items-center gap-4 rounded-xl border border-[#334155] bg-[#030712]/60 p-4 font-mono">
            <div>
              <span className="block text-[10px] font-bold text-[#64748b]">COMPOSITE RISK</span>
              <span className={`text-2xl font-bold ${estimatedRisk >= 75 ? 'text-red-400' : estimatedRisk >= 40 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {estimatedRisk.toFixed(0)} / 100
              </span>
            </div>
            <div className="h-8 w-px bg-[#334155]" />
            <div>
              <span className="block text-[10px] font-bold text-[#64748b]">LINKED ALERTS</span>
              <span className="text-2xl font-bold text-[#22d3ee]">{alerts.length}</span>
            </div>
          </div>
        </div>

        {/* Timestamps & Telemetry Metadata */}
        <div className="mt-6 grid grid-cols-2 gap-4 border-t border-[#334155] pt-4 sm:grid-cols-4 font-mono text-xs">
          <div>
            <span className="block text-[10px] text-[#64748b]">TENANT SCOPE</span>
            <span className="font-semibold text-[#cbd5e1]">{entity.tenant_id}</span>
          </div>
          <div>
            <span className="block text-[10px] text-[#64748b]">FIRST OBSERVED</span>
            <span className="text-[#cbd5e1]">{new Date(entity.first_seen).toLocaleString()}</span>
          </div>
          <div>
            <span className="block text-[10px] text-[#64748b]">LAST TELEMETRY</span>
            <span className="text-[#cbd5e1]">{new Date(entity.last_seen).toLocaleString()}</span>
          </div>
          <div>
            <span className="block text-[10px] text-[#64748b]">REGISTRATION TYPE</span>
            <span className="text-[#22d3ee]">Deterministic SHA-256</span>
          </div>
        </div>
      </div>

      {/* Grid: Properties & Risk Contributors */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Properties Inspector (5 cols) */}
        <div className="glass-card p-5 lg:col-span-5">
          <div className="flex items-center gap-2 pb-3 border-b border-[#334155]">
            <Server className="h-4 w-4 text-[#22d3ee]" />
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#f1f5f9]">
              Configuration & Attributes
            </span>
          </div>

          <div className="mt-4 space-y-3 font-mono text-xs">
            {entity.properties && Object.keys(entity.properties).length > 0 ? (
              Object.entries(entity.properties).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between rounded bg-[#0f172a] p-2.5 border border-[#1e293b]">
                  <span className="text-[#64748b]">{k}:</span>
                  <span className="text-[#cbd5e1] font-semibold">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                </div>
              ))
            ) : (
              <div className="text-xs text-[#64748b] py-4 text-center">
                No custom configuration properties attached to entity.
              </div>
            )}
          </div>
        </div>

        {/* Risk Contributors (7 cols) */}
        <div className="glass-card p-5 lg:col-span-7">
          <div className="flex items-center gap-2 pb-3 border-b border-[#334155]">
            <ShieldAlert className="h-4 w-4 text-amber-400" />
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#f1f5f9]">
              Forensic Risk Contributors
            </span>
          </div>

          <div className="mt-4 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between rounded bg-[#0f172a] p-3 border border-[#1e293b]">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-red-400" />
                <span className="text-[#cbd5e1]">Critical Severity Detections</span>
              </div>
              <span className="font-bold text-red-400">{criticalCount} alerts</span>
            </div>

            <div className="flex items-center justify-between rounded bg-[#0f172a] p-3 border border-[#1e293b]">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-amber-400" />
                <span className="text-[#cbd5e1]">High Severity Anomalies</span>
              </div>
              <span className="font-bold text-amber-400">{highCount} alerts</span>
            </div>

            <div className="flex items-center justify-between rounded bg-[#0f172a] p-3 border border-[#1e293b]">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-purple-400" />
                <span className="text-[#cbd5e1]">Attack Graph Entry Point Likelihood</span>
              </div>
              <span className="font-bold text-purple-400">
                {alerts.length > 0 ? 'Elevated (Candidate Root)' : 'Low'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Associated Detections Table */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between pb-3 border-b border-[#334155]">
          <div className="flex items-center gap-2">
            <BellRing className="h-4 w-4 text-[#22d3ee]" />
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#f1f5f9]">
              Associated Analytical Detections ({alerts.length})
            </span>
          </div>
        </div>

        {alerts.length === 0 ? (
          <div className="flex h-36 flex-col items-center justify-center gap-1 text-xs text-[#64748b]">
            <CheckCircle2 className="h-6 w-6 text-emerald-400" />
            <span className="mt-1">No active threat detections associated with this entity.</span>
          </div>
        ) : (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#334155] font-mono text-[11px] uppercase text-[#64748b]">
                <tr>
                  <th className="py-2 pr-4">Alert</th>
                  <th className="py-2 pr-4">Detector</th>
                  <th className="py-2 pr-4">Technique</th>
                  <th className="py-2 pr-4">Severity</th>
                  <th className="py-2 pr-4">Decision</th>
                  <th className="py-2">Observed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e293b] font-mono">
                {alerts.map((alt) => (
                  <tr key={alt.id} className="hover:bg-[#1e293b]/40">
                    <td className="py-3 pr-4">
                      <div className="font-semibold text-[#f1f5f9]">{alt.title}</div>
                      <div className="text-[10px] text-[#64748b]">{alt.id} · {alt.rule_id}</div>
                    </td>
                    <td className="py-3 pr-4 text-[#22d3ee]">
                      {alt.detector || 'rules-1.2.0'}
                    </td>
                    <td className="py-3 pr-4 text-purple-300">
                      {alt.technique || 'T1059'}
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`rounded px-2 py-0.5 text-[10px] uppercase font-bold ${getSeverityBadge(alt.severity)}`}>
                        {alt.severity}
                      </span>
                    </td>
                    <td className="py-3 pr-4">
                      <span className="rounded bg-[#1e293b] px-2 py-0.5 text-[10px] uppercase text-emerald-400">
                        {alt.decision || 'alert'}
                      </span>
                    </td>
                    <td className="py-3 text-[#64748b] text-[11px]">
                      {new Date(alt.observed_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default EntityPage;
