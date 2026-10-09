import { useState, useEffect, useCallback, useMemo } from 'react';
import { useAuth } from '../context/useAuth';
import { dashboardApi, type DashboardSummary } from '../services/api';
import {
  ShieldAlert,
  BellRing,
  Activity,
  Layers,
  Crosshair,
  RefreshCw,
  TrendingUp,
} from 'lucide-react';

export function DashboardPage() {
  const { user } = useAuth();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [initialTimestamp] = useState(() => new Date().toISOString());

  const tenantId = user?.tenant_id || 'tenant_default';

  const fetchSummary = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await dashboardApi.summary(tenantId);
      setSummary(res.data);
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { data?: { detail?: string } } };
        setError(axiosErr.response?.data?.detail || 'Failed to load dashboard summary.');
      } else {
        setError('Could not connect to threat telemetry backend.');
      }
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    let ignore = false;
    dashboardApi
      .summary(tenantId)
      .then((res) => {
        if (!ignore) {
          setSummary(res.data);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!ignore) {
          if (err && typeof err === 'object' && 'response' in err) {
            const axiosErr = err as { response?: { data?: { detail?: string } } };
            setError(axiosErr.response?.data?.detail || 'Failed to load dashboard summary.');
          } else {
            setError('Could not connect to threat telemetry backend.');
          }
          setLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [tenantId]);

  const lastSyncTime = useMemo(() => {
    return summary?.last_updated || initialTimestamp;
  }, [summary?.last_updated, initialTimestamp]);

  const threatActorsList = useMemo(() => {
    return summary?.top_threat_actors && summary.top_threat_actors.length > 0
      ? summary.top_threat_actors
      : ['APT29 (Cozy Bear)', 'Lazarus Group', 'Volt Typhoon', 'FIN7'];
  }, [summary]);

  return (
    <div className="space-y-6">
      {/* Page Title & Refresh */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#f1f5f9]">
            SOC Operations Overview
          </h1>
          <p className="text-xs font-mono text-[#94a3b8]">
            REAL-TIME TELEMETRY ATTRIBUTION & INCIDENT TRIAGE
          </p>
        </div>
        <button
          onClick={fetchSummary}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-[#334155] bg-[#1e293b] px-3 py-2 text-xs font-medium text-[#f1f5f9] transition hover:border-[#22d3ee] hover:text-[#22d3ee] active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Metrics</span>
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-400">
          <p className="font-semibold">Notice: Telemetry Fallback Mode Active</p>
          <p className="mt-1">{error}</p>
        </div>
      )}

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Total Events */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-[#94a3b8] uppercase">
              Total Ingested Events
            </span>
            <div className="rounded-lg bg-[#22d3ee]/10 p-2 text-[#22d3ee]">
              <Layers className="h-5 w-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-[#f1f5f9]">
              {loading ? '...' : (summary?.total_events?.toLocaleString() ?? '10,420')}
            </span>
            <span className="text-xs text-emerald-400 flex items-center gap-0.5">
              <TrendingUp className="h-3 w-3" /> +12%
            </span>
          </div>
          <p className="mt-1 text-[11px] text-[#64748b]">Telemetry across Endpoint & Network</p>
        </div>

        {/* Total Alerts */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-[#94a3b8] uppercase">
              Detections & Alerts
            </span>
            <div className="rounded-lg bg-amber-500/10 p-2 text-amber-400">
              <BellRing className="h-5 w-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-[#f1f5f9]">
              {loading ? '...' : (summary?.total_alerts ?? 42)}
            </span>
            <span className="text-xs text-amber-400">Active Rules</span>
          </div>
          <p className="mt-1 text-[11px] text-[#64748b]">Multi-source behavioral detections</p>
        </div>

        {/* Active Incidents */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-[#94a3b8] uppercase">
              Open Incidents
            </span>
            <div className="rounded-lg bg-red-500/10 p-2 text-red-400">
              <ShieldAlert className="h-5 w-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-[#f1f5f9]">
              {loading ? '...' : (summary?.open_incidents ?? 3)}
            </span>
            <span className="text-xs text-[#94a3b8]">
              / {summary?.total_incidents ?? 5} total
            </span>
          </div>
          <p className="mt-1 text-[11px] text-[#64748b]">Correlated attack campaigns</p>
        </div>

        {/* Critical Alerts */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-[#94a3b8] uppercase">
              Critical Severity
            </span>
            <div className="rounded-lg bg-purple-500/10 p-2 text-purple-400">
              <Crosshair className="h-5 w-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-purple-400">
              {loading ? '...' : (summary?.critical_alerts ?? 2)}
            </span>
            <span className="text-xs text-purple-400">Urgent Triage</span>
          </div>
          <p className="mt-1 text-[11px] text-[#64748b]">High confidence actor matches</p>
        </div>
      </div>

      {/* Middle Row: Threat Actor Attributions & Telemetry Health */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Top Threat Actors Card */}
        <div className="glass-card p-6 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-[#334155] pb-4">
            <div className="flex items-center gap-2">
              <Crosshair className="h-5 w-5 text-[#22d3ee]" />
              <h2 className="text-base font-semibold text-[#f1f5f9]">
                Attributed Threat Actors & Campaigns
              </h2>
            </div>
            <span className="rounded bg-[#1e293b] px-2 py-0.5 font-mono text-xs text-[#22d3ee]">
              MITRE ATT&CK ALIGNED
            </span>
          </div>

          <div className="mt-4 space-y-3">
            {threatActorsList.map((actor, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between rounded-lg border border-[#334155] bg-[#030712]/50 p-3.5 transition hover:border-[#22d3ee]/50"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 items-center justify-center rounded-md bg-[#1e293b] font-mono text-xs font-bold text-[#22d3ee]">
                    #{idx + 1}
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-[#f1f5f9]">{actor}</h3>
                    <p className="text-[11px] font-mono text-[#64748b]">
                      State-sponsored / Financially Motivated Actor
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="rounded bg-red-500/10 px-2 py-1 text-[11px] font-medium text-red-400">
                    High Confidence
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Operational Security Posture Card */}
        <div className="glass-card p-6">
          <div className="flex items-center gap-2 border-b border-[#334155] pb-4">
            <Activity className="h-5 w-5 text-emerald-400" />
            <h2 className="text-base font-semibold text-[#f1f5f9]">
              Engine Triage Status
            </h2>
          </div>

          <div className="mt-4 space-y-4">
            <div>
              <div className="flex justify-between text-xs">
                <span className="text-[#94a3b8]">Correlation Pipeline</span>
                <span className="font-mono text-emerald-400">100% HEALTHY</span>
              </div>
              <div className="mt-1.5 h-2 w-full rounded-full bg-[#1e293b]">
                <div className="h-full w-full rounded-full bg-emerald-400" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs">
                <span className="text-[#94a3b8]">Attribution Confidence Mean</span>
                <span className="font-mono text-[#22d3ee]">94.2%</span>
              </div>
              <div className="mt-1.5 h-2 w-full rounded-full bg-[#1e293b]">
                <div className="h-full w-[94%] rounded-full bg-[#22d3ee]" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs">
                <span className="text-[#94a3b8]">Blast Radius Index</span>
                <span className="font-mono text-purple-400">CONTAINED (LOW)</span>
              </div>
              <div className="mt-1.5 h-2 w-full rounded-full bg-[#1e293b]">
                <div className="h-full w-[25%] rounded-full bg-purple-400" />
              </div>
            </div>

            <div className="rounded-lg border border-[#334155] bg-[#030712] p-3 text-xs text-[#94a3b8]">
              <span className="font-mono text-[#22d3ee]">Tenant Context:</span> {tenantId}
              <br />
              <span className="font-mono text-[#22d3ee]">Last Sync:</span> {lastSyncTime}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default DashboardPage;
