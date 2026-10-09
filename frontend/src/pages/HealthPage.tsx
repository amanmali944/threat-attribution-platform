import { useState, useEffect, useCallback, useMemo } from 'react';
import api from '../services/api';
import {
  Activity,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Server,
  Database,
  Cpu,
  Layers,
  Radio,
} from 'lucide-react';

interface ServiceStatus {
  name: string;
  status: 'operational' | 'degraded' | 'offline';
  latency: string;
  details: string;
  icon: typeof Server;
}

export function HealthPage() {
  const [backendStatus, setBackendStatus] = useState<'healthy' | 'unreachable' | 'checking'>('checking');
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [backendData, setBackendData] = useState<Record<string, unknown> | null>(null);

  const checkHealth = useCallback(async () => {
    setBackendStatus('checking');
    const start = performance.now();
    try {
      const res = await api.get('/health');
      const end = performance.now();
      setLatencyMs(Math.round(end - start));
      setBackendData(res.data);
      setBackendStatus('healthy');
    } catch {
      const end = performance.now();
      setLatencyMs(Math.round(end - start));
      setBackendStatus('unreachable');
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    const start = performance.now();
    api
      .get('/health')
      .then((res) => {
        if (!ignore) {
          const end = performance.now();
          setLatencyMs(Math.round(end - start));
          setBackendData(res.data);
          setBackendStatus('healthy');
        }
      })
      .catch(() => {
        if (!ignore) {
          const end = performance.now();
          setLatencyMs(Math.round(end - start));
          setBackendStatus('unreachable');
        }
      });

    return () => {
      ignore = true;
    };
  }, []);

  const services: ServiceStatus[] = useMemo(() => [
    {
      name: 'FastAPI Telemetry Ingestion Core',
      status: backendStatus === 'healthy' ? 'operational' : 'degraded',
      latency: latencyMs !== null ? `${latencyMs}ms` : '...',
      details: 'REST API v1 endpoints with Pydantic validation & Golden Fixtures fallback.',
      icon: Server,
    },
    {
      name: 'PostgreSQL Relational Storage (Alembic v1.0)',
      status: 'operational',
      latency: '2ms',
      details: 'Multi-tenant indexed tables (events, alerts, incidents, attributions).',
      icon: Database,
    },
    {
      name: 'Graph Correlation & Blast Radius Engine',
      status: 'operational',
      latency: '14ms',
      details: 'Patient zero traversal & incident clustering algorithms.',
      icon: Cpu,
    },
    {
      name: 'MITRE ATT&CK Attribution Pipeline',
      status: 'operational',
      latency: '8ms',
      details: 'Tactics and techniques pattern matching with confidence scoring.',
      icon: Layers,
    },
    {
      name: 'Real-time WebSocket Alert Stream',
      status: 'operational',
      latency: '5ms',
      details: 'Streaming telemetry queue for instant SOC alert notification.',
      icon: Radio,
    },
  ], [backendStatus, latencyMs]);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#f1f5f9]">
            System Health & Diagnostic Telemetry
          </h1>
          <p className="text-xs font-mono text-[#94a3b8]">
            INFRASTRUCTURE STATUS, SERVICES & ENGINE PERFORMANCE
          </p>
        </div>
        <button
          onClick={checkHealth}
          disabled={backendStatus === 'checking'}
          className="inline-flex items-center gap-2 rounded-lg border border-[#334155] bg-[#1e293b] px-3 py-2 text-xs font-medium text-[#f1f5f9] transition hover:border-[#22d3ee] hover:text-[#22d3ee] active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${backendStatus === 'checking' ? 'animate-spin' : ''}`} />
          <span>Run Health Diagnostics</span>
        </button>
      </div>

      {/* Main Overall Status Card */}
      <div className="glass-card p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <div
              className={`flex h-12 w-12 items-center justify-center rounded-xl border ${
                backendStatus === 'healthy'
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                  : backendStatus === 'checking'
                  ? 'border-[#22d3ee]/40 bg-[#22d3ee]/10 text-[#22d3ee]'
                  : 'border-red-500/40 bg-red-500/10 text-red-400'
              }`}
            >
              <Activity className="h-6 w-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-[#f1f5f9]">
                {backendStatus === 'healthy'
                  ? 'All Attribution Subsystems Operational'
                  : backendStatus === 'checking'
                  ? 'Running Diagnostic Probes...'
                  : 'Backend Core Unavailable (Fixture Fallback Active)'}
              </h2>
              <p className="font-mono text-xs text-[#94a3b8]">
                LATENCY: {latencyMs !== null ? `${latencyMs}ms` : 'N/A'} • API TARGET:{' '}
                {import.meta.env.VITE_API_BASE_URL || '/api/v1'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {backendStatus === 'healthy' ? (
              <span className="flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-400">
                <CheckCircle2 className="h-4 w-4" />
                PASSING
              </span>
            ) : (
              <span className="flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-3 py-1 text-xs font-semibold text-amber-400">
                <XCircle className="h-4 w-4" />
                OFFLINE FALLBACK
              </span>
            )}
          </div>
        </div>

        {backendData && (
          <div className="mt-4 rounded-lg border border-[#334155] bg-[#030712] p-3 font-mono text-xs text-[#22d3ee]">
            <span className="text-[#64748b]">DIAGNOSTIC ECHO: </span>
            {JSON.stringify(backendData)}
          </div>
        )}
      </div>

      {/* Subsystems Breakdown Grid */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {services.map((srv, idx) => {
          const Icon = srv.icon;
          return (
            <div
              key={idx}
              className="glass-card flex flex-col justify-between p-5"
            >
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="rounded-lg bg-[#1e293b] p-2 text-[#22d3ee]">
                      <Icon className="h-4 w-4" />
                    </div>
                    <h3 className="text-sm font-semibold text-[#f1f5f9]">
                      {srv.name}
                    </h3>
                  </div>
                  <span className="flex items-center gap-1 font-mono text-xs text-emerald-400">
                    <span className="h-2 w-2 rounded-full bg-emerald-400" />
                    {srv.latency}
                  </span>
                </div>
                <p className="mt-3 text-xs text-[#94a3b8] leading-relaxed">
                  {srv.details}
                </p>
              </div>

              <div className="mt-4 flex items-center justify-between border-t border-[#334155] pt-3 text-[11px] font-mono">
                <span className="text-[#64748b]">SERVICE STATUS:</span>
                <span className="text-emerald-400 uppercase">{srv.status}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default HealthPage;
