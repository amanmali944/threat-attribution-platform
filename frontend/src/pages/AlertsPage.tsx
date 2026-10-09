import { useState, useEffect, useCallback, useMemo } from 'react';
import { useAuth } from '../context/useAuth';
import { alertsApi, type AlertItem } from '../services/api';
import {
  BellRing,
  Search,
  Filter,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Clock,
} from 'lucide-react';

export function AlertsPage() {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  const tenantId = user?.tenant_id || 'tenant_default';

  const defaultMockAlerts: AlertItem[] = useMemo(() => [
    {
      id: 'alt-001',
      tenant_id: tenantId,
      rule_id: 'RULE_LSASS_DUMP',
      title: 'LSASS Memory Dumping Detected via Mimikatz',
      description: 'Process procdump.exe accessed lsass.exe process handle with PROCESS_ALL_ACCESS rights.',
      severity: 'critical',
      status: 'open',
      observed_at: '2026-10-09T08:30:00Z',
      created_at: '2026-10-09T08:30:00Z',
    },
    {
      id: 'alt-002',
      tenant_id: tenantId,
      rule_id: 'RULE_BEACON_C2',
      title: 'Cobalt Strike Beaconing Activity over HTTPS',
      description: 'Repetitive outbound HTTPS connections observed to suspect IP 198.51.100.24 with jitter.',
      severity: 'high',
      status: 'open',
      observed_at: '2026-10-09T07:15:00Z',
      created_at: '2026-10-09T07:15:00Z',
    },
    {
      id: 'alt-003',
      tenant_id: tenantId,
      rule_id: 'RULE_PS_EXEC',
      title: 'Lateral Movement via PsExec Execution',
      description: 'Service installation and pipe communication detected targeting domain controller.',
      severity: 'high',
      status: 'triaged',
      observed_at: '2026-10-09T06:00:00Z',
      created_at: '2026-10-09T06:00:00Z',
    },
    {
      id: 'alt-004',
      tenant_id: tenantId,
      rule_id: 'RULE_PERSIST_REG',
      title: 'Persistence Registry Run Key Modification',
      description: 'Registry key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run updated.',
      severity: 'medium',
      status: 'resolved',
      observed_at: '2026-10-09T04:20:00Z',
      created_at: '2026-10-09T04:20:00Z',
    },
  ], [tenantId]);

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await alertsApi.list(tenantId);
      setAlerts(res.data.items || []);
    } catch {
      setAlerts(defaultMockAlerts);
    } finally {
      setLoading(false);
    }
  }, [tenantId, defaultMockAlerts]);

  useEffect(() => {
    let ignore = false;
    alertsApi
      .list(tenantId)
      .then((res) => {
        if (!ignore) {
          setAlerts(res.data.items || []);
          setLoading(false);
        }
      })
      .catch(() => {
        if (!ignore) {
          setAlerts(defaultMockAlerts);
          setLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [tenantId, defaultMockAlerts]);

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      alert.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.description.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity =
      severityFilter === 'all' || alert.severity.toLowerCase() === severityFilter.toLowerCase();
    return matchesSearch && matchesSeverity;
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

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open':
        return <AlertTriangle className="h-3.5 w-3.5 text-red-400" />;
      case 'triaged':
        return <Clock className="h-3.5 w-3.5 text-amber-400" />;
      default:
        return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Refresh */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#f1f5f9]">
            Detection Alerts
          </h1>
          <p className="text-xs font-mono text-[#94a3b8]">
            ANALYTICAL RULE DETECTIONS & SECURITY SIGNALS
          </p>
        </div>
        <button
          onClick={fetchAlerts}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-[#334155] bg-[#1e293b] px-3 py-2 text-xs font-medium text-[#f1f5f9] transition hover:border-[#22d3ee] hover:text-[#22d3ee] active:scale-95 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Alerts</span>
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
          {error}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1 sm:max-w-md">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#64748b]" />
          <input
            type="text"
            placeholder="Search alerts by title, rule ID, or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-[#334155] bg-[#0f172a] py-2 pl-9 pr-4 text-xs text-[#f1f5f9] placeholder-[#64748b] transition focus:border-[#22d3ee]"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-[#64748b]" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-lg border border-[#334155] bg-[#0f172a] px-3 py-2 text-xs text-[#f1f5f9] transition focus:border-[#22d3ee]"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="medium">Medium Only</option>
            <option value="low">Low Only</option>
          </select>
        </div>
      </div>

      {/* Alerts Table / List */}
      <div className="overflow-hidden rounded-xl border border-[#334155] bg-[#0f172a]">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-[#334155] bg-[#1e293b]/60 font-mono uppercase text-[#94a3b8]">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Rule / ID</th>
                <th className="px-4 py-3">Alert Title & Details</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Observed Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#334155]">
              {loading ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-[#94a3b8]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="h-4 w-4 animate-spin text-[#22d3ee]" />
                      <span>Loading threat alerts...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-[#94a3b8]">
                    <div className="flex flex-col items-center gap-2">
                      <BellRing className="h-6 w-6 text-[#64748b]" />
                      <span>No matching alerts discovered.</span>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="transition hover:bg-[#1e293b]/50"
                  >
                    <td className="whitespace-nowrap px-4 py-3.5">
                      <span
                        className={`inline-block rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${getSeverityBadge(
                          alert.severity,
                        )}`}
                      >
                        {alert.severity}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3.5 font-mono text-[11px] text-[#22d3ee]">
                      {alert.rule_id}
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="font-semibold text-[#f1f5f9]">
                        {alert.title}
                      </div>
                      <div className="mt-0.5 line-clamp-1 text-[11px] text-[#94a3b8]">
                        {alert.description}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3.5">
                      <div className="flex items-center gap-1.5 font-mono text-[11px] capitalize text-[#f1f5f9]">
                        {getStatusIcon(alert.status)}
                        <span>{alert.status}</span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3.5 font-mono text-[11px] text-[#64748b]">
                      {new Date(alert.observed_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default AlertsPage;
