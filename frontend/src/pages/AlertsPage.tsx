import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/useAuth';
import { alertsApi, type AlertItem } from '../services/api';
import {
  Search,
  RefreshCw,
  ChevronDown,
  ChevronRight,
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
    const isCritical = sev.toLowerCase() === 'critical' || sev.toLowerCase() === 'high';
    return (
      <span
        className={`px-2 py-0.5 font-jb text-[10px] font-bold uppercase ${
          isCritical
            ? 'border border-[#c81b1c] bg-[#1a0505] text-[#c81b1c]'
            : 'border border-[#282828] bg-[#0d0d0d] text-[#949494]'
        }`}
      >
        {sev}
      </span>
    );
  };

  const getDecisionBadge = (decision?: string | null) => {
    if (!decision) return null;
    const isAlert = decision.toLowerCase() === 'alert';
    return (
      <span
        className={`px-2 py-0.5 font-jb text-[10px] font-bold uppercase ${
          isAlert
            ? 'border border-[#c81b1c] bg-[#c81b1c] text-white'
            : 'border border-[#444444] bg-[#141414] text-[#949494]'
        }`}
      >
        {decision}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border border-[#1f1f1f] bg-black/90 p-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-sg text-xl md:text-2xl font-bold uppercase tracking-wider text-white">
              Analytical Detections Stream
            </h1>
            <span className="border border-[#c81b1c] bg-[#1a0505] px-2 py-0.5 font-jb text-[10px] font-bold uppercase text-[#c81b1c]">
              {alerts.length} TRIGGERS
            </span>
          </div>
          <p className="mt-1 font-jb text-xs text-[#949494]">
            FUSED ANOMALY OUTPUTS & DETERMINISTIC SECURITY RULE HITS
          </p>
        </div>

        <button onClick={fetchAlerts} className="btn btn-outline btn-sm font-jb">
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Sync Detections</span>
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="border border-[#c81b1c] bg-[#1a0505] p-3 font-jb text-xs text-[#c81b1c]">
          {error}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="border border-[#1f1f1f] bg-black/90 p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-[#949494]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by rule, technique ID, detector module, or description..."
              className="w-full pl-9 pr-3 py-1.5 text-xs bg-black border border-[#222222] text-white placeholder-[#666666]"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 font-jb text-xs">
            <span className="text-[#949494] text-[10px] uppercase font-sg">Severity:</span>
            {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-1 uppercase tracking-wider border text-[10px] ${
                  severityFilter === sev
                    ? 'border-[#c81b1c] bg-[#c81b1c] text-white font-bold'
                    : 'border-[#222222] bg-[#0c0c0c] text-[#949494] hover:text-white'
                }`}
              >
                {sev}
              </button>
            ))}

            <span className="text-[#949494] text-[10px] uppercase font-sg ml-2">Decision:</span>
            {['all', 'alert', 'review'].map((dec) => (
              <button
                key={dec}
                onClick={() => setDecisionFilter(dec)}
                className={`px-2 py-1 uppercase tracking-wider border text-[10px] ${
                  decisionFilter === dec
                    ? 'border-[#c81b1c] bg-[#c81b1c] text-white font-bold'
                    : 'border-[#222222] bg-[#0c0c0c] text-[#949494] hover:text-white'
                }`}
              >
                {dec}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Detections List */}
      <div className="space-y-2">
        {loading ? (
          <div className="flex items-center justify-center p-12 border border-[#1f1f1f] bg-black/90 font-jb text-xs text-[#949494]">
            <RefreshCw className="h-5 w-5 animate-spin text-[#c81b1c] mr-2" />
            Querying Telemetry Detectors...
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="border border-[#1f1f1f] bg-black/90 p-12 text-center font-jb text-xs text-[#949494]">
            No detection alerts matching criteria.
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const isExpanded = expandedAlertId === alert.id;
            return (
              <div
                key={alert.id}
                className="border border-[#1f1f1f] bg-black/90 p-4 transition hover:border-[#333333]"
              >
                <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 font-jb text-[10px]">
                      <span className="text-[#949494] uppercase">RULE: {alert.rule_id}</span>
                      {getSeverityBadge(alert.severity)}
                      {getDecisionBadge(alert.decision)}
                      {alert.detector && (
                        <span className="border border-[#222222] bg-[#0c0c0c] px-1.5 py-0.5 text-[#949494] uppercase">
                          {alert.detector}
                        </span>
                      )}
                    </div>

                    <h3 className="font-sg text-sm font-bold text-white uppercase tracking-wide">
                      {alert.title}
                    </h3>

                    <p className="font-jb text-xs text-[#949494] leading-relaxed max-w-3xl">
                      {alert.description}
                    </p>
                  </div>

                  <div className="flex sm:flex-col items-end justify-between font-jb text-[10px] text-[#949494] flex-shrink-0">
                    <span>{new Date(alert.observed_at).toLocaleString()}</span>
                    {alert.confidence !== undefined && alert.confidence !== null && (
                      <span className="text-white mt-1">
                        CONFIDENCE: <strong className="text-[#c81b1c]">{(alert.confidence * 100).toFixed(0)}%</strong>
                      </span>
                    )}
                  </div>
                </div>

                {/* Structured Evidence Toggle */}
                {alert.evidence && (
                  <div className="mt-3 border-t border-[#141414] pt-2">
                    <button
                      onClick={() => setExpandedAlertId(isExpanded ? null : alert.id)}
                      className="flex items-center gap-1 font-jb text-[10px] text-[#949494] hover:text-white"
                    >
                      {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                      <span>{isExpanded ? 'Hide Raw Telemetry Evidence' : 'Inspect Raw Telemetry Evidence'}</span>
                    </button>

                    {isExpanded && (
                      <pre className="mt-2 border border-[#1a1a1a] bg-[#050505] p-3 font-jb text-[10px] text-[#949494] overflow-x-auto">
                        {JSON.stringify(alert.evidence, null, 2)}
                      </pre>
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

export default AlertsPage;
