import { useState, useEffect } from 'react';
import { incidentsApi, type TimelineItem } from '../../services/api';
import {
  Clock,
  ShieldAlert,
  BellRing,
  Crosshair,
  Activity,
  AlertCircle,
  ChevronRight,
  ChevronDown,
  RefreshCw,
} from 'lucide-react';

interface IncidentTimelineViewProps {
  incidentId: string;
  tenantId?: string;
}

export function IncidentTimelineView({ incidentId, tenantId }: IncidentTimelineViewProps) {
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedIndices, setExpandedIndices] = useState<Record<number, boolean>>({});

  const loadTimeline = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await incidentsApi.getTimeline(incidentId, tenantId);
      setTimeline(res.data.timeline || []);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to load chronological event timeline.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTimeline();
  }, [incidentId, tenantId]);

  const toggleExpand = (idx: number) => {
    setExpandedIndices((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'incident_created':
        return <ShieldAlert className="h-4 w-4 text-purple-400" />;
      case 'alert_triggered':
        return <BellRing className="h-4 w-4 text-amber-400" />;
      case 'attribution_detected':
        return <Crosshair className="h-4 w-4 text-cyan-400" />;
      default:
        return <Activity className="h-4 w-4 text-blue-400" />;
    }
  };

  const getSeverityBadge = (sev?: string | null) => {
    if (!sev) return null;
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-purple-500/20 text-purple-400 border border-purple-500/40';
      case 'high':
        return 'bg-red-500/20 text-red-400 border border-red-500/40';
      case 'medium':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/40';
      case 'low':
        return 'bg-blue-500/20 text-blue-400 border border-blue-500/40';
      default:
        return 'bg-slate-500/20 text-slate-400 border border-slate-500/40';
    }
  };

  if (loading) {
    return (
      <div className="flex h-48 items-center justify-center gap-3 rounded-lg border border-[#334155] bg-[#030712]/50">
        <RefreshCw className="h-5 w-5 animate-spin text-[#22d3ee]" />
        <span className="font-mono text-xs text-[#94a3b8]">Loading forensic timeline stream...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-950/20 p-4 text-xs text-red-300">
        <AlertCircle className="h-4 w-4 flex-shrink-0 text-red-400" />
        <span>{error}</span>
        <button
          onClick={loadTimeline}
          className="ml-auto flex items-center gap-1 rounded border border-red-500/40 px-2 py-1 text-[11px] font-mono hover:bg-red-900/40"
        >
          <RefreshCw className="h-3 w-3" /> Retry
        </button>
      </div>
    );
  }

  if (timeline.length === 0) {
    return (
      <div className="flex h-36 flex-col items-center justify-center gap-1 rounded-lg border border-[#334155] bg-[#030712]/50 text-xs text-[#64748b]">
        <Clock className="h-5 w-5 text-[#475569]" />
        <span>No chronological events recorded for this incident yet.</span>
      </div>
    );
  }

  return (
    <div className="relative space-y-4 py-2">
      <div className="flex items-center justify-between pb-2 border-b border-[#334155]">
        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4 text-[#22d3ee]" />
          <span className="font-mono text-xs font-semibold uppercase tracking-wider text-[#f1f5f9]">
            Event Execution Sequence ({timeline.length} Events)
          </span>
        </div>
        <button
          onClick={loadTimeline}
          className="flex items-center gap-1 text-[11px] font-mono text-[#64748b] hover:text-[#22d3ee] transition"
        >
          <RefreshCw className="h-3 w-3" /> Refresh
        </button>
      </div>

      <div className="relative pl-6 before:absolute before:bottom-2 before:left-[11px] before:top-2 before:w-[2px] before:bg-gradient-to-b before:from-[#22d3ee]/60 before:via-[#334155] before:to-transparent">
        {timeline.map((item, idx) => {
          const isExpanded = !!expandedIndices[idx];
          const hasMetadata = item.metadata && Object.keys(item.metadata).length > 0;
          return (
            <div key={idx} className="relative mb-5 group">
              {/* Timeline Node Dot */}
              <div className="absolute -left-6 top-1.5 flex h-6 w-6 -translate-x-1/2 items-center justify-center rounded-full border border-[#334155] bg-[#0f172a] shadow-[0_0_10px_rgba(34,211,238,0.2)] group-hover:border-[#22d3ee]">
                {getTypeIcon(item.type)}
              </div>

              {/* Event Content Card */}
              <div className="ml-2 rounded-lg border border-[#334155] bg-[#0f172a]/90 p-3 shadow-md transition hover:border-[#22d3ee]/40">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] font-semibold text-[#f1f5f9]">
                      {item.title}
                    </span>
                    {item.severity && (
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono uppercase ${getSeverityBadge(item.severity)}`}>
                        {item.severity}
                      </span>
                    )}
                    <span className="rounded bg-[#1e293b] px-1.5 py-0.5 font-mono text-[10px] text-[#94a3b8]">
                      {item.type}
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-[#64748b]">
                    {new Date(item.timestamp).toLocaleString(undefined, {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })}
                  </div>
                </div>

                {item.description && (
                  <p className="mt-1 text-xs text-[#cbd5e1] leading-relaxed">
                    {item.description}
                  </p>
                )}

                {hasMetadata && (
                  <div className="mt-2 pt-2 border-t border-[#1e293b]">
                    <button
                      onClick={() => toggleExpand(idx)}
                      className="flex items-center gap-1 font-mono text-[10px] text-[#22d3ee] hover:underline"
                    >
                      {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                      <span>{isExpanded ? 'Hide Evidence Metadata' : 'View Evidence Metadata'}</span>
                    </button>
                    {isExpanded && (
                      <pre className="mt-2 max-h-48 overflow-auto rounded bg-[#030712] p-2 font-mono text-[10px] text-[#22d3ee]/90">
                        {JSON.stringify(item.metadata, null, 2)}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
