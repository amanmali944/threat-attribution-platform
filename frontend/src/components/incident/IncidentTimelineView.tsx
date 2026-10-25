import { useState, useEffect, useCallback } from 'react';
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

  const loadTimeline = useCallback(async () => {
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
  }, [incidentId, tenantId]);

  useEffect(() => {
    loadTimeline();
  }, [loadTimeline]);

  const toggleExpand = (idx: number) => {
    setExpandedIndices((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'incident_created':
        return <ShieldAlert className="h-4 w-4 text-[#c81b1c]" />;
      case 'alert_triggered':
        return <BellRing className="h-4 w-4 text-white" />;
      case 'attribution_detected':
        return <Crosshair className="h-4 w-4 text-[#c81b1c]" />;
      default:
        return <Activity className="h-4 w-4 text-[#949494]" />;
    }
  };

  const getSeverityBadge = (sev?: string | null) => {
    if (!sev) return null;
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

  if (loading) {
    return (
      <div className="flex h-48 items-center justify-center gap-3 border border-[#1f1f1f] bg-black/90">
        <RefreshCw className="h-5 w-5 animate-spin text-[#c81b1c]" />
        <span className="font-jb text-xs text-[#949494] uppercase tracking-wider">
          Streaming chronological telemetry...
        </span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-between border border-[#c81b1c] bg-[#160404] p-4 font-jb text-xs text-[#c81b1c]">
        <div className="flex items-center gap-2">
          <AlertCircle className="h-4 w-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
        <button
          onClick={loadTimeline}
          className="btn btn-outline btn-sm"
        >
          Retry
        </button>
      </div>
    );
  }

  if (timeline.length === 0) {
    return (
      <div className="border border-[#1f1f1f] bg-black/90 p-8 text-center font-jb text-xs text-[#949494]">
        No chronological timeline events recorded for this incident case.
      </div>
    );
  }

  return (
    <div className="border border-[#222222] bg-[#0c0c0c] p-6">
      <div className="mb-6 flex items-center justify-between border-b border-[#222222] pb-4">
        <div className="flex items-center gap-2.5 font-sg text-sm font-bold uppercase tracking-wider text-white">
          <Clock className="h-5 w-5 text-[#c81b1c]" />
          <span>Forensic Sequence ({timeline.length} Steps)</span>
        </div>
        <button
          onClick={loadTimeline}
          className="btn btn-outline btn-sm font-sg"
          title="Refresh timeline"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Sync Timeline</span>
        </button>
      </div>

      <div className="relative pl-8 before:absolute before:bottom-0 before:left-3 before:top-2 before:w-[2px] before:bg-[#222222]">
        <div className="space-y-5">
          {timeline.map((item, idx) => {
            const isExpanded = !!expandedIndices[idx];
            const hasMetadata = item.metadata && Object.keys(item.metadata).length > 0;

            return (
              <div key={idx} className="relative group">
                {/* Timeline node marker */}
                <div className="absolute -left-[37px] top-1.5 flex h-5 w-5 items-center justify-center border border-[#334155] bg-black group-hover:border-[#c81b1c]">
                  <div className="h-2 w-2 bg-[#c81b1c]" />
                </div>

                <div className="border border-[#222222] bg-black p-5 transition hover:border-[#444444] space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      {getTypeIcon(item.type)}
                      <span className="font-sg text-sm md:text-base font-bold uppercase tracking-wider text-white">
                        {item.title}
                      </span>
                      {getSeverityBadge(item.severity)}
                    </div>
                    <span className="font-mono text-xs text-[#94a3b8]">
                      {new Date(item.timestamp).toLocaleString()}
                    </span>
                  </div>

                  {item.description && (
                    <p className="text-sm text-[#e2e8f0] leading-relaxed">
                      {item.description}
                    </p>
                  )}

                  {hasMetadata && (
                    <div className="mt-3 pt-2 border-t border-[#1a1a1a]">
                      <button
                        onClick={() => toggleExpand(idx)}
                        className="flex items-center gap-1.5 text-xs font-semibold text-[#94a3b8] hover:text-white transition"
                      >
                        {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                        <span>{isExpanded ? 'Hide Forensic Attributes' : 'Inspect Forensic Attributes'}</span>
                      </button>

                      {isExpanded && (
                        <pre className="mt-2 border border-[#222222] bg-[#070707] p-3 font-mono text-xs text-[#e2e8f0] overflow-x-auto">
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
    </div>
  );
}

export default IncidentTimelineView;
