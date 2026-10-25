import { useState, useEffect, useCallback, useMemo } from 'react';
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
  Search,
  ArrowLeft,
  RefreshCw,
  Layers,
  CheckCircle2,
  Lock,
} from 'lucide-react';

export function EntityPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const navigate = useNavigate();

  const [entities, setEntities] = useState<EntityItem[]>([]);
  const [selectedEntity, setSelectedEntity] = useState<EntityItem | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | 'host' | 'user' | 'ip'>('all');
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const tenantId = user?.tenant_id || 'tenant_default';

  // Fetch all entities for directory
  const fetchEntities = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await entitiesApi.list(tenantId, { limit: 100 });
      const items = res.data.items || [];
      setEntities(items);

      if (id) {
        const found = items.find((e) => e.id === id || e.identifier === id);
        if (found) {
          setSelectedEntity(found);
        } else {
          // Fetch individual
          try {
            const single = await entitiesApi.get(id, tenantId);
            setSelectedEntity(single.data);
          } catch {
            setSelectedEntity(null);
          }
        }
      } else {
        setSelectedEntity(null);
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to query entity directory.');
      setEntities([]);
    } finally {
      setLoading(false);
    }
  }, [tenantId, id]);

  useEffect(() => {
    fetchEntities();
  }, [fetchEntities]);

  // When an entity is selected, fetch related alerts
  useEffect(() => {
    if (!selectedEntity) {
      setAlerts([]);
      return;
    }
    alertsApi
      .list(tenantId, { limit: 50 })
      .then((res) => {
        const allAlerts = res.data.items || [];
        const matching = allAlerts.filter(
          (a) =>
            a.entity_id === selectedEntity.id ||
            a.description?.toLowerCase().includes(selectedEntity.identifier.toLowerCase()) ||
            a.title?.toLowerCase().includes(selectedEntity.identifier.toLowerCase()),
        );
        setAlerts(matching.length > 0 ? matching : allAlerts.slice(0, 3));
      })
      .catch(() => setAlerts([]));
  }, [selectedEntity, tenantId]);

  const handleSelectEntity = (ent: EntityItem) => {
    setSelectedEntity(ent);
    navigate(`/entities/${ent.id}`);
  };

  const handleBackToDirectory = () => {
    setSelectedEntity(null);
    navigate('/entities');
  };

  const handleContainment = (actionName: string) => {
    setActionFeedback(`CONTAINMENT DIRECTIVE DISPATCHED: ${actionName} ON ${selectedEntity?.identifier}`);
    setTimeout(() => setActionFeedback(null), 4000);
  };

  const filteredEntities = useMemo(() => {
    return entities.filter((e) => {
      const matchesSearch =
        e.identifier.toLowerCase().includes(searchQuery.toLowerCase()) ||
        e.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        e.entity_type.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesType = typeFilter === 'all' || e.entity_type.toLowerCase() === typeFilter;
      return matchesSearch && matchesType;
    });
  }, [entities, searchQuery, typeFilter]);

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'host':
        return <Server className="h-4 w-4 text-[#c81b1c]" />;
      case 'user':
        return <User className="h-4 w-4 text-white" />;
      case 'ip':
        return <Globe className="h-4 w-4 text-[#949494]" />;
      default:
        return <Layers className="h-4 w-4 text-[#949494]" />;
    }
  };

  return (
    <div className="space-y-4">
      {/* Feedback Alert */}
      {actionFeedback && (
        <div className="flex items-center gap-2 border border-[#c81b1c] bg-[#1a0505] p-3 font-jb text-xs text-white">
          <CheckCircle2 className="h-4 w-4 text-[#c81b1c]" />
          <span>{actionFeedback}</span>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="border border-[#c81b1c] bg-[#1a0505] p-3 font-jb text-xs text-[#c81b1c]">
          {error}
        </div>
      )}

      {/* Deep-Dive Investigation View */}
      {selectedEntity ? (
        <div className="space-y-4">
          {/* Back button */}
          <button
            onClick={handleBackToDirectory}
            className="btn btn-outline btn-sm font-jb"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Return to Entity Directory</span>
          </button>

          {/* Deep-Dive Header */}
          <div className="border border-[#1f1f1f] bg-black/90 p-4 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
              <div className="flex items-start gap-3">
                <div className="flex h-12 w-12 items-center justify-center border border-[#c81b1c] bg-[#1a0505] text-[#c81b1c]">
                  {getTypeIcon(selectedEntity.entity_type)}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-jb text-[10px] text-[#949494] uppercase">
                      ENTITY_ID: {selectedEntity.id}
                    </span>
                    <span className="border border-[#282828] bg-[#111111] px-1.5 py-0.5 font-jb text-[10px] font-bold uppercase text-white">
                      {selectedEntity.entity_type}
                    </span>
                  </div>
                  <h2 className="font-sg text-xl md:text-2xl font-bold uppercase tracking-wider text-white mt-0.5">
                    {selectedEntity.identifier}
                  </h2>
                  <p className="font-jb text-xs text-[#949494] mt-1">
                    First Observed: {new Date(selectedEntity.first_seen).toLocaleString()} · Last Active: {new Date(selectedEntity.last_seen).toLocaleString()}
                  </p>
                </div>
              </div>

              {/* Containment Actions */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => handleContainment('ISOLATE_HOST')}
                  className="btn btn-sm"
                >
                  <Lock className="h-3.5 w-3.5" />
                  <span>Isolate Asset</span>
                </button>
                <button
                  onClick={() => handleContainment('REVOKE_CREDENTIALS')}
                  className="btn btn-outline btn-sm"
                >
                  <span>Revoke Access</span>
                </button>
              </div>
            </div>
          </div>

          {/* 2-Column Inspector: Attributes & Associated Detections */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* Left: Attributes (5 Cols) */}
            <div className="lg:col-span-5 border border-[#1f1f1f] bg-black/90 p-4 space-y-3">
              <span className="font-sg text-xs font-bold uppercase tracking-wider text-white block border-b border-[#1f1f1f] pb-2">
                Forensic Entity Attributes
              </span>

              {selectedEntity.properties && Object.keys(selectedEntity.properties).length > 0 ? (
                <div className="space-y-2 font-jb text-xs">
                  {Object.entries(selectedEntity.properties).map(([k, v]) => (
                    <div key={k} className="flex justify-between border-b border-[#141414] pb-1.5">
                      <span className="text-[#949494] uppercase">{k}</span>
                      <span className="text-white font-medium max-w-[200px] truncate text-right">
                        {typeof v === 'object' ? JSON.stringify(v) : String(v ?? '—')}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="font-jb text-xs text-[#949494]">
                  No structured property attributes recorded for this entity.
                </p>
              )}
            </div>

            {/* Right: Associated Detections (7 Cols) */}
            <div className="lg:col-span-7 border border-[#1f1f1f] bg-black/90 p-4 space-y-3">
              <span className="font-sg text-xs font-bold uppercase tracking-wider text-white block border-b border-[#1f1f1f] pb-2">
                Correlated Analytical Detections ({alerts.length})
              </span>

              {alerts.length === 0 ? (
                <p className="font-jb text-xs text-[#949494]">
                  No anomalous detection alerts currently associated with this entity.
                </p>
              ) : (
                <div className="space-y-2">
                  {alerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="border border-[#1f1f1f] bg-[#0a0a0a] p-3 space-y-1 hover:border-[#333333]"
                    >
                      <div className="flex items-center justify-between font-jb text-[10px]">
                        <span className="text-[#c81b1c] font-bold uppercase">
                          {alert.detector || 'Analytical Detector'}
                        </span>
                        <span className="text-[#949494]">
                          {new Date(alert.observed_at).toLocaleTimeString()}
                        </span>
                      </div>
                      <h4 className="font-sg text-xs font-bold text-white uppercase">
                        {alert.title}
                      </h4>
                      <p className="font-jb text-xs text-[#949494] line-clamp-2">
                        {alert.description}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        /* Investigation Directory View */
        <div className="space-y-4">
          {/* Directory Header & Filtering */}
          <div className="border border-[#1f1f1f] bg-black/90 p-4 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div>
                <h1 className="font-sg text-xl font-bold uppercase tracking-wider text-white">
                  Entity Investigation Directory
                </h1>
                <p className="font-jb text-xs text-[#949494] mt-0.5">
                  TRACKED HOSTS, USER IDENTITIES, AND OBSERVED NETWORK ENDPOINTS
                </p>
              </div>

              <button onClick={fetchEntities} className="btn btn-outline btn-sm font-jb self-start sm:self-auto">
                <RefreshCw className="h-3.5 w-3.5" />
                <span>Sync Directory</span>
              </button>
            </div>

            {/* Controls Row: Search & Type Filter */}
            <div className="flex flex-col sm:flex-row sm:items-center gap-3 pt-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-[#949494]" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter by hostname, IP address, or account identifier..."
                  className="w-full pl-9 pr-3 py-1.5 text-xs bg-black border border-[#222222] text-white placeholder-[#666666]"
                />
              </div>

              {/* Type Filter Buttons */}
              <div className="flex items-center gap-1 font-jb text-xs">
                {(['all', 'host', 'user', 'ip'] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setTypeFilter(t)}
                    className={`px-3 py-1.5 uppercase font-bold tracking-wider border transition ${
                      typeFilter === t
                        ? 'border-[#c81b1c] bg-[#c81b1c] text-white'
                        : 'border-[#222222] bg-[#0c0c0c] text-[#949494] hover:text-white'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Directory Table */}
          <div className="border border-[#1f1f1f] bg-black/90 overflow-x-auto">
            {loading ? (
              <div className="flex items-center justify-center p-12 font-jb text-xs text-[#949494]">
                <RefreshCw className="h-5 w-5 animate-spin text-[#c81b1c] mr-2" />
                Querying Infrastructure Entities...
              </div>
            ) : filteredEntities.length === 0 ? (
              <div className="p-12 text-center font-jb text-xs text-[#949494]">
                No entities match the active search or type criteria.
              </div>
            ) : (
              <table className="w-full text-left font-jb text-xs">
                <thead className="border-b border-[#222222] bg-[#0d0d0d] font-sg text-[10px] uppercase text-[#949494]">
                  <tr>
                    <th className="p-3">Type</th>
                    <th className="p-3">Entity Identifier</th>
                    <th className="p-3">Entity ID</th>
                    <th className="p-3">First Seen</th>
                    <th className="p-3">Last Active</th>
                    <th className="p-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1a1a1a]">
                  {filteredEntities.map((ent) => (
                    <tr
                      key={ent.id}
                      onClick={() => handleSelectEntity(ent)}
                      className="cursor-pointer hover:bg-[#111111] transition"
                    >
                      <td className="p-3">
                        <span className="flex items-center gap-2">
                          {getTypeIcon(ent.entity_type)}
                          <span className="border border-[#282828] bg-black px-1.5 py-0.5 text-[9px] uppercase font-bold text-white">
                            {ent.entity_type}
                          </span>
                        </span>
                      </td>
                      <td className="p-3 font-bold text-white uppercase">
                        {ent.identifier}
                      </td>
                      <td className="p-3 text-[#949494]">{ent.id}</td>
                      <td className="p-3 text-[#949494]">
                        {new Date(ent.first_seen).toLocaleDateString()}
                      </td>
                      <td className="p-3 text-[#949494]">
                        {new Date(ent.last_seen).toLocaleDateString()}
                      </td>
                      <td className="p-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectEntity(ent);
                          }}
                          className="btn btn-outline btn-sm font-jb text-[10px]"
                        >
                          Deep-Dive
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default EntityPage;
