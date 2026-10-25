import axios from 'axios';
import type { AxiosInstance, InternalAxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';

/**
 * Centralized Axios API client for the Threat Attribution Platform.
 *
 * - Reads base URL from Vite environment variable `VITE_API_BASE_URL`.
 * - Request Interceptor: Attaches `Authorization: Bearer <token>` from localStorage.
 * - Response Interceptor: Handles 401 Unauthorized by clearing tokens and redirecting to /login.
 */

const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL || '/api/v1';

const api: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ─── Request Interceptor ────────────────────────────────────────────────────
api.interceptors.request.use(
  (config: InternalAxiosRequestConfig): InternalAxiosRequestConfig => {
    const token = localStorage.getItem('soc_session_token') || localStorage.getItem('access_token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error: AxiosError) => Promise.reject(error),
);

// ─── Response Interceptor ───────────────────────────────────────────────────
api.interceptors.response.use(
  (response: AxiosResponse): AxiosResponse => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Clear stale authentication state
      localStorage.removeItem('soc_session_token');
      localStorage.removeItem('access_token');
      localStorage.removeItem('user');

      // Redirect to login only if not already on /login
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  },
);

export default api;

// ─── Typed API Methods ──────────────────────────────────────────────────────

export interface LoginPayload {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  role?: string;
  tenant_id?: string;
}

export interface UserProfile {
  id: string;
  tenant_id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface DashboardSummary {
  tenant_id: string;
  total_events: number;
  total_alerts: number;
  total_incidents: number;
  open_incidents: number;
  critical_alerts: number;
  top_threat_actors: string[];
  attribution_confidence_mean?: number;
  blast_radius_index?: string;
  blast_radius_score?: number;
  last_updated: string;
}

export interface AlertItem {
  id: string;
  tenant_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  observed_at: string;
  created_at: string;
  // Developer A Analytical Extension Fields (CR-03)
  detector?: string | null;
  detector_version?: string | null;
  technique?: string | null;
  technique_id?: string | null;
  entity_id?: string | null;
  score?: number | null;
  confidence?: number | null;
  decision?: string | null;
  evidence?: any;
}

export interface AlertListResponse {
  total: number;
  limit: number;
  offset: number;
  items: AlertItem[];
}

export interface IncidentItem {
  id: string;
  tenant_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  assigned_to: string;
  risk_score?: number | null;
  risk_level?: string | null;
  layers?: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  created_at: string;
  updated_at: string;
}

export interface IncidentListResponse {
  total: number;
  limit: number;
  offset: number;
  items: IncidentItem[];
}

export interface EvaluationSummary {
  model_version: string;
  overall_precision: number;
  overall_recall: number;
  overall_f1: number;
  calibration?: {
    brier_score: number;
    expected_calibration_error: number;
    max_calibration_error: number;
    auc_roc: number;
  };
  attribution?: {
    entry_point_accuracy?: number;
    path_precision?: number;
    path_recall?: number;
    reached_assets_jaccard?: number;
  };
  per_detector_metrics?: Record<string, any>;
  per_class_metrics?: Record<string, any>;
  alerts_per_analyst_day?: Record<string, number>;
  detection_latency_seconds?: Record<string, number>;
  [key: string]: any;
}

export interface TimelineItem {
  timestamp: string;
  type: string;
  title: string;
  description?: string | null;
  severity?: string | null;
  metadata?: Record<string, any>;
}

export interface IncidentTimelineResponse {
  incident_id: string;
  total: number;
  timeline: TimelineItem[];
}

export interface EntityItem {
  id: string;
  tenant_id: string;
  entity_type: string;
  identifier: string;
  properties?: Record<string, any>;
  first_seen: string;
  last_seen: string;
}

export interface EntityListResponse {
  total: number;
  limit: number;
  offset: number;
  items: EntityItem[];
}

export interface AttributionItem {
  id: string;
  attribution_id?: string;
  tenant_id: string;
  incident_id: string;
  actor_name?: string | null;
  campaign?: string | null;
  confidence_score: number;
  confidence?: number;
  tactics_techniques?: any[];
  entry_point?: any;
  attack_path?: any[];
  reached_assets?: any[];
  blast_radius?: any;
  dwell_time_seconds?: number | null;
  explanation?: any;
  graph?: any;
  method?: string | null;
  created_at: string;
}

export interface AttributionListResponse {
  total: number;
  limit: number;
  offset: number;
  items: AttributionItem[];
}

/** Auth APIs */
export const authApi = {
  login: (data: LoginPayload) =>
    api.post<TokenResponse>('/auth/login', data),
  me: () =>
    api.get<UserProfile>('/auth/me'),
};

/** Dashboard APIs */
export const dashboardApi = {
  summary: (tenantId: string) =>
    api.get<DashboardSummary>('/dashboard/summary', { params: { tenant_id: tenantId } }),
};

/** Evaluation APIs */
export const evaluationApi = {
  summary: (tenantId?: string) =>
    api.get<EvaluationSummary>('/evaluation/summary', { params: tenantId ? { tenant_id: tenantId } : {} }),
};

/** Alert APIs */
export const alertsApi = {
  list: (tenantId: string, params?: Record<string, string | number>) =>
    api.get<AlertListResponse>('/alerts', { params: { tenant_id: tenantId, ...params } }),
  get: (alertId: string) =>
    api.get<AlertItem>(`/alerts/${alertId}`),
};

/** Incident APIs */
export const incidentsApi = {
  list: (tenantId: string, params?: Record<string, string | number>) =>
    api.get<IncidentListResponse>('/incidents', { params: { tenant_id: tenantId, ...params } }),
  get: (incidentId: string, tenantId?: string) =>
    api.get<IncidentItem>(`/incidents/${incidentId}`, { params: tenantId ? { tenant_id: tenantId } : {} }),
  updateStatus: (incidentId: string, status: string, notes?: string) =>
    api.patch<IncidentItem>(`/incidents/${incidentId}`, { status, notes }),
  getTimeline: (incidentId: string, tenantId?: string) =>
    api.get<IncidentTimelineResponse>(`/incidents/${incidentId}/timeline`, {
      params: tenantId ? { tenant_id: tenantId } : {},
    }),
};

/** Entity APIs */
export const entitiesApi = {
  list: (tenantId: string, params?: Record<string, string | number>) =>
    api.get<EntityListResponse>('/entities', { params: { tenant_id: tenantId, ...params } }),
  get: (entityId: string, tenantId?: string) =>
    api.get<EntityItem>(`/entities/${entityId}`, { params: tenantId ? { tenant_id: tenantId } : {} }),
};

/** Attribution APIs */
export const attributionsApi = {
  list: (tenantId: string, params?: Record<string, string | number>) =>
    api.get<AttributionListResponse>('/attributions', { params: { tenant_id: tenantId, ...params } }),
  get: (attributionId: string, tenantId?: string) =>
    api.get<AttributionItem>(`/attributions/${attributionId}`, { params: tenantId ? { tenant_id: tenantId } : {} }),
};

// ─── Graph / Attack Topology Types ──────────────────────────────────────────

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  properties?: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  weight: number;
}

export interface PatientZero {
  id?: string;
  entity_id?: string;
  entity_type?: string;
  label?: string;
  identifier?: string;
  type?: string;
  first_seen?: string;
  observed_at?: string;
  confidence?: number;
  first_anomalous_event_id?: string;
}

export interface BlastRadius {
  total_entities?: number;
  reached_count?: number;
  potential_reach_count?: number;
  affected_hosts?: number;
  affected_users?: number;
  affected_ips?: number;
  score?: number;
}

export interface IncidentGraphResponse {
  incident_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  patient_zero: PatientZero | null;
  blast_radius: BlastRadius | null;
}

/** Graph / Attack Topology APIs */
export const graphApi = {
  getIncidentGraph: (incidentId: string, tenantId?: string) =>
    api.get<IncidentGraphResponse>(`/incidents/${incidentId}/graph`, {
      params: tenantId ? { tenant_id: tenantId } : {},
    }),
};

