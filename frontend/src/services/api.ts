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
    const token = localStorage.getItem('access_token');
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
  created_at: string;
  updated_at: string;
}

export interface IncidentListResponse {
  total: number;
  limit: number;
  offset: number;
  items: IncidentItem[];
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

/** Alert APIs */
export const alertsApi = {
  list: (tenantId: string, params?: Record<string, string | number>) =>
    api.get<AlertListResponse>('/alerts', { params: { tenant_id: tenantId, ...params } }),
};

/** Incident APIs */
export const incidentsApi = {
  list: (tenantId: string, params?: Record<string, string | number>) =>
    api.get<IncidentListResponse>('/incidents', { params: { tenant_id: tenantId, ...params } }),
};
