/**
 * API Service for Red Team Attacker Dashboard
 * Directs simulation triggers and health checks to backend Port 8000.
 */

export interface SimulationPayload {
  scenario_id: string;
  tenant_id?: string;
}

export interface SimulationResult {
  status: string;
  scenario_id: string;
  injected_events: number;
  alerts_generated: number;
  incidents_generated: number;
  attributions_generated: number;
  incident_id?: string | null;
  incident_ids?: string[];
  alert_ids?: string[];
  execution_logs?: Array<{
    timestamp: string;
    level: string;
    target: string;
    message: string;
  }>;
  scenario?: {
    name: string;
    target_vector: string;
    difficulty: string;
    description: string;
    mitre_techniques: string[];
  };
}

// Prefer direct connection to Port 8000, fallback to current origin proxy if needed
const PRIMARY_API_URL = 'http://127.0.0.1:8000';

async function fetchWithFallback(endpoint: string, options: RequestInit = {}): Promise<Response> {
  // First attempt direct backend Port 8000
  try {
    const directUrl = `${PRIMARY_API_URL}${endpoint}`;
    const res = await fetch(directUrl, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    });
    return res;
  } catch (directErr) {
    // If direct fails (e.g. CORS or network blocking), try relative path through Vite proxy
    try {
      const proxyUrl = endpoint;
      const proxyRes = await fetch(proxyUrl, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {}),
        },
      });
      return proxyRes;
    } catch {
      throw directErr;
    }
  }
}

export const api = {
  /**
   * Health check to Port 8000
   */
  async checkHealth(): Promise<boolean> {
    try {
      const res = await fetchWithFallback('/health', { method: 'GET' });
      return res.ok;
    } catch {
      return false;
    }
  },

  /**
   * Trigger simulation scenario
   */
  async simulateAttack(payload: SimulationPayload): Promise<SimulationResult> {
    const res = await fetchWithFallback('/api/v1/demo/simulate', {
      method: 'POST',
      body: JSON.stringify({
        scenario_id: payload.scenario_id,
        tenant_id: payload.tenant_id || 'tenant-default-001',
      }),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({ detail: `HTTP ${res.status}: Simulation error` }));
      throw new Error(errorData.detail || `Server error (${res.status})`);
    }

    const raw = await res.json();

    // Normalize response fields across both schemas
    return {
      status: raw.status || 'success',
      scenario_id: raw.scenario_id || payload.scenario_id,
      injected_events: raw.injected_events ?? raw.events_injected ?? 0,
      alerts_generated: raw.alerts_generated ?? 0,
      incidents_generated: raw.incidents_generated ?? (raw.incident_ids?.length || 0),
      attributions_generated: raw.attributions_generated ?? 0,
      incident_id: raw.incident_id || raw.incident_ids?.[0] || null,
      incident_ids: raw.incident_ids || [],
      alert_ids: raw.alert_ids || [],
      execution_logs: raw.execution_logs || [],
      scenario: raw.scenario,
    };
  },
};
