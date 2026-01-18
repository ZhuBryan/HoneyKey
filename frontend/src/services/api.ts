/**
 * HoneyKey API Client
 *
 * Uses VITE_API_BASE_URL environment variable for the backend URL.
 * - Local development: http://127.0.0.1:8000
 * - Production: https://your-backend-domain.com
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

// Types
export interface DashboardStats {
  active_incidents: number;
  total_incidents: number;
  honeypot_keys_active: number;
  blocked_ips: number;
  last_incident_time: string | null;
}

export interface ReportListItem {
  id: string;
  incident_id: number;
  title: string;
  generated_date: string;
  incident_date: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'new' | 'reviewed' | 'archived';
  event_count: number;
  source_ip: string;
  summary: string;
}

export interface AIReport {
  incident_id: number;
  severity: string;
  confidence_score: number;
  summary: string;
  evidence: string[];
  techniques: string[];
  recommended_actions: string[];
  report?: string;
}

export interface ReportEvent {
  id: number;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  user_agent: string;
  correlation_id: string;
  auth_present?: boolean;
  honeypot_key_used?: boolean;
}

export interface ReportDetail {
  id: string;
  incident_id: number;
  source_ip: string;
  key_id: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  is_blocked: boolean;
  has_ai_report: boolean;
  ai_report: AIReport | null;
  events: ReportEvent[];
}

export interface BlockIPResponse {
  success: boolean;
  message: string;
  block?: Record<string, unknown>;
}

// API Error class
export class APIError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
    this.name = 'APIError';
  }
}

// Helper function for API calls
async function fetchAPI<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const error = await response.json();
      detail = error.detail || detail;
    } catch {
      // Ignore JSON parse errors
    }
    throw new APIError(response.status, detail);
  }

  return response.json();
}

// Dashboard API
export async function getDashboardStats(): Promise<DashboardStats> {
  return fetchAPI<DashboardStats>('/api/dashboard/stats');
}

// Reports API
export async function getReports(): Promise<ReportListItem[]> {
  return fetchAPI<ReportListItem[]>('/api/reports');
}

export async function getReport(reportId: string): Promise<ReportDetail> {
  return fetchAPI<ReportDetail>(`/api/reports/${reportId}`);
}

export async function getReportEvents(reportId: string, limit: number = 50): Promise<ReportEvent[]> {
  return fetchAPI<ReportEvent[]>(`/api/reports/${reportId}/events?limit=${limit}`);
}

export async function analyzeReport(reportId: string): Promise<AIReport> {
  return fetchAPI<AIReport>(`/api/reports/${reportId}/analyze`, {
    method: 'POST',
  });
}

export async function blockReportIP(
  reportId: string,
  options: { reason?: string; duration_hours?: number; notes?: string } = {}
): Promise<BlockIPResponse> {
  return fetchAPI<BlockIPResponse>(`/api/reports/${reportId}/block-ip`, {
    method: 'POST',
    body: JSON.stringify({
      reason: options.reason || 'honeypot_abuse',
      duration_hours: options.duration_hours ?? 24,
      notes: options.notes || '',
    }),
  });
}

export async function unblockReportIP(reportId: string): Promise<BlockIPResponse> {
  return fetchAPI<BlockIPResponse>(`/api/reports/${reportId}/unblock-ip`, {
    method: 'DELETE',
  });
}

// Health check
export async function healthCheck(): Promise<{ status: string }> {
  return fetchAPI<{ status: string }>('/health');
}

// Export the base URL for debugging
export function getAPIBaseURL(): string {
  return API_BASE_URL;
}
