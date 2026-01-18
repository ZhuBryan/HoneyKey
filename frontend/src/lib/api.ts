import { useState, useEffect } from "react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL as string;

if (!API_BASE_URL) {
  // Helps catch “blank screen” issues early
  console.warn("VITE_API_BASE_URL is not set. Did you create .env.local?");
}

// Type definitions
export interface Report {
  id: string;
  title: string;
  generatedDate: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "ACTIVE" | "RESOLVED" | "ACKNOWLEDGED";
  incidentCount: number;
  threatLevel: string;
  type: "engineer";
  summary: string;
}

export interface Incident {
  timestamp: string;
  sourceIP: string;
  asn: string;
  honeypotKeyId: string;
  requestCount: number;
  requestRate: number[];
  findings: string;
  threatIntel: string;
}

export interface DashboardStats {
  activeHoneypots: number;
  activeThreats: number;
  totalIncidents: number;
  lastIncidentTime: string;
}

// Generic API functions with optional API key support
export async function apiGet<T>(path: string, apiKey?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }

  const res = await fetch(`${API_BASE_URL}${path}`, { headers });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GET ${path} failed: ${res.status} ${text}`);
  }
  return (await res.json()) as T;
}

export async function apiPost<T>(path: string, body?: unknown, apiKey?: string): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }

  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`POST ${path} failed: ${res.status} ${text}`);
  }
  // Some POST endpoints may return no JSON
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? ((await res.json()) as T) : (undefined as T);
}

// Specific API functions for reports
export async function fetchReports(
  filters?: { severity?: string; status?: string; search?: string },
  apiKey?: string
): Promise<Report[]> {
  const params = new URLSearchParams();
  if (filters?.severity) params.append("severity", filters.severity);
  if (filters?.status) params.append("status", filters.status);
  if (filters?.search) params.append("search", filters.search);

  const queryString = params.toString();
  const path = `/api/reports${queryString ? "?" + queryString : ""}`;
  return apiGet<Report[]>(path, apiKey);
}

export async function fetchReportById(id: string, apiKey?: string): Promise<Report> {
  return apiGet<Report>(`/api/reports/${id}`, apiKey);
}

export async function fetchIncidents(reportId: string, apiKey?: string): Promise<Incident[]> {
  return apiGet<Incident[]>(`/api/reports/${reportId}/incidents`, apiKey);
}

export async function fetchDashboardStats(apiKey?: string): Promise<DashboardStats> {
  return apiGet<DashboardStats>(`/api/dashboard/stats`, apiKey);
}

// Custom hooks for data fetching
export interface UseFetchState<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
}

export function useReports(filters?: { severity?: string; status?: string; search?: string }) {
  const [state, setState] = useState<UseFetchState<Report[]>>({
    data: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    let isMounted = true;

    const loadReports = async () => {
      try {
        setState({ data: null, loading: true, error: null });
        const apiKey = localStorage.getItem("apiKey") || undefined;
        const data = await fetchReports(filters, apiKey);
        if (isMounted) {
          setState({ data, loading: false, error: null });
        }
      } catch (error) {
        if (isMounted) {
          setState({ data: null, loading: false, error: error as Error });
        }
      }
    };

    loadReports();
    return () => {
      isMounted = false;
    };
  }, [filters?.severity, filters?.status, filters?.search]);

  return state;
}

export function useReportById(id: string) {
  const [state, setState] = useState<UseFetchState<Report>>({
    data: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    let isMounted = true;

    const loadReport = async () => {
      try {
        setState({ data: null, loading: true, error: null });
        const apiKey = localStorage.getItem("apiKey") || undefined;
        const data = await fetchReportById(id, apiKey);
        if (isMounted) {
          setState({ data, loading: false, error: null });
        }
      } catch (error) {
        if (isMounted) {
          setState({ data: null, loading: false, error: error as Error });
        }
      }
    };

    loadReport();
    return () => {
      isMounted = false;
    };
  }, [id]);

  return state;
}

export function useIncidents(reportId: string) {
  const [state, setState] = useState<UseFetchState<Incident[]>>({
    data: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    let isMounted = true;

    const loadIncidents = async () => {
      try {
        setState({ data: null, loading: true, error: null });
        const apiKey = localStorage.getItem("apiKey") || undefined;
        const data = await fetchIncidents(reportId, apiKey);
        if (isMounted) {
          setState({ data, loading: false, error: null });
        }
      } catch (error) {
        if (isMounted) {
          setState({ data: null, loading: false, error: error as Error });
        }
      }
    };

    if (reportId) {
      loadIncidents();
    }
    return () => {
      isMounted = false;
    };
  }, [reportId]);

  return state;
}

export function useDashboardStats() {
  const [state, setState] = useState<UseFetchState<DashboardStats>>({
    data: null,
    loading: true,
    error: null,
  });

  useEffect(() => {
    let isMounted = true;

    const loadStats = async () => {
      try {
        setState({ data: null, loading: true, error: null });
        const apiKey = localStorage.getItem("apiKey") || undefined;
        const data = await fetchDashboardStats(apiKey);
        if (isMounted) {
          setState({ data, loading: false, error: null });
        }
      } catch (error) {
        if (isMounted) {
          setState({ data: null, loading: false, error: error as Error });
        }
      }
    };

    loadStats();
    return () => {
      isMounted = false;
    };
  }, []);

  return state;
}