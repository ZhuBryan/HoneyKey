const BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export type Incident = {
  id: number;
  key_id: string;
  source_ip: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
};

export const api = {
  listIncidents: () => http<Incident[]>(`/incidents`),
  analyzeIncident: (id: number) => http<any>(`/incidents/${id}/analyze`, { method: "POST" }),
  getAiReport: (id: number) => http<any>(`/incidents/${id}/ai-report`),
};
