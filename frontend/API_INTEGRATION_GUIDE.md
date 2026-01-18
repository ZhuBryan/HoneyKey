# API Integration Guide

## Setup

1. Create a `.env.local` file in the `frontend/` directory:
```
VITE_API_BASE_URL=http://localhost:3000
```

2. The API client will look for an `apiKey` in localStorage (optional for authentication)

## Available Hooks

### useReports()
Fetches all reports with optional filtering.

```tsx
import { useReports } from '@/lib/api';

export function ReportsPage() {
  const { data: reports, loading, error } = useReports({
    severity: 'HIGH',
    status: 'ACTIVE',
    search: 'api'
  });

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  
  return (
    <div>
      {reports?.map(report => (
        <div key={report.id}>{report.title}</div>
      ))}
    </div>
  );
}
```

### useReportById()
Fetches a single report by ID.

```tsx
import { useReportById } from '@/lib/api';

export function ReportDetail({ id }: { id: string }) {
  const { data: report, loading, error } = useReportById(id);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  
  return <div>{report?.title}</div>;
}
```

### useIncidents()
Fetches incidents for a specific report.

```tsx
import { useIncidents } from '@/lib/api';

export function IncidentList({ reportId }: { reportId: string }) {
  const { data: incidents, loading, error } = useIncidents(reportId);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  
  return (
    <ul>
      {incidents?.map(incident => (
        <li key={incident.honeypotKeyId}>{incident.sourceIP}</li>
      ))}
    </ul>
  );
}
```

### useDashboardStats()
Fetches dashboard statistics.

```tsx
import { useDashboardStats } from '@/lib/api';

export function Dashboard() {
  const { data: stats, loading, error } = useDashboardStats();

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  
  return (
    <div>
      <p>Active Honeypots: {stats?.activeHoneypots}</p>
      <p>Active Threats: {stats?.activeThreats}</p>
      <p>Total Incidents: {stats?.totalIncidents}</p>
    </div>
  );
}
```

## Direct API Functions

If you need more control, use the direct functions:

```tsx
import { fetchReports, fetchReportById, fetchIncidents, fetchDashboardStats } from '@/lib/api';

// With optional API key
const reports = await fetchReports({ severity: 'HIGH' }, apiKey);
const report = await fetchReportById('123', apiKey);
const incidents = await fetchIncidents('report-id', apiKey);
const stats = await fetchDashboardStats(apiKey);
```

## Type Definitions

All types are exported from `@/lib/api`:

```tsx
import type { Report, Incident, DashboardStats, UseFetchState } from '@/lib/api';
```

## Backend Endpoints

The frontend expects these endpoints:

- `GET /api/reports` - List all reports (supports query params: severity, status, search)
- `GET /api/reports/:id` - Get specific report
- `GET /api/reports/:id/incidents` - Get incidents for a report
- `GET /api/dashboard/stats` - Get dashboard statistics

## Error Handling

All hooks return `{ data, loading, error }`. Always check for errors:

```tsx
const { data, loading, error } = useReports();

if (error) {
  console.error('Failed to fetch reports:', error.message);
}
```

## Authentication

Store API key in localStorage:

```tsx
// In your login/auth component
localStorage.setItem('apiKey', 'your-api-key-here');

// Hooks will automatically include it in requests
```
