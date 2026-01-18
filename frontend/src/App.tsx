import { useEffect, useState } from "react";
import { api, type Incident } from "./lib/api";

export default function App() {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listIncidents()
      .then(setIncidents)
      .catch((e) => setError(String(e)));
  }, []);

  if (error) return <pre>Error: {error}</pre>;
  if (!incidents) return <div>Loading incidents…</div>;

  return (
    <div style={{ padding: 16 }}>
      <h1>HoneyKey Incidents</h1>
      <ul>
        {incidents.map((i) => (
          <li key={i.id}>
            #{i.id} {i.source_ip} ({i.event_count} events)
          </li>
        ))}
      </ul>
    </div>
  );
}
