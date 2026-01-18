import { useState } from 'react';
import { AlertCircle, MapPin, Clock, Activity, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';

interface Incident {
  id: string;
  timestamp: string;
  ip: string;
  location: string;
  keyUsed: string;
  attempts: number;
  severity: 'high' | 'medium' | 'low';
  status: 'active' | 'resolved';
}

export function IncidentDemo() {
  const [incidents] = useState<Incident[]>([
    {
      id: 'INC-2026-001',
      timestamp: '2026-01-17 14:32:15 UTC',
      ip: '185.220.101.47',
      location: 'Moscow, Russia',
      keyUsed: 'sk-proj-abc123...xyz789',
      attempts: 47,
      severity: 'high',
      status: 'active',
    },
    {
      id: 'INC-2026-002',
      timestamp: '2026-01-17 12:18:03 UTC',
      ip: '103.75.201.12',
      location: 'Shanghai, China',
      keyUsed: 'ghp_honeypot...def456',
      attempts: 23,
      severity: 'medium',
      status: 'active',
    },
    {
      id: 'INC-2026-003',
      timestamp: '2026-01-17 09:45:22 UTC',
      ip: '198.51.100.89',
      location: 'São Paulo, Brazil',
      keyUsed: 'aws-key-honey...ghi789',
      attempts: 12,
      severity: 'medium',
      status: 'resolved',
    },
  ]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return 'text-[#DC5037] bg-[#DC5037]/20 border border-[#DC5037]/30';
      case 'medium':
        return 'text-[#F39C12] bg-[#F39C12]/20 border border-[#F39C12]/30';
      case 'low':
        return 'text-[#16A085] bg-[#16A085]/20 border border-[#16A085]/30';
      default:
        return 'text-[#456A77] bg-[#456A77]/20 border border-[#456A77]/30';
    }
  };

  return (
    <section className="py-20 px-4 sm:px-6 lg:px-8 bg-[#FBEAD2]">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold mb-4 text-[#023D50]">
            Live <span className="gradient-text">Incident Detection</span>
          </h2>
          <p className="text-xl text-[#456A77] max-w-2xl mx-auto">
            Real-time monitoring of honeypot API key usage attempts
          </p>
        </div>

        <div className="mb-8 flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-[#16A085] rounded-full animate-pulse"></div>
              <span className="text-sm text-[#456A77]">System Online</span>
            </div>
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#E09B3D]" />
              <span className="text-sm text-[#456A77]">
                {incidents.filter(i => i.status === 'active').length} Active Threats
              </span>
            </div>
          </div>
          
          <div className="flex gap-3">
            <Link 
              to="/report/engineer"
              className="px-4 py-2 bg-[#E09B3D] hover:bg-[#D4881C] rounded-lg text-sm font-medium transition-colors flex items-center gap-2 text-white"
            >
              Technical Report
              <ChevronRight className="w-4 h-4" />
            </Link>
          </div>
        </div>

        {incidents.length === 0 ? (
          <div className="incident-card rounded-xl p-12 text-center">
            <div className="w-16 h-16 bg-[#16A085]/20 rounded-full flex items-center justify-center mx-auto mb-4">
              <Activity className="w-8 h-8 text-[#16A085]" />
            </div>
            <h3 className="text-xl font-semibold mb-2 text-[#023D50]">No Incidents Detected</h3>
            <p className="text-[#456A77]">
              All honeypot API keys are monitored and ready. No unauthorized usage attempts detected yet.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {incidents.map((incident) => (
              <div key={incident.id} className="incident-card rounded-xl p-6">
                <div className="flex items-start justify-between flex-wrap gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-3 flex-wrap">
                      <span className="text-lg font-semibold text-[#023D50]">{incident.id}</span>
                      <span className={`px-3 py-1 rounded-full text-xs font-medium uppercase ${getSeverityColor(incident.severity)}`}>
                        {incident.severity}
                      </span>
                      <span className={`px-3 py-1 rounded-full text-xs font-medium uppercase border ${
                        incident.status === 'active' 
                          ? 'text-[#E09B3D] bg-[#E09B3D]/20 border-[#E09B3D]/30' 
                          : 'text-[#456A77] bg-[#456A77]/20 border-[#456A77]/30'
                      }`}>
                        {incident.status}
                      </span>
                    </div>
                    
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
                      <div className="flex items-center gap-2 text-[#456A77]">
                        <Clock className="w-4 h-4 flex-shrink-0" />
                        <span className="truncate">{incident.timestamp}</span>
                      </div>
                      <div className="flex items-center gap-2 text-[#456A77]">
                        <MapPin className="w-4 h-4 flex-shrink-0" />
                        <span className="truncate">{incident.location}</span>
                      </div>
                      <div className="flex items-center gap-2 text-[#456A77]">
                        <AlertCircle className="w-4 h-4 flex-shrink-0" />
                        <span className="truncate">IP: {incident.ip}</span>
                      </div>
                      <div className="flex items-center gap-2 text-[#456A77]">
                        <Activity className="w-4 h-4 flex-shrink-0" />
                        <span className="truncate">{incident.attempts} attempts</span>
                      </div>
                    </div>
                    
                    <div className="mt-3 pt-3 border-t border-[#D4C4B0]">
                      <div className="text-xs text-[#456A77]">Honeypot Key Used:</div>
                      <code className="text-xs">{incident.keyUsed}</code>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}