import { useState } from "react";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import { Shield, AlertTriangle, Cpu, Zap, Activity, Clock, ChevronRight } from "lucide-react";

const viewport = { margin: "-50px" } as const;

const fadeInUp = {
  initial: { opacity: 0, y: 60 },
  whileInView: { opacity: 1, y: 0 },
} as const;

const fadeInUpTransition = { duration: 0.5, ease: "easeOut" } as const;

const staggerContainer = {
  initial: {},
  whileInView: { transition: { staggerChildren: 0.08 } },
} as const;

export function Dashboard() {
  const [activeIncidents] = useState(2); // Change this to 0 to show "no incidents" state
  const totalIncidents = 3;
  const lastIncidentTime = '14 minutes ago';

  return (
    <div className="min-h-screen bg-[#FBEAD2] py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-12"
        >
          <h1 className="text-4xl font-bold text-[#023D50] mb-2">Security Dashboard</h1>
          <p className="text-[#456A77] text-lg">Real-time honeypot monitoring and threat detection</p>
        </motion.div>

        {/* Status Alert */}
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className={`bg-white rounded-2xl p-8 mb-8 border-2 shadow-sm ${
            activeIncidents === 0 
              ? 'border-[#16A085]' 
              : 'border-[#DC5037]'
          }`}
        >
          <div className="flex items-start gap-6">
            <motion.div 
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ duration: 0.5, delay: 0.3, type: "spring" }}
              className={`w-16 h-16 rounded-xl flex items-center justify-center flex-shrink-0 ${
                activeIncidents === 0 ? 'bg-[#16A085]/10' : 'bg-[#DC5037]/10'
              }`}
            >
              {activeIncidents === 0 ? (
                <Shield className="w-8 h-8 text-[#16A085]" />
              ) : (
                <AlertTriangle className="w-8 h-8 text-[#DC5037]" />
              )}
            </motion.div>
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-3">
                <div className={`w-3 h-3 rounded-full ${
                  activeIncidents === 0 ? 'bg-[#16A085]' : 'bg-[#DC5037] animate-pulse'
                }`}></div>
                <h2 className="text-2xl font-bold text-[#023D50]">
                  {activeIncidents === 0 ? 'All Systems Secure' : `${activeIncidents} Active Security Incident${activeIncidents > 1 ? 's' : ''}`}
                </h2>
              </div>
              <p className="text-[#023D50] text-lg mb-6 leading-relaxed">
                {activeIncidents === 0 
                  ? 'All honeypot API keys are monitored and secure. No unauthorized access attempts detected in the last 24 hours.'
                  : `Unauthorized API key usage detected ${lastIncidentTime}. HoneyKey has automatically generated detailed security reports with threat analysis and recommended actions.`
                }
              </p>
              {activeIncidents > 0 && (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className="flex gap-4 flex-wrap"
                >
                  <Link
                    to="/reports"
                    className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#DC5037] hover:bg-[#C74433] text-white rounded-lg font-medium transition-all hover:scale-105"
                  >
                    View All Reports
                    <ChevronRight className="w-4 h-4" />
                  </Link>
                </motion.div>
              )}
            </div>
          </div>
        </motion.div>

        {/* AI Monitoring Status */}
        <motion.div
          variants={fadeInUp}
          initial="initial"
          whileInView="whileInView"
          viewport={viewport}
          transition={fadeInUpTransition}
          className="bg-white rounded-2xl p-8 mb-8 border border-[#D4C4B0]"
        >
          <div className="flex items-start gap-6">
            <div className="w-16 h-16 bg-gradient-to-br from-[#E09B3D]/20 to-[#023D50]/20 rounded-xl flex items-center justify-center flex-shrink-0 relative">
              <Cpu className="w-8 h-8 text-[#E09B3D]" />
              <div className="absolute -top-1 -right-1 w-3 h-3 bg-[#16A085] rounded-full animate-pulse"></div>
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-3">
                <h2 className="text-2xl font-bold text-[#023D50]">AI Monitoring Engine</h2>
                <span className="px-3 py-1 bg-[#16A085]/10 text-[#16A085] text-xs font-semibold rounded-full uppercase">
                  Active
                </span>
              </div>
              <p className="text-[#023D50] mb-6 leading-relaxed">
                HoneyKey's AI-powered detection engine is continuously analyzing API key usage patterns, 
                network behaviors, and threat signatures across all deployed honeypots.
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 bg-[#16A085]/10 rounded-lg flex items-center justify-center flex-shrink-0">
                    <Zap className="w-5 h-5 text-[#16A085]" />
                  </div>
                  <div>
                    <div className="text-lg font-bold text-[#023D50] mb-1">Real-Time Analysis</div>
                    <div className="text-sm text-[#456A77]">Processing 847 events/sec</div>
                  </div>
                </div>
                
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 bg-[#E09B3D]/10 rounded-lg flex items-center justify-center flex-shrink-0">
                    <Activity className="w-5 h-5 text-[#E09B3D]" />
                  </div>
                  <div>
                    <div className="text-lg font-bold text-[#023D50] mb-1">Pattern Detection</div>
                    <div className="text-sm text-[#456A77]">12 known threat signatures</div>
                  </div>
                </div>
                
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 bg-[#023D50]/10 rounded-lg flex items-center justify-center flex-shrink-0">
                    <Shield className="w-5 h-5 text-[#023D50]" />
                  </div>
                  <div>
                    <div className="text-lg font-bold text-[#023D50] mb-1">Model Accuracy</div>
                    <div className="text-sm text-[#456A77]">98.7% detection rate</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Stats Grid */}
        <motion.div 
          variants={staggerContainer}
          initial="initial"
          whileInView="whileInView"
          viewport={{ margin: "-50px" }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8"
        >
          {[
            { icon: Shield, value: '12', label: 'Honeypot Keys Active', color: 'bg-[#E09B3D]/10 text-[#E09B3D]' },
            { 
              icon: AlertTriangle, 
              value: activeIncidents.toString(), 
              label: 'Active Threats', 
              color: activeIncidents === 0 ? 'bg-[#16A085]/10 text-[#16A085]' : 'bg-[#DC5037]/10 text-[#DC5037]',
              valueColor: activeIncidents === 0 ? 'text-[#16A085]' : 'text-[#DC5037]'
            },
            { icon: Activity, value: totalIncidents.toString(), label: 'Total Incidents (24h)', color: 'bg-[#023D50]/10 text-[#023D50]' },
            { icon: Clock, value: lastIncidentTime.split(' ')[0], label: lastIncidentTime.split(' ').slice(1).join(' '), color: 'bg-[#F39C12]/10 text-[#F39C12]' },
          ].map((stat) => (
            <motion.div 
              key={stat.value}
              variants={fadeInUp}
              whileHover={{ y: -4, transition: { duration: 0.2 } }}
              className="bg-white rounded-xl p-6 border border-[#D4C4B0] hover:border-[#E09B3D] transition-all cursor-default"
            >
              <div className="flex items-center justify-between mb-4">
                <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${stat.color}`}>
                  <stat.icon className="w-6 h-6" />
                </div>
              </div>
              <div className={`text-3xl font-bold mb-1 ${stat.valueColor || 'text-[#023D50]'}`}>{stat.value}</div>
              <div className="text-sm text-[#456A77]">{stat.label}</div>
            </motion.div>
          ))}
        </motion.div>

        {/* Recent Activity */}
        <motion.div 
          variants={fadeInUp}
          initial="initial"
          whileInView="whileInView"
          viewport={viewport}
          transition={fadeInUpTransition}
          className="bg-white rounded-xl p-8 border border-[#D4C4B0]"
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-[#023D50]">Recent Activity</h2>
            <Link to="/reports" className="text-[#E09B3D] hover:text-[#D4881C] font-medium flex items-center gap-1 transition-colors">
              View All
              <ChevronRight className="w-4 h-4" />
            </Link>
          </div>

          <motion.div 
            variants={staggerContainer}
            initial="initial"
            whileInView="whileInView"
            viewport={{ margin: "-50px" }}
            className="space-y-3"
          >
            {[
              {
                id: 'INC-2026-001',
                title: 'Multiple API Key Exploitation Attempts - OpenAI',
                time: '14 minutes ago',
                severity: 'high',
                status: 'active',
                ip: '185.220.101.47'
              },
              {
                id: 'INC-2026-002',
                title: 'Automated Scanning Campaign - GitHub PAT',
                time: '2 hours ago',
                severity: 'medium',
                status: 'active',
                ip: '103.75.201.12'
              },
              {
                id: 'INC-2026-003',
                title: 'Probing Activity - AWS Credentials',
                time: '5 hours ago',
                severity: 'low',
                status: 'resolved',
                ip: '198.51.100.89'
              },
            ].map((incident) => (
              <motion.div
                key={incident.id}
                variants={fadeInUp}
                whileHover={{ x: 4, transition: { duration: 0.2 } }}
              >
                <Link 
                  to="/reports"
                  className="flex items-center gap-4 p-4 bg-[#FFF8F0] rounded-lg border border-[#D4C4B0] hover:border-[#E09B3D] transition-all group"
                >
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                    incident.severity === 'high' ? 'bg-[#DC5037]' :
                    incident.severity === 'medium' ? 'bg-[#F39C12]' :
                    'bg-[#16A085]'
                  } ${incident.status === 'active' ? 'animate-pulse' : ''}`}></div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <span className="font-semibold text-[#023D50]">{incident.id}</span>
                      <span className={`text-xs px-2 py-0.5 rounded uppercase font-medium ${
                        incident.severity === 'high' ? 'text-[#DC5037] bg-[#DC5037]/10' :
                        incident.severity === 'medium' ? 'text-[#F39C12] bg-[#F39C12]/10' :
                        'text-[#16A085] bg-[#16A085]/10'
                      }`}>
                        {incident.severity}
                      </span>
                    </div>
                    <p className="text-[#023D50] mb-1">{incident.title}</p>
                    <p className="text-sm text-[#456A77]">{incident.time} • IP: {incident.ip}</p>
                  </div>
                  <ChevronRight className="w-5 h-5 text-[#456A77] group-hover:text-[#E09B3D] group-hover:translate-x-1 transition-all flex-shrink-0" />
                </Link>
              </motion.div>
            ))}
          </motion.div>
        </motion.div>
      </div>
    </div>
  );
}