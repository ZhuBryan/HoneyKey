import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ArrowLeft,
  AlertTriangle,
  Shield,
  Clock,
  Globe,
  Target,
  Zap,
  CheckCircle,
  XCircle,
  RefreshCw,
  Ban,
  Unlock,
  FileText,
  Activity,
} from 'lucide-react';
import {
  getReport,
  analyzeReport,
  blockReportIP,
  unblockReportIP,
  type ReportDetail as ReportDetailType,
  type AIReport,
  APIError,
} from '../services/api';
import { useToast } from '../contexts/ToastContext';

const fadeInUp = {
  initial: { opacity: 0, y: 20 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.4 },
};

export function ReportDetail() {
  const { reportId } = useParams<{ reportId: string }>();
  const { showToast, showReportGeneratedAlert } = useToast();
  const [report, setReport] = useState<ReportDetailType | null>(null);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (reportId) {
      loadReport();
    }
  }, [reportId]);

  async function loadReport() {
    try {
      setLoading(true);
      setError(null);
      const data = await getReport(reportId!);
      setReport(data);
    } catch (err) {
      const message = err instanceof APIError ? err.detail : 'Failed to load report';
      setError(message);
      showToast({ type: 'error', title: 'Error', message });
    } finally {
      setLoading(false);
    }
  }

  async function handleAnalyze() {
    if (!reportId) return;
    try {
      setAnalyzing(true);
      const aiReport = await analyzeReport(reportId);
      setReport((prev) => prev ? { ...prev, has_ai_report: true, ai_report: aiReport } : prev);
      showReportGeneratedAlert(reportId, aiReport.severity);
    } catch (err) {
      const message = err instanceof APIError ? err.detail : 'Failed to analyze report';
      showToast({ type: 'error', title: 'Analysis Failed', message });
    } finally {
      setAnalyzing(false);
    }
  }

  async function handleBlockIP() {
    if (!reportId) return;
    try {
      setBlocking(true);
      await blockReportIP(reportId, { reason: 'honeypot_abuse', duration_hours: 24 });
      setReport((prev) => prev ? { ...prev, is_blocked: true } : prev);
      showToast({ type: 'success', title: 'IP Blocked', message: `${report?.source_ip} has been blocked for 24 hours` });
    } catch (err) {
      const message = err instanceof APIError ? err.detail : 'Failed to block IP';
      showToast({ type: 'error', title: 'Block Failed', message });
    } finally {
      setBlocking(false);
    }
  }

  async function handleUnblockIP() {
    if (!reportId) return;
    try {
      setBlocking(true);
      await unblockReportIP(reportId);
      setReport((prev) => prev ? { ...prev, is_blocked: false } : prev);
      showToast({ type: 'success', title: 'IP Unblocked', message: `${report?.source_ip} has been unblocked` });
    } catch (err) {
      const message = err instanceof APIError ? err.detail : 'Failed to unblock IP';
      showToast({ type: 'error', title: 'Unblock Failed', message });
    } finally {
      setBlocking(false);
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-[#DC5037] bg-[#DC5037]/10 border-[#DC5037]';
      case 'high': return 'text-[#E09B3D] bg-[#E09B3D]/10 border-[#E09B3D]';
      case 'medium': return 'text-[#F39C12] bg-[#F39C12]/10 border-[#F39C12]';
      case 'low': return 'text-[#16A085] bg-[#16A085]/10 border-[#16A085]';
      default: return 'text-[#456A77] bg-[#456A77]/10 border-[#456A77]';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#FBEAD2] py-12 px-4 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-12 h-12 text-[#E09B3D] animate-spin mx-auto mb-4" />
          <p className="text-[#023D50] text-lg">Loading report...</p>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="min-h-screen bg-[#FBEAD2] py-12 px-4">
        <div className="max-w-4xl mx-auto">
          <Link to="/reports" className="inline-flex items-center gap-2 text-[#E09B3D] hover:text-[#D4881C] mb-8">
            <ArrowLeft className="w-5 h-5" />
            Back to Reports
          </Link>
          <div className="bg-white rounded-2xl p-8 border border-[#DC5037] text-center">
            <XCircle className="w-16 h-16 text-[#DC5037] mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-[#023D50] mb-2">Report Not Found</h2>
            <p className="text-[#456A77]">{error || 'The requested report could not be loaded.'}</p>
          </div>
        </div>
      </div>
    );
  }

  const aiReport = report.ai_report;

  return (
    <div className="min-h-screen bg-[#FBEAD2] py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto">
        {/* Back Button */}
        <Link to="/reports" className="inline-flex items-center gap-2 text-[#E09B3D] hover:text-[#D4881C] mb-8 transition-colors">
          <ArrowLeft className="w-5 h-5" />
          Back to Reports
        </Link>

        {/* Header */}
        <motion.div {...fadeInUp} className="bg-white rounded-2xl p-8 mb-6 border border-[#D4C4B0]">
          <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
            <div>
              <div className="flex items-center gap-3 mb-3 flex-wrap">
                <h1 className="text-3xl font-bold text-[#023D50]">Incident #{report.incident_id}</h1>
                {aiReport && (
                  <span className={`px-3 py-1 rounded-full text-sm font-medium uppercase border ${getSeverityColor(aiReport.severity)}`}>
                    {aiReport.severity}
                  </span>
                )}
                {report.is_blocked && (
                  <span className="px-3 py-1 rounded-full text-sm font-medium uppercase bg-[#DC5037]/10 text-[#DC5037] border border-[#DC5037]">
                    IP Blocked
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-4 text-[#456A77]">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4" />
                  <span>Source IP: <code className="bg-[#FFF8F0] px-2 py-0.5 rounded">{report.source_ip}</code></span>
                </div>
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4" />
                  <span>First seen: {formatTimestamp(report.first_seen)}</span>
                </div>
              </div>
            </div>
            <div className="flex gap-2 flex-wrap">
              {!report.has_ai_report && (
                <button
                  onClick={handleAnalyze}
                  disabled={analyzing}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-[#E09B3D] hover:bg-[#D4881C] text-white rounded-lg font-medium transition-all disabled:opacity-50"
                >
                  {analyzing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                  {analyzing ? 'Analyzing...' : 'Generate AI Report'}
                </button>
              )}
              {report.is_blocked ? (
                <button
                  onClick={handleUnblockIP}
                  disabled={blocking}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-[#16A085] hover:bg-[#138D75] text-white rounded-lg font-medium transition-all disabled:opacity-50"
                >
                  {blocking ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Unlock className="w-4 h-4" />}
                  Unblock IP
                </button>
              ) : (
                <button
                  onClick={handleBlockIP}
                  disabled={blocking}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-[#DC5037] hover:bg-[#C74433] text-white rounded-lg font-medium transition-all disabled:opacity-50"
                >
                  {blocking ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Ban className="w-4 h-4" />}
                  Block IP
                </button>
              )}
            </div>
          </div>
        </motion.div>

        {/* AI Report Section */}
        {aiReport && (
          <motion.div {...fadeInUp} transition={{ delay: 0.1 }} className="space-y-6">
            {/* Summary */}
            <div className="bg-white rounded-2xl p-8 border border-[#D4C4B0]">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-[#E09B3D]/10 rounded-lg flex items-center justify-center">
                  <FileText className="w-5 h-5 text-[#E09B3D]" />
                </div>
                <h2 className="text-xl font-bold text-[#023D50]">Executive Summary</h2>
                <span className="px-2 py-1 bg-[#16A085]/10 text-[#16A085] text-xs font-medium rounded-full">
                  {Math.round(aiReport.confidence_score * 100)}% Confidence
                </span>
              </div>
              <p className="text-[#023D50] leading-relaxed">{aiReport.summary}</p>
            </div>

            {/* Evidence */}
            {aiReport.evidence && aiReport.evidence.length > 0 && (
              <div className="bg-white rounded-2xl p-8 border border-[#D4C4B0]">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-[#DC5037]/10 rounded-lg flex items-center justify-center">
                    <AlertTriangle className="w-5 h-5 text-[#DC5037]" />
                  </div>
                  <h2 className="text-xl font-bold text-[#023D50]">Indicators of Compromise</h2>
                </div>
                <ul className="space-y-2">
                  {aiReport.evidence.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-3 p-3 bg-[#FFF8F0] rounded-lg">
                      <Target className="w-4 h-4 text-[#DC5037] mt-0.5 flex-shrink-0" />
                      <span className="text-[#023D50]">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Techniques */}
            {aiReport.techniques && aiReport.techniques.length > 0 && (
              <div className="bg-white rounded-2xl p-8 border border-[#D4C4B0]">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-[#023D50]/10 rounded-lg flex items-center justify-center">
                    <Activity className="w-5 h-5 text-[#023D50]" />
                  </div>
                  <h2 className="text-xl font-bold text-[#023D50]">Attack Techniques (MITRE ATT&CK)</h2>
                </div>
                <div className="flex flex-wrap gap-2">
                  {aiReport.techniques.map((technique, idx) => (
                    <span
                      key={idx}
                      className="px-3 py-1.5 bg-[#023D50]/10 text-[#023D50] rounded-lg text-sm font-medium"
                    >
                      {technique}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Recommended Actions */}
            {aiReport.recommended_actions && aiReport.recommended_actions.length > 0 && (
              <div className="bg-white rounded-2xl p-8 border border-[#D4C4B0]">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-[#16A085]/10 rounded-lg flex items-center justify-center">
                    <Shield className="w-5 h-5 text-[#16A085]" />
                  </div>
                  <h2 className="text-xl font-bold text-[#023D50]">Recommended Actions</h2>
                </div>
                <ul className="space-y-2">
                  {aiReport.recommended_actions.map((action, idx) => (
                    <li key={idx} className="flex items-start gap-3 p-3 bg-[#16A085]/5 rounded-lg">
                      <CheckCircle className="w-4 h-4 text-[#16A085] mt-0.5 flex-shrink-0" />
                      <span className="text-[#023D50]">{action}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </motion.div>
        )}

        {/* Events Timeline */}
        {report.events && report.events.length > 0 && (
          <motion.div {...fadeInUp} transition={{ delay: 0.2 }} className="bg-white rounded-2xl p-8 border border-[#D4C4B0] mt-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 bg-[#F39C12]/10 rounded-lg flex items-center justify-center">
                <Clock className="w-5 h-5 text-[#F39C12]" />
              </div>
              <h2 className="text-xl font-bold text-[#023D50]">Event Timeline</h2>
              <span className="px-2 py-1 bg-[#456A77]/10 text-[#456A77] text-xs font-medium rounded-full">
                {report.events.length} events
              </span>
            </div>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {report.events.map((event) => (
                <div key={event.id} className="p-4 bg-[#FFF8F0] rounded-lg border border-[#D4C4B0]">
                  <div className="flex items-center justify-between mb-2">
                    <code className="text-sm font-mono text-[#023D50]">
                      {event.method} {event.path}
                    </code>
                    <span className="text-xs text-[#456A77]">{formatTimestamp(event.timestamp)}</span>
                  </div>
                  <div className="flex flex-wrap gap-2 text-xs">
                    <span className="px-2 py-1 bg-white rounded text-[#456A77]">IP: {event.ip}</span>
                    {event.honeypot_key_used && (
                      <span className="px-2 py-1 bg-[#DC5037]/10 text-[#DC5037] rounded">Honeypot Key Used</span>
                    )}
                    {event.auth_present && (
                      <span className="px-2 py-1 bg-[#E09B3D]/10 text-[#E09B3D] rounded">Auth Present</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
