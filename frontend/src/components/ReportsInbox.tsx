import { useState, useEffect } from 'react';
import { Search, Filter, Calendar, FileText, AlertTriangle, Download, Clock, ChevronRight, RefreshCw } from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { getReports, type ReportListItem } from '../services/api';

const fadeInUp = {
  initial: { opacity: 0, y: 60 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { margin: "-50px" },
  transition: { duration: 0.4, ease: "easeOut" }
};

const staggerContainer = {
  initial: {},
  whileInView: { transition: { staggerChildren: 0.1 } },
  viewport: { margin: "-50px" }
};

export function ReportsInbox() {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [reports, setReports] = useState<ReportListItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadReports() {
      try {
        const data = await getReports();
        setReports(data);
      } catch (error) {
        console.error('Failed to load reports:', error);
      } finally {
        setLoading(false);
      }
    }
    loadReports();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-[#DC5037] bg-[#DC5037]/20 border-[#DC5037]/30';
      case 'high':
        return 'text-[#E09B3D] bg-[#E09B3D]/20 border-[#E09B3D]/30';
      case 'medium':
        return 'text-[#F39C12] bg-[#F39C12]/20 border-[#F39C12]/30';
      case 'low':
        return 'text-[#16A085] bg-[#16A085]/20 border-[#16A085]/30';
      default:
        return 'text-[#456A77] bg-[#456A77]/20 border-[#456A77]/30';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'new':
        return 'text-[#16A085] bg-[#16A085]/20';
      case 'reviewed':
        return 'text-[#E09B3D] bg-[#E09B3D]/20';
      case 'archived':
        return 'text-[#456A77] bg-[#456A77]/20';
      default:
        return 'text-[#456A77] bg-[#456A77]/20';
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const filteredReports = reports.filter(report => {
    const matchesSearch = report.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         report.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         report.summary.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = filterSeverity === 'all' || report.severity === filterSeverity;
    const matchesStatus = filterStatus === 'all' || report.status === filterStatus;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  if (loading) {
    return (
      <div className="min-h-screen bg-[#FBEAD2] py-12 px-4 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-12 h-12 text-[#E09B3D] animate-spin mx-auto mb-4" />
          <p className="text-[#023D50] text-lg">Loading reports...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#FBEAD2] py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-8"
        >
          <h1 className="text-4xl font-bold mb-2 text-[#023D50]">SOC Reports Inbox</h1>
          <p className="text-[#456A77] text-lg">AI-generated security incident reports and analysis</p>
        </motion.div>

        {/* Stats Bar */}
        <motion.div 
          variants={staggerContainer}
          initial="initial"
          animate="whileInView"
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8"
        >
          {[
            { icon: FileText, label: 'Total Reports', value: reports.length, color: 'text-[#E09B3D]' },
            { icon: AlertTriangle, label: 'New Reports', value: reports.filter(r => r.status === 'new').length, color: 'text-[#16A085]' },
            { icon: AlertTriangle, label: 'Critical/High', value: reports.filter(r => r.severity === 'critical' || r.severity === 'high').length, color: 'text-[#DC5037]' },
            { icon: Calendar, label: 'This Week', value: reports.filter(r => new Date(r.generated_date) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).length, color: 'text-[#E09B3D]' },
          ].map((stat, i) => (
            <motion.div 
              key={i}
              variants={fadeInUp}
              whileHover={{ y: -2, transition: { duration: 0.2 } }}
              className="bg-white rounded-lg p-4 border border-[#D4C4B0] hover:border-[#E09B3D] transition-all"
            >
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm text-[#456A77] mb-1">{stat.label}</div>
                  <div className={`text-2xl font-bold ${stat.color === 'text-[#DC5037]' ? 'text-[#DC5037]' : stat.color === 'text-[#16A085]' ? 'text-[#16A085]' : 'text-[#023D50]'}`}>
                    {stat.value}
                  </div>
                </div>
                <stat.icon className={`w-8 h-8 ${stat.color} opacity-50`} />
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Filters */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="bg-white rounded-lg p-6 mb-6 border border-[#D4C4B0]"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#456A77]" />
              <input
                type="text"
                placeholder="Search reports..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-white border border-[#D4C4B0] rounded-lg text-[#023D50] placeholder-[#456A77]/50 focus:outline-none focus:border-[#E09B3D] transition-colors"
              />
            </div>

            {/* Severity Filter */}
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#456A77]" />
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-white border border-[#D4C4B0] rounded-lg text-[#023D50] focus:outline-none focus:border-[#E09B3D] transition-colors appearance-none cursor-pointer"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            {/* Status Filter */}
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#456A77]" />
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-white border border-[#D4C4B0] rounded-lg text-[#023D50] focus:outline-none focus:border-[#E09B3D] transition-colors appearance-none cursor-pointer"
              >
                <option value="all">All Statuses</option>
                <option value="new">New</option>
                <option value="reviewed">Reviewed</option>
                <option value="archived">Archived</option>
              </select>
            </div>
          </div>
        </motion.div>

        {/* Reports List */}
        <motion.div 
          variants={staggerContainer}
          initial="initial"
          whileInView="whileInView"
          viewport={{ margin: "-50px" }}
          className="space-y-4"
        >
          {filteredReports.length === 0 ? (
            <motion.div 
              variants={fadeInUp}
              className="bg-white rounded-lg p-12 text-center border border-[#D4C4B0]"
            >
              <FileText className="w-16 h-16 text-[#456A77]/30 mx-auto mb-4" />
              <h3 className="text-xl font-semibold mb-2 text-[#023D50]">No Reports Found</h3>
              <p className="text-[#456A77]">Try adjusting your search or filter criteria</p>
            </motion.div>
          ) : (
            filteredReports.map((report) => (
              <motion.div 
                key={report.id}
                variants={fadeInUp}
                whileHover={{ scale: 1.01, transition: { duration: 0.2 } }}
                className="bg-white rounded-lg p-6 hover:border-[#E09B3D] transition-all group border border-[#D4C4B0]"
              >
                <div className="flex items-start justify-between gap-4 mb-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2 flex-wrap">
                      <span className="text-lg font-semibold text-[#023D50]">RPT-{report.incident_id}</span>
                      <span className={`px-3 py-1 rounded-full text-xs font-medium uppercase border ${getSeverityColor(report.severity)}`}>
                        {report.severity}
                      </span>
                      <span className={`px-3 py-1 rounded-full text-xs font-medium uppercase ${getStatusColor(report.status)}`}>
                        {report.status}
                      </span>
                      {report.status === 'new' && (
                        <span className="flex items-center gap-1 text-xs text-[#16A085]">
                          <div className="w-2 h-2 bg-[#16A085] rounded-full animate-pulse"></div>
                          Unread
                        </span>
                      )}
                    </div>
                    <h3 className="text-xl font-semibold mb-2 text-[#023D50]">{report.title}</h3>
                    <p className="text-[#456A77] text-sm mb-3">{report.summary}</p>
                    
                    <div className="flex items-center gap-6 text-sm text-[#456A77] flex-wrap">
                      <div className="flex items-center gap-2">
                        <Calendar className="w-4 h-4" />
                        <span>Generated: {formatDate(report.generated_date)}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4" />
                        <span>{report.event_count} event{report.event_count !== 1 ? 's' : ''}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Clock className="w-4 h-4" />
                        <span>IP: {report.source_ip}</span>
                      </div>
                    </div>
                  </div>

                  <motion.div 
                    whileHover={{ scale: 1.1 }}
                    className="flex flex-col gap-2"
                  >
                    <button className="p-2 bg-white border border-[#D4C4B0] hover:border-[#E09B3D] hover:bg-[#FFF8F0] rounded-lg transition-colors">
                      <Download className="w-4 h-4 text-[#456A77]" />
                    </button>
                  </motion.div>
                </div>

                <div className="flex items-center gap-3 pt-4 border-t border-[#D4C4B0]">
                  <Link
                    to={`/reports/${report.id}`}
                    className="flex items-center gap-2 px-4 py-2 bg-white border border-[#D4C4B0] hover:bg-[#E09B3D] hover:border-[#E09B3D] hover:text-white rounded-lg text-sm transition-all group/btn"
                  >
                    <FileText className="w-4 h-4" />
                    View Report
                    <ChevronRight className="w-4 h-4 group-hover/btn:translate-x-1 transition-transform" />
                  </Link>
                </div>
              </motion.div>
            ))
          )}
        </motion.div>
      </div>
    </div>
  );
}