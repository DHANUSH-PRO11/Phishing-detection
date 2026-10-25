import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  ArrowRight,
  TrendingUp,
  RefreshCw,
  ExternalLink,
  Layers,
  Globe
} from 'lucide-react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Legend
} from 'recharts';
import { api } from '../services/api';
import StatCard from '../components/StatCard';
import EmptyState from '../components/EmptyState';

export default function OverviewDashboard({ onNavigateToScanner, onSelectScan }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getStats();
      setStats(data);
    } catch (err) {
      setError(err.message || 'Failed to load telemetry statistics from backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  if (loading && !stats) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-slate-400">
        <RefreshCw className="w-8 h-8 animate-spin text-red-500 mb-4" />
        <p className="text-sm">Connecting to backend telemetry engine...</p>
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="p-8 max-w-xl mx-auto">
        <div className="cyber-card p-6 rounded-2xl border border-red-500/30 bg-red-950/20 text-center">
          <ShieldAlert className="w-10 h-10 text-red-400 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-white mb-2">Backend Connection Error</h3>
          <p className="text-xs text-red-200/90 mb-5 leading-relaxed">{error}</p>
          <button
            onClick={fetchStats}
            className="px-4 py-2 rounded-xl text-xs font-medium bg-red-600 hover:bg-red-500 text-white transition-colors"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  const totalScans = stats?.total_scans || 0;
  const phishingRatio = totalScans > 0
    ? ((stats.phishing_detected_count / totalScans) * 100).toFixed(1)
    : 0;

  // Real Status Distribution for Recharts
  const statusPieData = stats?.status_distribution
    ? Object.entries(stats.status_distribution).map(([name, value]) => ({
        name,
        value,
      }))
    : [];

  const statusColorMap = {
    'Potentially Phishing': '#ef4444',
    'No Phishing Indicators Detected': '#10b981',
    'Inconclusive': '#f59e0b',
  };

  // Real Risk Category Data for Recharts BarChart
  const riskBarData = stats?.risk_category_distribution
    ? Object.entries(stats.risk_category_distribution).map(([cat, count]) => ({
        category: cat,
        count,
      }))
    : [];

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Action */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-white/5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-red-500" />
            Security Telemetry & Overview
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time aggregate telemetry from verified lexical and structural URL evaluations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchStats}
            title="Refresh statistics"
            className="p-2.5 rounded-xl bg-slate-900/80 border border-white/10 text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-red-400' : ''}`} />
          </button>
          <button
            onClick={onNavigateToScanner}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/20 transition-all hover:gap-3"
          >
            Scan Suspicious URL
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {totalScans === 0 ? (
        <EmptyState
          title="No URLs Scanned Yet"
          description="The local audit database is currently empty. Run your first URL scan to populate real telemetry and distribution charts."
          actionLabel="Launch URL Scanner"
          onAction={onNavigateToScanner}
        />
      ) : (
        <>
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              title="Total Scans Executed"
              value={totalScans.toLocaleString()}
              subtitle="All persisted offline analyses"
              icon={Layers}
              color="blue"
            />
            <StatCard
              title="Phishing URLs Detected"
              value={stats.phishing_detected_count.toLocaleString()}
              subtitle={`${phishingRatio}% of all recorded scans`}
              icon={ShieldAlert}
              color="red"
            />
            <StatCard
              title="Benign Verified"
              value={stats.legitimate_count.toLocaleString()}
              subtitle="No structural red flags found"
              icon={ShieldCheck}
              color="green"
            />
            <StatCard
              title="Average Risk Index"
              value={`${stats.average_risk_score.toFixed(1)} / 100`}
              subtitle={
                stats.inconclusive_count > 0
                  ? `${stats.inconclusive_count} inconclusive scans`
                  : 'Synthesized composite score'
              }
              icon={TrendingUp}
              color={stats.average_risk_score >= 60 ? 'red' : 'amber'}
            />
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Status Classification Distribution */}
            <div className="cyber-card p-5 rounded-2xl border border-white/10 flex flex-col justify-between">
              <div className="mb-4">
                <h3 className="text-sm font-semibold text-white">Classification Distribution</h3>
                <p className="text-xs text-slate-400">
                  Breakdown by primary prediction status ({totalScans} total samples).
                </p>
              </div>

              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={statusPieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={85}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {statusPieData.map((entry) => (
                        <Cell
                          key={`cell-${entry.name}`}
                          fill={statusColorMap[entry.name] || '#94a3b8'}
                          stroke="#07090e"
                          strokeWidth={2}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0c1017',
                        borderColor: 'rgba(255,255,255,0.1)',
                        borderRadius: '0.75rem',
                        fontSize: '12px',
                        color: '#f8fafc',
                      }}
                    />
                    <Legend
                      wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
                      formatter={(val) => <span className="text-slate-300">{val}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Risk Category Distribution */}
            <div className="cyber-card p-5 rounded-2xl border border-white/10 flex flex-col justify-between">
              <div className="mb-4">
                <h3 className="text-sm font-semibold text-white">Risk Tier Stratification</h3>
                <p className="text-xs text-slate-400">
                  Distribution across Low, Medium, High, and Critical risk tiers.
                </p>
              </div>

              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={riskBarData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis
                      dataKey="category"
                      stroke="#64748b"
                      fontSize={11}
                      tickLine={false}
                    />
                    <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0c1017',
                        borderColor: 'rgba(255,255,255,0.1)',
                        borderRadius: '0.75rem',
                        fontSize: '12px',
                        color: '#f8fafc',
                      }}
                    />
                    <Bar
                      dataKey="count"
                      fill="#ef4444"
                      radius={[6, 6, 0, 0]}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Bottom Grid: Recent Timeline & Top Flagged Domains */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Recent Scans (2 cols) */}
            <div className="lg:col-span-2 cyber-card p-5 rounded-2xl border border-white/10">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-white">Recent Telemetry Activity</h3>
                  <p className="text-xs text-slate-400">Latest evaluated URL requests</p>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/60 text-slate-400 uppercase font-mono tracking-wider border-b border-white/5">
                    <tr>
                      <th className="py-2.5 px-3">Domain</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Risk</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {stats.recent_scans_timeline?.slice(0, 5).map((scan) => (
                      <tr key={scan.scan_id} className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-3 px-3 font-mono font-medium text-slate-200 truncate max-w-xs">
                          {scan.domain || 'N/A'}
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                              scan.status === 'Potentially Phishing'
                                ? 'bg-red-950/80 text-red-300 border-red-800/40'
                                : scan.status === 'Inconclusive'
                                ? 'bg-amber-950/80 text-amber-300 border-amber-800/40'
                                : 'bg-emerald-950/80 text-emerald-300 border-emerald-800/40'
                            }`}
                          >
                            {scan.status}
                          </span>
                        </td>
                        <td className="py-3 px-3 font-mono">
                          <span
                            className={`font-semibold ${
                              scan.risk_score >= 60
                                ? 'text-red-400'
                                : scan.risk_score >= 30
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {scan.risk_score}
                          </span>
                          <span className="text-slate-500 text-[10px]">/100</span>
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button
                            onClick={() => onSelectScan(scan.scan_id)}
                            className="text-slate-400 hover:text-white inline-flex items-center gap-1 text-[11px] hover:underline"
                          >
                            Details
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Top Flagged Domains (1 col) */}
            <div className="cyber-card p-5 rounded-2xl border border-white/10">
              <div className="flex items-center gap-2 mb-4">
                <Globe className="w-4 h-4 text-red-400" />
                <div>
                  <h3 className="text-sm font-semibold text-white">Top Flagged Domains</h3>
                  <p className="text-xs text-slate-400">Most frequent phishing targets</p>
                </div>
              </div>

              {stats.top_flagged_domains?.length === 0 ? (
                <p className="text-xs text-slate-500 py-6 text-center">
                  No phishing domains flagged yet.
                </p>
              ) : (
                <div className="space-y-3">
                  {stats.top_flagged_domains?.slice(0, 6).map((item, idx) => (
                    <div
                      key={item.domain}
                      className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-white/5 text-xs"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <span className="font-mono text-slate-500 text-[11px] w-4">
                          {idx + 1}.
                        </span>
                        <span className="font-mono text-slate-200 truncate">{item.domain}</span>
                      </div>
                      <span className="font-mono px-2 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-800/40 text-[10px] font-semibold">
                        {item.count} flag{item.count > 1 ? 's' : ''}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
