import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Filter,
  Trash2,
  Download,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  ExternalLink,
  RefreshCw,
  AlertTriangle,
  X,
  ShieldAlert,
  ShieldCheck,
  HelpCircle
} from 'lucide-react';
import { api } from '../services/api';
import EmptyState from '../components/EmptyState';

export default function ScanHistory({ onSelectScan, onNavigateToScanner }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [riskCategoryFilter, setRiskCategoryFilter] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState('desc');

  // Deletion Modal state
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getHistory({
        page,
        size: pageSize,
        search,
        status: statusFilter,
        risk_category: riskCategoryFilter,
        sort_by: sortBy,
        sort_order: sortOrder,
      });
      setItems(res.items || []);
      setTotal(res.total || 0);
      setPages(res.pages || 1);
    } catch (err) {
      setError(err.message || 'Failed to load historical scan audit records.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [page, pageSize, statusFilter, riskCategoryFilter, sortBy, sortOrder]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchHistory();
  };

  const handleClearFilters = () => {
    setSearch('');
    setStatusFilter('');
    setRiskCategoryFilter('');
    setSortBy('created_at');
    setSortOrder('desc');
    setPage(1);
  };

  const handleConfirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.deleteScan(deleteTarget.scan_id);
      setDeleteTarget(null);
      // Refresh list
      fetchHistory();
    } catch (err) {
      alert(`Deletion failed: ${err.message}`);
    } finally {
      setDeleting(false);
    }
  };

  const exportCsvUrl = api.getExportCsvUrl({
    search,
    status: statusFilter,
    risk_category: riskCategoryFilter,
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-white/5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <History className="w-6 h-6 text-red-500" />
            Audit Scan History
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Persisted history of analyzed URLs, risk classifications, and threat assessments.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <a
            href={exportCsvUrl}
            download="phishing_scans_export.csv"
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-900 border border-white/10 text-slate-300 hover:text-white hover:bg-white/5 transition-colors"
            title="Export filtered records as CSV"
          >
            <Download className="w-4 h-4 text-slate-400" />
            Export CSV
          </a>
          <button
            onClick={fetchHistory}
            className="p-2 rounded-xl bg-slate-900 border border-white/10 text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
            title="Refresh history"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-red-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="cyber-card p-4 rounded-2xl border border-white/10 space-y-3">
        <form onSubmit={handleSearchSubmit} className="flex flex-col sm:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by URL string or domain..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-900/80 border border-white/10 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-red-500/50"
            />
          </div>

          {/* Status Filter */}
          <select
            aria-label="Filter by Status"
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-900/80 border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-red-500/50"
          >
            <option value="">All Statuses</option>
            <option value="Potentially Phishing">Potentially Phishing</option>
            <option value="No Phishing Indicators Detected">No Phishing Indicators</option>
            <option value="Inconclusive">Inconclusive</option>
          </select>

          {/* Risk Tier Filter */}
          <select
            aria-label="Filter by Risk Tier"
            value={riskCategoryFilter}
            onChange={(e) => {
              setRiskCategoryFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-900/80 border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-red-500/50"
          >
            <option value="">All Risk Tiers</option>
            <option value="Critical Risk">Critical Risk</option>
            <option value="High Risk">High Risk</option>
            <option value="Medium Risk">Medium Risk</option>
            <option value="Low Risk">Low Risk</option>
          </select>

          {/* Sort Field */}
          <select
            aria-label="Sort Order"
            value={`${sortBy}:${sortOrder}`}
            onChange={(e) => {
              const [field, order] = e.target.value.split(':');
              setSortBy(field);
              setSortOrder(order);
              setPage(1);
            }}
            className="bg-slate-900/80 border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-red-500/50 font-mono"
          >
            <option value="created_at:desc">Newest First</option>
            <option value="created_at:asc">Oldest First</option>
            <option value="risk_score:desc">Highest Risk</option>
            <option value="risk_score:asc">Lowest Risk</option>
            <option value="url:asc">URL (A-Z)</option>
          </select>

          <button
            type="submit"
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-red-600/30 hover:bg-red-600/40 text-red-300 border border-red-500/30 transition-colors"
          >
            Filter
          </button>
        </form>

        {(search || statusFilter || riskCategoryFilter) && (
          <div className="flex items-center justify-between text-xs pt-2 border-t border-white/5 text-slate-400">
            <span>
              Showing results for active filter filters ({total} matches)
            </span>
            <button
              onClick={handleClearFilters}
              className="text-red-400 hover:text-red-300 hover:underline flex items-center gap-1"
            >
              <X className="w-3.5 h-3.5" />
              Reset Filters
            </button>
          </div>
        )}
      </div>

      {/* Main Table */}
      <div className="cyber-card rounded-2xl border border-white/10 overflow-hidden">
        {loading && items.length === 0 ? (
          <div className="py-20 flex flex-col items-center justify-center text-slate-400">
            <RefreshCw className="w-8 h-8 animate-spin text-red-500 mb-3" />
            <p className="text-xs">Loading scan history...</p>
          </div>
        ) : items.length === 0 ? (
          <EmptyState
            title="No Scan Records Found"
            description={
              search || statusFilter || riskCategoryFilter
                ? 'No scans match your current filter parameters.'
                : 'No URLs have been audited yet.'
            }
            actionLabel={
              search || statusFilter || riskCategoryFilter
                ? 'Clear Filters'
                : 'Run a URL Scan'
            }
            onAction={
              search || statusFilter || riskCategoryFilter
                ? handleClearFilters
                : onNavigateToScanner
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 uppercase font-mono tracking-wider border-b border-white/5">
                <tr>
                  <th className="py-3 px-4">Domain / URL Target</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Risk Index</th>
                  <th className="py-3 px-4">Risk Category</th>
                  <th className="py-3 px-4">Date / Time</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {items.map((scan) => (
                  <tr
                    key={scan.scan_id}
                    className="hover:bg-white/[0.02] transition-colors cursor-pointer group"
                    onClick={() => onSelectScan(scan.scan_id)}
                  >
                    <td className="py-3 px-4 max-w-sm">
                      <div className="font-mono font-medium text-slate-200 truncate">
                        {scan.domain || 'N/A'}
                      </div>
                      <div className="text-[11px] text-slate-500 font-mono truncate max-w-xs group-hover:text-slate-400">
                        {scan.url}
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-semibold border ${
                          scan.status === 'Potentially Phishing'
                            ? 'bg-red-950/80 text-red-300 border-red-800/40'
                            : scan.status === 'Inconclusive'
                            ? 'bg-amber-950/80 text-amber-300 border-amber-800/40'
                            : 'bg-emerald-950/80 text-emerald-300 border-emerald-800/40'
                        }`}
                      >
                        {scan.status === 'Potentially Phishing' ? (
                          <ShieldAlert className="w-3 h-3 text-red-400" />
                        ) : scan.status === 'Inconclusive' ? (
                          <HelpCircle className="w-3 h-3 text-amber-400" />
                        ) : (
                          <ShieldCheck className="w-3 h-3 text-emerald-400" />
                        )}
                        {scan.status}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono font-bold">
                      <span
                        className={
                          scan.risk_score >= 60
                            ? 'text-red-400'
                            : scan.risk_score >= 30
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }
                      >
                        {scan.risk_score}
                      </span>
                      <span className="text-slate-500 font-normal text-[11px]">/100</span>
                    </td>

                    <td className="py-3 px-4">
                      <span className="text-slate-300 font-medium">
                        {scan.risk_category}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {new Date(scan.created_at).toLocaleDateString()}{' '}
                      <span className="text-slate-500">
                        {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => onSelectScan(scan.scan_id)}
                          className="px-2 py-1 rounded-lg bg-slate-800/60 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] font-medium transition-colors"
                        >
                          Details
                        </button>
                        <button
                          onClick={() => setDeleteTarget(scan)}
                          title="Delete this scan record"
                          className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-950/40 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {total > 0 && (
          <div className="p-4 border-t border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <span>Rows per page:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                className="bg-slate-900 border border-white/10 rounded-lg px-2 py-1 text-slate-200"
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
              </select>
              <span className="ml-2 font-mono">
                Showing {(page - 1) * pageSize + 1} - {Math.min(page * pageSize, total)} of {total} records
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="p-1.5 rounded-lg bg-slate-900 border border-white/10 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-white/5"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="font-mono text-slate-300 px-2">
                Page {page} of {pages}
              </span>
              <button
                disabled={page >= pages}
                onClick={() => setPage((p) => Math.min(pages, p + 1))}
                className="p-1.5 rounded-lg bg-slate-900 border border-white/10 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-white/5"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="cyber-card p-6 rounded-2xl border border-red-500/40 max-w-md w-full shadow-2xl animate-scaleIn">
            <div className="flex items-center gap-3 text-red-400 mb-3">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-base font-bold text-white">Confirm Record Deletion</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              Are you sure you want to permanently delete the audit record for:
            </p>
            <div className="p-3 rounded-xl bg-black/60 border border-white/5 font-mono text-xs text-red-300 break-all mb-5">
              {deleteTarget.url}
            </div>
            <div className="flex items-center justify-end gap-3">
              <button
                onClick={() => setDeleteTarget(null)}
                disabled={deleting}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDelete}
                disabled={deleting}
                className="px-4 py-2 rounded-xl text-xs font-semibold bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/30 transition-colors"
              >
                {deleting ? 'Deleting...' : 'Delete Permanently'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
