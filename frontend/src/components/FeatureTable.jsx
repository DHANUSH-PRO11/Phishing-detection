import React, { useState } from 'react';
import { Search, Flag, CheckCircle2, ChevronRight, HelpCircle } from 'lucide-react';

export default function FeatureTable({ featureDetails = [] }) {
  const [filter, setFilter] = useState('');
  const [onlyFlagged, setOnlyFlagged] = useState(false);

  const filtered = featureDetails.filter((item) => {
    const matchesText =
      item.name.toLowerCase().includes(filter.toLowerCase()) ||
      item.description.toLowerCase().includes(filter.toLowerCase());
    const matchesFlag = onlyFlagged ? item.is_flagged : true;
    return matchesText && matchesFlag;
  });

  return (
    <div className="cyber-card rounded-2xl overflow-hidden border border-white/10">
      {/* Header & Controls */}
      <div className="p-4 sm:p-5 border-b border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-white">Extracted URL Features</h3>
          <p className="text-xs text-slate-400">
            Evaluating {featureDetails.length} lexical, structural, and statistical dimensions offline.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search features..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="bg-slate-900/80 border border-white/10 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500/50 w-44"
            />
          </div>

          {/* Toggle Flagged */}
          <button
            onClick={() => setOnlyFlagged(!onlyFlagged)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border flex items-center gap-1.5 transition-colors ${
              onlyFlagged
                ? 'bg-red-500/20 text-red-300 border-red-500/40'
                : 'bg-slate-800/40 text-slate-400 border-white/10 hover:bg-white/5'
            }`}
          >
            <Flag className="w-3.5 h-3.5 text-red-400" />
            Flagged Only
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/50 text-slate-400 border-b border-white/5 uppercase font-mono tracking-wider">
            <tr>
              <th className="py-3 px-4">Feature Name</th>
              <th className="py-3 px-4">Measurement</th>
              <th className="py-3 px-4">Anomaly Flag</th>
              <th className="py-3 px-4">Threat Context & Description</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="4" className="py-8 text-center text-slate-500">
                  No features match your filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((item) => (
                <tr
                  key={item.name}
                  className={`hover:bg-white/[0.02] transition-colors ${
                    item.is_flagged ? 'bg-red-950/10' : ''
                  }`}
                >
                  <td className="py-3 px-4 font-mono font-medium text-slate-200">
                    {item.name}
                  </td>
                  <td className="py-3 px-4 font-mono text-cyan-300 font-semibold">
                    {typeof item.value === 'number' ? item.value.toFixed(item.value % 1 === 0 ? 0 : 3) : item.value}
                  </td>
                  <td className="py-3 px-4">
                    {item.is_flagged ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-950/80 text-red-300 border border-red-800/50">
                        <Flag className="w-3 h-3 text-red-400" />
                        {item.flag_reason || 'Anomaly'}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[11px] text-slate-500">
                        <CheckCircle2 className="w-3.5 h-3.5 text-slate-600" />
                        Normal
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-slate-400 max-w-md">
                    <div>
                      <span className="text-slate-300 block mb-0.5">{item.description}</span>
                      <span className="text-[11px] text-slate-500 block italic">
                        {item.threat_rationale}
                      </span>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
