import React from 'react';
import { Database, SearchX, AlertCircle } from 'lucide-react';

export default function EmptyState({
  icon: Icon = Database,
  title = 'No Data Available',
  description = 'No records match your criteria yet.',
  actionLabel,
  onAction,
}) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center cyber-card rounded-2xl border border-white/5">
      <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center mb-4 text-slate-400">
        <Icon className="w-6 h-6" />
      </div>
      <h3 className="text-base font-semibold text-slate-200 mb-1">{title}</h3>
      <p className="text-xs text-slate-400 max-w-sm mb-5 leading-relaxed">{description}</p>
      {actionLabel && onAction && (
        <button
          onClick={onAction}
          className="px-4 py-2 rounded-xl text-xs font-medium bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 transition-colors"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}
