import React from 'react';

export default function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  color = 'slate',
}) {
  const colorMap = {
    red: {
      text: 'text-red-400',
      bg: 'bg-red-500/10',
      border: 'border-red-500/20',
      glow: 'shadow-red-500/5',
    },
    green: {
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
      glow: 'shadow-emerald-500/5',
    },
    amber: {
      text: 'text-amber-400',
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/20',
      glow: 'shadow-amber-500/5',
    },
    blue: {
      text: 'text-cyan-400',
      bg: 'bg-cyan-500/10',
      border: 'border-cyan-500/20',
      glow: 'shadow-cyan-500/5',
    },
    slate: {
      text: 'text-slate-300',
      bg: 'bg-slate-800/40',
      border: 'border-white/10',
      glow: 'shadow-black/20',
    },
  };

  const c = colorMap[color] || colorMap.slate;

  return (
    <div className={`p-5 rounded-2xl cyber-card ${c.border} shadow-lg ${c.glow} flex flex-col justify-between`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          {title}
        </span>
        {Icon && (
          <div className={`p-2 rounded-xl ${c.bg} border ${c.border}`}>
            <Icon className={`w-4 h-4 ${c.text}`} />
          </div>
        )}
      </div>

      <div>
        <div className="flex items-baseline gap-2 mb-1">
          <span className="text-3xl font-bold font-mono tracking-tight text-white">
            {value}
          </span>
          {trend && (
            <span className="text-xs font-mono font-medium text-slate-400">
              {trend}
            </span>
          )}
        </div>
        {subtitle && (
          <p className="text-xs text-slate-400 font-normal">
            {subtitle}
          </p>
        )}
      </div>
    </div>
  );
}
