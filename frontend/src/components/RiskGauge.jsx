import React from 'react';
import { ShieldAlert, ShieldCheck, HelpCircle } from 'lucide-react';

export default function RiskGauge({ score = 0, probability = 0, category = 'Low Risk', threshold = 0.5 }) {
  const getTheme = () => {
    if (score >= 85) {
      return {
        color: 'text-red-400',
        bg: 'bg-red-500/10',
        border: 'border-red-500/30',
        bar: 'bg-red-500',
        glow: 'glow-red',
        icon: ShieldAlert,
      };
    }
    if (score >= 60) {
      return {
        color: 'text-orange-400',
        bg: 'bg-orange-500/10',
        border: 'border-orange-500/30',
        bar: 'bg-orange-500',
        glow: 'shadow-orange-500/20',
        icon: ShieldAlert,
      };
    }
    if (score >= 30) {
      return {
        color: 'text-amber-400',
        bg: 'bg-amber-500/10',
        border: 'border-amber-500/30',
        bar: 'bg-amber-500',
        glow: 'shadow-amber-500/20',
        icon: HelpCircle,
      };
    }
    return {
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      bar: 'bg-emerald-500',
      glow: 'glow-green',
      icon: ShieldCheck,
    };
  };

  const theme = getTheme();
  const Icon = theme.icon;

  return (
    <div className={`p-6 rounded-2xl cyber-card ${theme.border} relative overflow-hidden`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <Icon className={`w-5 h-5 ${theme.color}`} />
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Composite Risk Index</h3>
        </div>
        <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${theme.bg} ${theme.color} border ${theme.border}`}>
          {category}
        </span>
      </div>

      {/* Main Score Display */}
      <div className="flex items-baseline gap-2 mb-3">
        <span className={`text-5xl font-black font-mono tracking-tight ${theme.color}`}>
          {score}
        </span>
        <span className="text-slate-500 text-sm font-mono">/ 100</span>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-slate-800/80 rounded-full h-2.5 mb-4 overflow-hidden border border-white/5">
        <div
          className={`h-full rounded-full transition-all duration-700 ease-out ${theme.bar}`}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>

      {/* Secondary Metrics: Probability vs Threshold */}
      <div className="grid grid-cols-2 gap-3 pt-3 border-t border-white/5 text-xs">
        <div>
          <span className="text-slate-400 block mb-0.5">ML Probability</span>
          <span className="font-mono font-medium text-slate-200">
            {(probability * 100).toFixed(1)}%
          </span>
        </div>
        <div>
          <span className="text-slate-400 block mb-0.5">Decision Threshold</span>
          <span className="font-mono font-medium text-slate-200">
            {(threshold * 100).toFixed(0)}%
          </span>
        </div>
      </div>
    </div>
  );
}
