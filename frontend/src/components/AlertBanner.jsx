import React from 'react';
import { AlertTriangle, Lock, Info, ShieldCheck } from 'lucide-react';

export default function AlertBanner({
  type = 'warning',
  title,
  message,
  className = '',
}) {
  const configs = {
    https: {
      icon: Lock,
      border: 'border-amber-500/30',
      bg: 'bg-amber-950/30',
      titleColor: 'text-amber-400',
      textColor: 'text-amber-200/90',
      iconColor: 'text-amber-400',
    },
    safety: {
      icon: AlertTriangle,
      border: 'border-red-500/30',
      bg: 'bg-red-950/20',
      titleColor: 'text-red-400',
      textColor: 'text-red-200/90',
      iconColor: 'text-red-400',
    },
    info: {
      icon: Info,
      border: 'border-cyan-500/30',
      bg: 'bg-cyan-950/20',
      titleColor: 'text-cyan-400',
      textColor: 'text-cyan-200/90',
      iconColor: 'text-cyan-400',
    },
    success: {
      icon: ShieldCheck,
      border: 'border-emerald-500/30',
      bg: 'bg-emerald-950/20',
      titleColor: 'text-emerald-400',
      textColor: 'text-emerald-200/90',
      iconColor: 'text-emerald-400',
    },
  };

  const c = configs[type] || configs.info;
  const Icon = c.icon;

  return (
    <div className={`p-4 rounded-xl border ${c.border} ${c.bg} ${className} flex items-start gap-3`}>
      <Icon className={`w-5 h-5 flex-shrink-0 mt-0.5 ${c.iconColor}`} />
      <div className="text-xs leading-relaxed">
        {title && <h4 className={`font-semibold mb-1 ${c.titleColor}`}>{title}</h4>}
        <p className={c.textColor}>{message}</p>
      </div>
    </div>
  );
}
