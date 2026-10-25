import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  History,
  BrainCircuit,
  Settings,
  Search,
  Menu,
  X,
  RefreshCw
} from 'lucide-react';
import { api } from '../services/api';

export default function Navbar({ activePage, setActivePage }) {
  const [health, setHealth] = useState({ status: 'checking', model_ready: false });
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const fetchHealth = async () => {
    try {
      const data = await api.getHealth();
      setHealth(data);
    } catch {
      setHealth({ status: 'offline', model_ready: false });
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { id: 'dashboard', label: 'Overview', icon: Activity },
    { id: 'scanner', label: 'URL Scanner', icon: Search },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'model', label: 'Model & Metrics', icon: BrainCircuit },
    { id: 'settings', label: 'Settings & Docs', icon: Settings },
  ];

  return (
    <header className="sticky top-0 z-50 bg-cyber-900/90 backdrop-blur-md border-b border-white/10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo */}
          <div
            className="flex items-center gap-3 cursor-pointer"
            onClick={() => setActivePage('dashboard')}
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-600/30 to-red-950 flex items-center justify-center border border-red-500/30 shadow-lg shadow-red-500/10">
              <ShieldAlert className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg text-white tracking-tight">PhishShield</span>
                <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800/40">
                  ML Copilot
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">Defensive Cyber URL Analysis</p>
            </div>
          </div>

          {/* Desktop Nav Items */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActivePage(item.id)}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-red-500/15 text-red-300 border border-red-500/30 shadow-sm'
                      : 'text-slate-300 hover:text-white hover:bg-white/5'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-red-400' : 'text-slate-400'}`} />
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* System Health Status Indicator */}
          <div className="hidden sm:flex items-center gap-3">
            <div
              className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono border ${
                health.status === 'ok'
                  ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800/50'
                  : health.status === 'checking'
                  ? 'bg-slate-800/40 text-slate-300 border-slate-700/50'
                  : 'bg-red-950/40 text-red-300 border-red-800/50'
              }`}
              title="Backend & ML Model Health Status"
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  health.status === 'ok'
                    ? 'bg-emerald-400 animate-pulse'
                    : health.status === 'checking'
                    ? 'bg-amber-400'
                    : 'bg-red-500'
                }`}
              />
              <span className="capitalize">{health.status === 'ok' ? 'System Active' : health.status}</span>
            </div>
          </div>

          {/* Mobile menu trigger */}
          <div className="flex md:hidden">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-white/5"
              aria-label="Toggle Navigation Menu"
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-cyber-900 border-b border-white/10 px-4 pt-2 pb-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setActivePage(item.id);
                  setMobileMenuOpen(false);
                }}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium ${
                  isActive
                    ? 'bg-red-500/15 text-red-300 border border-red-500/30'
                    : 'text-slate-300 hover:bg-white/5'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-red-400' : 'text-slate-400'}`} />
                {item.label}
              </button>
            );
          })}
        </div>
      )}
    </header>
  );
}
