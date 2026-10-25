import React, { useState, useEffect } from 'react';
import {
  Settings,
  ShieldCheck,
  ShieldAlert,
  Server,
  Terminal,
  FileText,
  Lock,
  Globe,
  RefreshCw,
  ExternalLink,
  Cpu,
  Layers,
  Database
} from 'lucide-react';
import { api } from '../services/api';
import AlertBanner from '../components/AlertBanner';

export default function SettingsInfo() {
  const [health, setHealth] = useState(null);
  const [testingConnection, setTestingConnection] = useState(false);
  const [pingResult, setPingResult] = useState(null);

  const testBackendConnection = async () => {
    setTestingConnection(true);
    setPingResult(null);
    const start = performance.now();
    try {
      const data = await api.getHealth();
      const duration = (performance.now() - start).toFixed(1);
      setHealth(data);
      setPingResult({
        success: true,
        latency: `${duration} ms`,
        status: data.status,
        modelReady: data.model_ready,
      });
    } catch (err) {
      setPingResult({
        success: false,
        error: err.message,
      });
    } finally {
      setTestingConnection(false);
    }
  };

  useEffect(() => {
    testBackendConnection();
  }, []);

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Title */}
      <div className="pb-2 border-b border-white/5">
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
          <Settings className="w-6 h-6 text-red-500" />
          Settings & Architecture Overview
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          System operational configurations, threat model specifications, and security design principles.
        </p>
      </div>

      {/* Backend API Configuration & Health Ping */}
      <div className="cyber-card p-6 rounded-2xl border border-white/10 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">API Service Connectivity</h3>
            <p className="text-xs text-slate-400">
              Connection to the FastAPI analysis engine and SQLite database.
            </p>
          </div>

          <button
            onClick={testBackendConnection}
            disabled={testingConnection}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${testingConnection ? 'animate-spin' : ''}`} />
            {testingConnection ? 'Testing...' : 'Test Connection'}
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5">
            <span className="text-slate-500 block text-[10px] uppercase">Base Endpoint</span>
            <span className="text-cyan-300 mt-1 block truncate">
              {import.meta.env.VITE_API_BASE_URL || '/api (Vite Proxy: :8000)'}
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5">
            <span className="text-slate-500 block text-[10px] uppercase">Service Status</span>
            <span
              className={`mt-1 font-semibold flex items-center gap-1.5 ${
                pingResult?.success ? 'text-emerald-400' : 'text-red-400'
              }`}
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  pingResult?.success ? 'bg-emerald-400' : 'bg-red-400'
                }`}
              />
              {pingResult ? (pingResult.success ? 'Online & Healthy' : 'Unreachable') : 'Probing...'}
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5">
            <span className="text-slate-500 block text-[10px] uppercase">Round-trip Latency</span>
            <span className="text-slate-200 mt-1 block">
              {pingResult?.latency || 'N/A'}
            </span>
          </div>
        </div>

        {pingResult && !pingResult.success && (
          <AlertBanner
            type="safety"
            title="Backend Offline Warning"
            message={`Connection failed: ${pingResult.error}. Please ensure the backend server is running via "uvicorn app.main:app --port 8000".`}
          />
        )}
      </div>

      {/* Defensive Threat Model Philosophy */}
      <div className="cyber-card p-6 rounded-2xl border border-white/10 space-y-4">
        <h3 className="text-sm font-semibold text-white">Defensive Architecture & Safety Philosophy</h3>
        
        <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
          <p>
            <strong className="text-white">Strict 100% Offline Static URL Analysis:</strong> Unlike conventional web scanners that initiate HTTP requests or render pages in a headless browser, this defensive platform analyzes URL strings purely through lexical and structural feature extraction.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-white/5">
              <span className="font-semibold text-white block mb-1">
                Zero Malicious Code Execution
              </span>
              <p className="text-[11px] text-slate-400">
                Never downloads malicious binaries, executes JavaScript zero-days, or renders exploit kits on security analyst workstations.
              </p>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-white/5">
              <span className="font-semibold text-white block mb-1">
                Zero Attacker Telemetry Burn
              </span>
              <p className="text-[11px] text-slate-400">
                Attackers cannot detect that their lure URL is being investigated. Unique tracking tokens in queries are never fetched or activated.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Dataset Provenance & Standards */}
      <div className="cyber-card p-6 rounded-2xl border border-white/10 space-y-3">
        <h3 className="text-sm font-semibold text-white">Dataset Provenance & Rigor</h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          Our machine learning pipeline is trained on verified threat telemetry and high-reputation domain distributions:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5">
            <span className="text-red-400 font-bold block mb-1">PhishTank Feed</span>
            <span className="text-slate-400 text-[11px]">
              Community-verified phishing URLs with verified credential harvesting targets.
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5">
            <span className="text-emerald-400 font-bold block mb-1">Tranco Top 1M</span>
            <span className="text-slate-400 text-[11px]">
              Research-grade hardened ranking of benign legitimate internet domains.
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5">
            <span className="text-cyan-400 font-bold block mb-1">Zero-Leakage Hash</span>
            <span className="text-slate-400 text-[11px]">
              Cryptographic SHA-256 validation ensuring zero overlap between train, val, and test splits.
            </span>
          </div>
        </div>
      </div>

      {/* Environment & Installation Info */}
      <div className="cyber-card p-6 rounded-2xl border border-white/10 space-y-3">
        <h3 className="text-sm font-semibold text-white">Local Run Commands</h3>
        <div className="space-y-2 text-xs font-mono">
          <div className="p-3 rounded-xl bg-black/60 border border-white/5 text-slate-300">
            <span className="text-slate-500 block text-[10px] uppercase font-sans mb-1">Start Backend (FastAPI)</span>
            <code>cd backend &amp;&amp; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload</code>
          </div>
          <div className="p-3 rounded-xl bg-black/60 border border-white/5 text-slate-300">
            <span className="text-slate-500 block text-[10px] uppercase font-sans mb-1">Start Frontend (Vite)</span>
            <code>cd frontend &amp;&amp; npm run dev</code>
          </div>
          <div className="p-3 rounded-xl bg-black/60 border border-white/5 text-slate-300">
            <span className="text-slate-500 block text-[10px] uppercase font-sans mb-1">Run Frontend Tests</span>
            <code>cd frontend &amp;&amp; npm test</code>
          </div>
        </div>
      </div>

      {/* Safety Notice */}
      <AlertBanner
        type="safety"
        title="Operational Security Disclaimer"
        message="This application is intended strictly for defensive security research, incident response triage, and educational risk assessment. Automated models may produce false positives or false negatives."
      />
    </div>
  );
}
