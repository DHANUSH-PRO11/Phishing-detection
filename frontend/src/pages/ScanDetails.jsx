import React, { useState, useEffect } from 'react';
import {
  ArrowLeft,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  ExternalLink,
  Code2,
  Cpu,
  Layers,
  HelpCircle,
  RefreshCw,
  Clock
} from 'lucide-react';
import { api } from '../services/api';
import RiskGauge from '../components/RiskGauge';
import AlertBanner from '../components/AlertBanner';
import FeatureTable from '../components/FeatureTable';

export default function ScanDetails({ scanIdOrData, onBack }) {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!scanIdOrData) return;

    if (typeof scanIdOrData === 'object' && scanIdOrData.url) {
      setScan(scanIdOrData);
      return;
    }

    // It's a string scan_id
    const fetchScanDetails = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getScanDetails(scanIdOrData);
        setScan(data);
      } catch (err) {
        setError(err.message || 'Failed to load scan details from database.');
      } finally {
        setLoading(false);
      }
    };

    fetchScanDetails();
  }, [scanIdOrData]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-slate-400">
        <RefreshCw className="w-8 h-8 animate-spin text-red-500 mb-4" />
        <p className="text-sm">Retrieving persisted scan telemetry...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-xl mx-auto py-12">
        <div className="cyber-card p-6 rounded-2xl border border-red-500/30 text-center">
          <ShieldAlert className="w-10 h-10 text-red-400 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-white mb-2">Scan Details Not Found</h3>
          <p className="text-xs text-red-200/90 mb-6">{error || 'The requested scan record does not exist.'}</p>
          <button
            onClick={onBack}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Previous View
          </button>
        </div>
      </div>
    );
  }

  // Normalize fields between /api/scan and /api/history/{id}
  const riskScore = scan.risk?.final_risk_score ?? scan.risk_score ?? 0;
  const probability = scan.risk?.model_probability ?? scan.model_probability ?? 0;
  const riskCategory = scan.risk?.risk_category ?? scan.risk_category ?? 'Unknown';
  const threshold = scan.risk?.decision_threshold ?? 0.5;
  const explanations = scan.explanations || [];
  const components = scan.components || {};

  // Build feature_details list if not already present
  const featureDetails = scan.feature_details || (
    scan.features
      ? Object.entries(scan.features).map(([name, val]) => ({
          name,
          value: val,
          description: `Extracted lexical/structural measurement for ${name}`,
          threat_rationale: 'Observed URL pattern dimension.',
          is_flagged: val > 0 && ['has_ip_address', 'has_at_symbol', 'is_punycode', 'is_url_shortener', 'has_suspicious_tld'].includes(name),
          flag_reason: 'Flagged structural indicator',
        }))
      : []
  );

  return (
    <div className="space-y-6">
      {/* Top Nav Back & Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-white/5">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-xl bg-slate-900 border border-white/10 text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
            title="Go Back"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white tracking-tight">Security Diagnostic Dossier</h1>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-white/10">
                {scan.scan_id ? scan.scan_id.substring(0, 8) : 'ACTIVE'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Comprehensive offline static analysis and model explanations
            </p>
          </div>
        </div>

        {scan.created_at && (
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
            <Clock className="w-3.5 h-3.5 text-slate-500" />
            <span>Recorded: {new Date(scan.created_at).toLocaleString()}</span>
          </div>
        )}
      </div>

      {/* URL Banner */}
      <div className="p-4 sm:p-5 rounded-2xl cyber-card border border-white/10">
        <span className="text-[11px] uppercase font-mono tracking-wider text-slate-400 block mb-1">
          Analyzed URL Target
        </span>
        <div className="font-mono text-sm sm:text-base text-cyan-300 break-all bg-black/40 p-3 rounded-xl border border-white/5 select-all">
          {scan.url}
        </div>
      </div>

      {/* Risk Gauge & Verdict Card */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-1">
          <RiskGauge
            score={riskScore}
            probability={probability}
            category={riskCategory}
            threshold={threshold}
          />
        </div>

        <div className="md:col-span-2 cyber-card p-6 rounded-2xl border border-white/10 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                Evaluation Classification
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-white/5 text-slate-300 border border-white/10">
                Engine: {scan.model_name || 'Champion ML Pipeline'}
              </span>
            </div>

            <div className="flex items-center gap-3.5 mb-5">
              {scan.status === 'Potentially Phishing' ? (
                <div className="w-12 h-12 rounded-2xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 flex-shrink-0">
                  <ShieldAlert className="w-7 h-7" />
                </div>
              ) : scan.status === 'Inconclusive' ? (
                <div className="w-12 h-12 rounded-2xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 flex-shrink-0">
                  <HelpCircle className="w-7 h-7" />
                </div>
              ) : (
                <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 flex-shrink-0">
                  <ShieldCheck className="w-7 h-7" />
                </div>
              )}

              <div>
                <h2 className="text-2xl font-black text-white tracking-tight">{scan.status}</h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  ML probability {(probability * 100).toFixed(1)}% vs validation decision threshold {(threshold * 100).toFixed(0)}%
                </p>
              </div>
            </div>

            {/* Formula Documentation */}
            {scan.risk?.formula_documentation && (
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-white/5 text-xs text-slate-300">
                <span className="font-mono text-[11px] text-red-400 uppercase font-semibold block mb-1">
                  Synthesized Risk Formula
                </span>
                <p className="font-mono text-slate-300 leading-relaxed text-[11px]">
                  {scan.risk.formula_documentation}
                </p>
              </div>
            )}
          </div>

          <div className="pt-4 mt-4 border-t border-white/5 flex items-center justify-between text-xs text-slate-400">
            <span>Heuristic red-flag penalty: +{scan.risk?.heuristic_penalty ?? 0} pts</span>
            <span>Zero external network calls made</span>
          </div>
        </div>
      </div>

      {/* URL Structural Decomposition */}
      <div className="cyber-card p-6 rounded-2xl border border-white/10">
        <h3 className="text-sm font-semibold text-white mb-1">URL Structural Decomposition</h3>
        <p className="text-xs text-slate-400 mb-4">
          RFC 3986 lexical hierarchy extracted with urllib and public suffix registry.
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 text-xs">
          <div className="p-3 rounded-xl bg-slate-900/70 border border-white/5">
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Scheme</span>
            <span className="font-mono font-medium text-slate-200 mt-1 block truncate">
              {components.scheme || 'N/A'}
            </span>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/70 border border-white/5">
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Subdomain</span>
            <span className="font-mono font-medium text-slate-200 mt-1 block truncate" title={components.subdomain}>
              {components.subdomain || '(none)'}
            </span>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/70 border border-white/5">
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Domain</span>
            <span className="font-mono font-medium text-slate-200 mt-1 block truncate" title={components.domain}>
              {components.domain || 'N/A'}
            </span>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/70 border border-white/5">
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Public Suffix</span>
            <span className="font-mono font-medium text-slate-200 mt-1 block truncate">
              {components.suffix || 'N/A'}
            </span>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/70 border border-white/5">
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Port</span>
            <span className="font-mono font-medium text-slate-200 mt-1 block truncate">
              {components.netloc?.includes(':') ? components.netloc.split(':')[1] : '(default)'}
            </span>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/70 border border-white/5 sm:col-span-2">
            <span className="text-slate-500 block text-[10px] uppercase font-mono">Path</span>
            <span className="font-mono font-medium text-slate-200 mt-1 block truncate" title={components.path}>
              {components.path || '/'}
            </span>
          </div>
        </div>
      </div>

      {/* Security Findings & Explanations */}
      <div className="cyber-card p-6 rounded-2xl border border-white/10 space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-white">Explainable Security Findings</h3>
          <p className="text-xs text-slate-400">
            Human-readable findings detailing detected deceptive tactics and structural anomalies.
          </p>
        </div>

        {explanations.length === 0 ? (
          <p className="text-xs text-slate-500 py-4 text-center">
            No specific security findings triggered for this URL.
          </p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {explanations.map((exp, idx) => {
              const isHigh = exp.severity === 'CRITICAL' || exp.severity === 'HIGH';
              const isMed = exp.severity === 'MEDIUM';
              return (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border flex flex-col justify-between ${
                    isHigh
                      ? 'bg-red-950/20 border-red-800/40'
                      : isMed
                      ? 'bg-amber-950/20 border-amber-800/40'
                      : 'bg-slate-900/60 border-white/10'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-bold text-white">{exp.title}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border ${
                          isHigh
                            ? 'bg-red-950 text-red-400 border-red-700/50'
                            : isMed
                            ? 'bg-amber-950 text-amber-400 border-amber-700/50'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}
                      >
                        {exp.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed mb-2">
                      {exp.message}
                    </p>
                  </div>
                  {exp.threat_context && (
                    <div className="pt-2 border-t border-white/5 text-[11px] text-slate-400 italic">
                      Threat context: {exp.threat_context}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Feature Breakdown Table */}
      <FeatureTable featureDetails={featureDetails} />

      {/* Disclaimers */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <AlertBanner
          type="https"
          title="TLS/HTTPS Cryptographic Boundary"
          message={
            scan.https_analysis ||
            "HTTPS encrypts data in transit against eavesdropping, but over 80% of modern phishing sites employ valid TLS certificates. HTTPS does NOT verify that the domain is benign or trustworthy."
          }
        />
        <AlertBanner
          type="safety"
          title="Defensive Boundary & Safety Disclaimer"
          message={
            scan.safety_disclaimer ||
            "This assessment represents an automated machine learning prediction based exclusively on offline lexical and structural URL features. No automated classifier can provide an absolute guarantee of safety."
          }
        />
      </div>
    </div>
  );
}
