import React, { useState } from 'react';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Sparkles,
  ExternalLink,
  Lock,
  Layers,
  HelpCircle
} from 'lucide-react';
import { api } from '../services/api';
import AlertBanner from '../components/AlertBanner';
import RiskGauge from '../components/RiskGauge';

export default function UrlScanner({ onScanComplete, onViewDetails }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [validationError, setValidationError] = useState('');
  const [result, setResult] = useState(null);

  // Curated defensible examples for testing
  const sampleUrls = [
    {
      label: 'Legitimate Domain (HTTPS)',
      url: 'https://www.paypal.com/signin',
      type: 'legit',
    },
    {
      label: 'IP-Based Host Lure',
      url: 'http://192.168.1.100/paypal/security-verification/login.php',
      type: 'phish',
    },
    {
      label: 'Excessive Subdomain Brand Lure',
      url: 'https://paypal.account.verification.update.secureserver-alert.com/login',
      type: 'phish',
    },
    {
      label: 'Benign University Portal',
      url: 'https://cs.stanford.edu/people/faculty',
      type: 'legit',
    },
  ];

  const validateInput = (value) => {
    const trimmed = value.trim();
    if (!trimmed) {
      return 'Please enter a URL to analyze.';
    }
    if (trimmed.length < 3) {
      return 'URL is too short to be valid.';
    }
    if (trimmed.length > 2048) {
      return 'URL exceeds maximum permitted length of 2048 characters.';
    }
    const lower = trimmed.toLowerCase();
    if (lower.includes(':')) {
      const candidate = lower.split(':', 1)[0].trim();
      if (!candidate.includes('/') && candidate !== 'http' && candidate !== 'https') {
        return `Unsupported URI scheme "${candidate}". Only HTTP and HTTPS web URLs can be evaluated.`;
      }
    }
    // Check for empty destination host
    const stripped = trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '').split(/[/?#]/)[0].trim();
    if (!stripped) {
      return 'URL must include a valid destination hostname or domain.';
    }
    return '';
  };

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    setValidationError('');
    setError(null);

    const validation = validateInput(url);
    if (validation) {
      setValidationError(validation);
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const data = await api.scanUrl(url.trim());
      setResult(data);
      if (onScanComplete) {
        onScanComplete(data);
      }
    } catch (err) {
      setError(err.message || 'Scan evaluation failed. Please verify that the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectSample = (sampleUrl) => {
    setUrl(sampleUrl);
    setValidationError('');
    setError(null);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="text-center max-w-2xl mx-auto pt-2 pb-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-950/40 border border-red-800/40 text-red-400 text-xs font-mono mb-3">
          <Sparkles className="w-3.5 h-3.5" />
          100% Offline Static Feature Extraction
        </div>
        <h1 className="text-3xl font-black text-white tracking-tight sm:text-4xl">
          Cybersecurity URL Scanner
        </h1>
        <p className="text-sm text-slate-400 mt-2">
          Analyze suspicious URLs without navigating, resolving DNS, or executing code. 
          Extracts 29 lexical features and predicts phishing risk in real time.
        </p>
      </div>

      {/* Input Scanner Form */}
      <div className="cyber-card p-6 sm:p-8 rounded-3xl border border-white/10 shadow-2xl relative">
        <form onSubmit={handleScan} className="space-y-4">
          <label htmlFor="url-input" className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Target URL String
          </label>
          <div className="relative">
            <input
              id="url-input"
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (validationError) setValidationError('');
              }}
              placeholder="e.g., https://secure-login-account-update.example-domain.com/auth"
              className="w-full bg-slate-900/90 border border-white/10 rounded-2xl px-4 py-3.5 pr-32 text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:border-red-500/70 focus:ring-2 focus:ring-red-500/20 transition-all"
              disabled={loading}
              autoComplete="off"
              spellCheck="false"
            />
            <div className="absolute right-2 top-1/2 -translate-y-1/2">
              <button
                type="submit"
                disabled={loading}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold bg-red-600 hover:bg-red-500 disabled:bg-slate-800 disabled:text-slate-500 text-white shadow-lg shadow-red-600/30 transition-all"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    <span>Scan URL</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Validation Error Message */}
          {validationError && (
            <p className="text-xs text-red-400 font-medium flex items-center gap-1.5 mt-1.5">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              {validationError}
            </p>
          )}

          {/* Preset Samples */}
          <div className="pt-2">
            <span className="text-[11px] uppercase font-mono tracking-wider text-slate-500 block mb-2">
              Quick Test Samples:
            </span>
            <div className="flex flex-wrap gap-2">
              {sampleUrls.map((sample, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleSelectSample(sample.url)}
                  className={`text-xs px-3 py-1.5 rounded-lg border font-mono transition-colors text-left flex items-center gap-1.5 ${
                    sample.type === 'phish'
                      ? 'bg-red-950/30 text-red-300 border-red-800/30 hover:bg-red-950/60'
                      : 'bg-slate-900/60 text-slate-300 border-white/10 hover:bg-white/5'
                  }`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      sample.type === 'phish' ? 'bg-red-400' : 'bg-emerald-400'
                    }`}
                  />
                  {sample.label}
                </button>
              ))}
            </div>
          </div>
        </form>

        {/* Loading Indicator */}
        {loading && (
          <div className="mt-8 pt-6 border-t border-white/10 flex flex-col items-center justify-center py-6 text-center animate-pulse">
            <RefreshCw className="w-8 h-8 text-red-500 animate-spin mb-3" />
            <h4 className="text-sm font-semibold text-white">Extracting Lexical & Structural Features...</h4>
            <p className="text-xs text-slate-400 mt-1 max-w-sm">
              Parsing hostname, checking IP format, analyzing Shannon entropy, and querying model pipeline offline.
            </p>
          </div>
        )}

        {/* Backend Error Banner */}
        {error && (
          <div className="mt-6">
            <AlertBanner
              type="safety"
              title="Scan Request Failed"
              message={error}
            />
          </div>
        )}
      </div>

      {/* Result Overview (Shown upon scan completion) */}
      {result && !loading && (
        <div className="space-y-6 pt-2 animate-fadeIn">
          {/* Main Status & Risk Banner */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Risk Gauge */}
            <div className="md:col-span-1">
              <RiskGauge
                score={result.risk.final_risk_score}
                probability={result.risk.model_probability}
                category={result.risk.risk_category}
                threshold={result.risk.decision_threshold}
              />
            </div>

            {/* Assessment Verdict & Highlights */}
            <div className="md:col-span-2 cyber-card p-6 rounded-2xl border border-white/10 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between gap-3 mb-3">
                  <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                    Detection Status
                  </span>
                  <span className="text-xs font-mono text-slate-500">
                    ID: {result.scan_id ? result.scan_id.substring(0, 8) : 'N/A'}
                  </span>
                </div>

                <div className="flex items-center gap-3 mb-4">
                  {result.status === 'Potentially Phishing' ? (
                    <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400">
                      <ShieldAlert className="w-6 h-6" />
                    </div>
                  ) : result.status === 'Inconclusive' ? (
                    <div className="w-10 h-10 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400">
                      <HelpCircle className="w-6 h-6" />
                    </div>
                  ) : (
                    <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                      <ShieldCheck className="w-6 h-6" />
                    </div>
                  )}

                  <div>
                    <h2 className="text-xl font-bold text-white tracking-tight">
                      {result.status}
                    </h2>
                    <p className="text-xs text-slate-400 font-mono truncate max-w-md">
                      {result.normalized_url}
                    </p>
                  </div>
                </div>

                {/* Primary explanations count */}
                <div className="space-y-2 mt-4 text-xs">
                  {result.explanations?.slice(0, 2).map((exp, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-xl bg-slate-900/60 border border-white/5 flex items-start gap-2.5"
                    >
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold uppercase flex-shrink-0 mt-0.5 ${
                          exp.severity === 'CRITICAL' || exp.severity === 'HIGH'
                            ? 'bg-red-950/80 text-red-400 border border-red-800/40'
                            : exp.severity === 'MEDIUM'
                            ? 'bg-amber-950/80 text-amber-400 border border-amber-800/40'
                            : 'bg-blue-950/80 text-blue-400 border border-blue-800/40'
                        }`}
                      >
                        {exp.severity}
                      </span>
                      <div>
                        <span className="font-semibold text-slate-200 block">{exp.title}</span>
                        <span className="text-slate-400">{exp.message}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action Button to Full Details */}
              <div className="pt-5 mt-4 border-t border-white/5 flex items-center justify-between">
                <span className="text-xs text-slate-400">
                  {result.feature_details?.length || 29} feature dimensions analyzed
                </span>
                <button
                  onClick={() => onViewDetails(result.scan_id || result)}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 transition-colors"
                >
                  View Full Diagnostics & Features
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Mandatory Disclaimers */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <AlertBanner
              type="https"
              title="HTTPS Security Boundary Notice"
              message={result.https_analysis}
            />
            <AlertBanner
              type="safety"
              title="Automated ML Model Disclaimer"
              message={result.safety_disclaimer}
            />
          </div>
        </div>
      )}
    </div>
  );
}
