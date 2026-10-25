import React, { useState, useEffect } from 'react';
import {
  BrainCircuit,
  Award,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Scale,
  RefreshCw,
  Cpu,
  FileCode,
  ShieldAlert,
  Info
} from 'lucide-react';
import { api } from '../services/api';
import StatCard from '../components/StatCard';
import AlertBanner from '../components/AlertBanner';

export default function ModelInfo() {
  const [modelInfo, setModelInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchModelInfo = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getModelInfo();
      setModelInfo(data);
    } catch (err) {
      setError(err.message || 'Failed to fetch model metadata.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchModelInfo();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-slate-400">
        <RefreshCw className="w-8 h-8 animate-spin text-red-500 mb-4" />
        <p className="text-sm">Inspecting active model pipeline metadata...</p>
      </div>
    );
  }

  if (error || !modelInfo) {
    return (
      <div className="max-w-xl mx-auto py-12">
        <div className="cyber-card p-6 rounded-2xl border border-red-500/30 text-center">
          <ShieldAlert className="w-10 h-10 text-red-400 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-white mb-2">Model Pipeline Offline</h3>
          <p className="text-xs text-red-200/90 mb-5">{error || 'Could not load model information.'}</p>
          <button
            onClick={fetchModelInfo}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-red-600 text-white"
          >
            Retry Inspection
          </button>
        </div>
      </div>
    );
  }

  const metrics = modelInfo.test_metrics || {};
  const cm = metrics.confusion_matrix || {};
  const dataset = modelInfo.dataset_sizes || {};

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-white/5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <BrainCircuit className="w-6 h-6 text-red-500" />
            Machine Learning Model Intelligence
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Verified performance metrics, decision thresholds, and mathematical guarantees of the champion classifier.
          </p>
        </div>

        <button
          onClick={fetchModelInfo}
          className="p-2.5 rounded-xl bg-slate-900 border border-white/10 text-slate-400 hover:text-white hover:bg-white/5 self-start sm:self-auto"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Model Identity Card */}
      <div className="cyber-card p-6 rounded-2xl border border-white/10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block">
            Champion Architecture
          </span>
          <span className="text-base font-bold text-white mt-1 block">
            {modelInfo.model_name}
          </span>
          <span className="text-xs text-slate-400 mt-0.5 block font-mono">
            Algorithm: {modelInfo.algorithm}
          </span>
        </div>

        <div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block">
            Validation Optimal Threshold
          </span>
          <span className="text-base font-bold text-red-400 mt-1 block font-mono">
            τ* = {modelInfo.optimal_threshold}
          </span>
          <span className="text-xs text-slate-400 mt-0.5 block">
            Tuned strictly on validation split
          </span>
        </div>

        <div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block">
            Dataset Stratification
          </span>
          <span className="text-base font-bold text-slate-200 mt-1 block font-mono">
            {dataset.train_size || 0} / {dataset.val_size || 0} / {dataset.test_size || 0}
          </span>
          <span className="text-xs text-slate-400 mt-0.5 block">
            Train / Val / Test (zero leakage)
          </span>
        </div>

        <div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block">
            Feature Space Dimensions
          </span>
          <span className="text-base font-bold text-cyan-300 mt-1 block font-mono">
            {modelInfo.feature_count} Features
          </span>
          <span className="text-xs text-slate-400 mt-0.5 block">
            Offline lexical & structural
          </span>
        </div>
      </div>

      {/* Key Test Set Evaluation Metrics */}
      <div>
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
          Independent Test Set Evaluation Metrics
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          <StatCard
            title="Precision"
            value={metrics.precision !== undefined ? `${(metrics.precision * 100).toFixed(1)}%` : 'N/A'}
            subtitle="Phishing class reliability"
            color="red"
          />
          <StatCard
            title="Recall (Sensitivity)"
            value={metrics.recall !== undefined ? `${(metrics.recall * 100).toFixed(1)}%` : 'N/A'}
            subtitle="Detection of actual lures"
            color="red"
          />
          <StatCard
            title="F1-Score"
            value={metrics.f1 !== undefined ? `${(metrics.f1 * 100).toFixed(1)}%` : 'N/A'}
            subtitle="Harmonic mean balance"
            color="blue"
          />
          <StatCard
            title="ROC-AUC"
            value={metrics.roc_auc !== undefined ? metrics.roc_auc.toFixed(3) : 'N/A'}
            subtitle="Area under ROC curve"
            color="green"
          />
          <StatCard
            title="PR-AUC"
            value={metrics.pr_auc !== undefined ? metrics.pr_auc.toFixed(3) : 'N/A'}
            subtitle="Precision-Recall Area"
            color="amber"
          />
        </div>
      </div>

      {/* Confusion Matrix and Threshold Rationale */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix */}
        <div className="cyber-card p-6 rounded-2xl border border-white/10 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white mb-1">Empirical Confusion Matrix</h3>
            <p className="text-xs text-slate-400 mb-5">
              Evaluated on the held-out test split of real phishing and benign URLs.
            </p>

            <div className="grid grid-cols-2 gap-3 font-mono text-center">
              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/40">
                <span className="text-[10px] text-emerald-400 uppercase tracking-wider block mb-1">
                  True Negatives (TN)
                </span>
                <span className="text-2xl font-black text-white">
                  {cm.true_negatives ?? 0}
                </span>
                <span className="text-[11px] text-slate-400 block mt-1">Benign classified benign</span>
              </div>

              <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/40">
                <span className="text-[10px] text-amber-400 uppercase tracking-wider block mb-1">
                  False Positives (FP)
                </span>
                <span className="text-2xl font-black text-amber-300">
                  {cm.false_positives ?? 0}
                </span>
                <span className="text-[11px] text-slate-400 block mt-1">Benign misclassified phishing</span>
              </div>

              <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/50">
                <span className="text-[10px] text-red-400 uppercase tracking-wider block mb-1">
                  False Negatives (FN)
                </span>
                <span className="text-2xl font-black text-red-400">
                  {cm.false_negatives ?? 0}
                </span>
                <span className="text-[11px] text-slate-400 block mt-1">Phishing missed</span>
              </div>

              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/40">
                <span className="text-[10px] text-emerald-400 uppercase tracking-wider block mb-1">
                  True Positives (TP)
                </span>
                <span className="text-2xl font-black text-white">
                  {cm.true_positives ?? 0}
                </span>
                <span className="text-[11px] text-slate-400 block mt-1">Phishing caught</span>
              </div>
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-white/5 text-xs text-slate-400 flex items-center justify-between">
            <span>Accuracy: {metrics.accuracy ? `${(metrics.accuracy * 100).toFixed(1)}%` : 'N/A'}</span>
            <span>Zero-leakage SHA-256 partition verified</span>
          </div>
        </div>

        {/* Threshold Rationale & Decision Trade-offs */}
        <div className="cyber-card p-6 rounded-2xl border border-white/10 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white mb-1">Decision Threshold Rationale</h3>
            <p className="text-xs text-slate-400 mb-4">
              Mathematical justification for operating point selection.
            </p>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-white/5 text-xs text-slate-300 leading-relaxed space-y-3">
              <p>
                <strong className="text-white block mb-1">Operating Point (τ* = {modelInfo.optimal_threshold})</strong>
                {modelInfo.threshold_rationale ||
                  "Selected via validation grid search to optimize F1-score with balanced sensitivity. A central tie-breaking penalty favors τ = 0.50 over extreme boundaries to ensure resilient operational stability."}
              </p>
              <div className="pt-2 border-t border-white/5 text-[11px] text-slate-400">
                In defensive cybersecurity, the cost of a False Negative (allowing a credential harvester through) is typically higher than a False Positive (causing a user confirmation prompt).
              </div>
            </div>
          </div>

          {/* Environment Specs */}
          <div className="pt-4 mt-4 border-t border-white/5">
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 block mb-2">
              Model Artifact Environment
            </span>
            <div className="flex flex-wrap gap-2 text-xs font-mono">
              {Object.entries(modelInfo.environment || {}).map(([key, val]) => (
                <span
                  key={key}
                  className="px-2 py-1 rounded bg-black/40 border border-white/5 text-slate-300 text-[11px]"
                >
                  {key}: <span className="text-cyan-400">{val}</span>
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Feature Schema List */}
      <div className="cyber-card p-6 rounded-2xl border border-white/10">
        <h3 className="text-sm font-semibold text-white mb-1">
          Registered Feature Schema ({modelInfo.feature_count} Input Dimensions)
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          All lexical and structural dimensions ingested by the machine learning pipeline.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
          {modelInfo.feature_names?.map((feat, idx) => {
            const meta = modelInfo.features_metadata?.[feat];
            return (
              <div
                key={feat}
                className="p-3 rounded-xl bg-slate-900/60 border border-white/5 text-xs"
              >
                <div className="flex items-center gap-1.5 font-mono font-medium text-slate-200">
                  <span className="text-[10px] text-slate-500">{idx + 1}.</span>
                  <span className="text-cyan-300">{feat}</span>
                </div>
                {meta && (
                  <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                    {meta.description || meta}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Limitations Caveat */}
      <AlertBanner
        type="safety"
        title="ML Threat Model Boundaries & Limitations"
        message="This classifier functions entirely via offline URL string syntax and structural heuristics. It does not resolve dynamic DNS, render JavaScript, inspect DOM trees, or download payloads. Attackers utilizing zero-day brand homographs on legitimate infrastructure without lexical anomalies require defense-in-depth measures."
      />
    </div>
  );
}
