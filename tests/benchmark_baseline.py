"""
Granular Component Performance Profiler and Benchmark Suite.

Isolates and measures:
1. Pure ML model inference latency (predict_proba)
2. Pure URL lexical and structural feature extraction
3. Database insert, query, and aggregate statistics latency
4. Full ScannerService workflow (extraction + inference + risk calculation + explanations)
5. Memory usage and CPU timing statistics
"""

import time
import os
import sys
import gc
import json
import psutil
import numpy as np
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.ml.features import FeatureExtractor
from backend.app.ml.model_loader import load_model
from backend.app.services.scanner import scan_url
from backend.app.db.database import SessionLocal
from backend.app.db import crud

def compute_percentiles(durations_ms):
    arr = np.array(durations_ms)
    return {
        "count": len(arr),
        "mean": float(np.mean(arr)),
        "min": float(np.min(arr)),
        "p50": float(np.percentile(arr, 50)),
        "p90": float(np.percentile(arr, 90)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "max": float(np.max(arr)),
        "ops_per_sec": float(1000.0 / np.mean(arr)) if np.mean(arr) > 0 else 0.0,
    }

def run_benchmarks():
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / (1024 * 1024)
    cpu_start = process.cpu_percent(interval=None)

    print("=================================================================")
    print("PHISHSHIELD GRANULAR COMPONENT PERFORMANCE PROFILE")
    print("=================================================================")

    # 1. Measure Pure ML Model Inference
    artifacts = load_model()
    sample_features = {name: 1.0 for name in artifacts.feature_names}
    
    # Warm-up
    for _ in range(50):
        _ = artifacts.predict_features(sample_features)

    inference_times = []
    for _ in range(1000):
        t0 = time.perf_counter()
        _ = artifacts.predict_features(sample_features)
        inference_times.append((time.perf_counter() - t0) * 1000.0)

    inf_stats = compute_percentiles(inference_times)
    print("\n[1] PURE ML INFERENCE (1,000 iterations):")
    print(f"    Mean: {inf_stats['mean']:.3f} ms | Median (p50): {inf_stats['p50']:.3f} ms")
    print(f"    p90:  {inf_stats['p90']:.3f} ms | p95: {inf_stats['p95']:.3f} ms | p99: {inf_stats['p99']:.3f} ms")
    print(f"    Throughput: {inf_stats['ops_per_sec']:.1f} inferences/sec")

    # 2. Measure Pure Feature Extraction
    extractor = FeatureExtractor()
    test_urls = [
        "https://www.paypal.com/signin",
        "http://paypal.verification-secure-account-update.xyz/login.php?token=482910",
        "https://example.com/deep/path/catalog/item?session=abcdef1234567890&filter=category%3Dsecurity",
        "http://198.51.100.42/banking/update.html",
        "https://en.wikipedia.org/wiki/Phishing",
    ]

    # Warm-up
    for u in test_urls:
        _ = extractor.extract(u)

    feat_times = []
    for i in range(1000):
        u = test_urls[i % len(test_urls)]
        t0 = time.perf_counter()
        _ = extractor.extract(u)
        feat_times.append((time.perf_counter() - t0) * 1000.0)

    feat_stats = compute_percentiles(feat_times)
    print("\n[2] FEATURE EXTRACTION (1,000 iterations across 5 URL types):")
    print(f"    Mean: {feat_stats['mean']:.3f} ms | Median (p50): {feat_stats['p50']:.3f} ms")
    print(f"    p90:  {feat_stats['p90']:.3f} ms | p95: {feat_stats['p95']:.3f} ms | p99: {feat_stats['p99']:.3f} ms")
    print(f"    Throughput: {feat_stats['ops_per_sec']:.1f} extractions/sec")

    # 3. Measure Full ScannerService (Extraction + Inference + Risk Engine + Explanations)
    scan_times = []
    for i in range(500):
        u = test_urls[i % len(test_urls)]
        t0 = time.perf_counter()
        _ = scan_url(u)
        scan_times.append((time.perf_counter() - t0) * 1000.0)

    scan_stats = compute_percentiles(scan_times)
    print("\n[3] FULL SCANNER SERVICE WORKFLOW (500 iterations):")
    print(f"    Mean: {scan_stats['mean']:.3f} ms | Median (p50): {scan_stats['p50']:.3f} ms")
    print(f"    p90:  {scan_stats['p90']:.3f} ms | p95: {scan_stats['p95']:.3f} ms | p99: {scan_stats['p99']:.3f} ms")
    print(f"    Throughput: {scan_stats['ops_per_sec']:.1f} scans/sec")

    # 4. Measure Database Operations
    db = SessionLocal()
    dummy_scan = scan_url("https://example.com/test-db-latency")

    # Insert Latency
    db_insert_times = []
    for _ in range(100):
        t0 = time.perf_counter()
        crud.create_scan_record(db, dummy_scan)
        db_insert_times.append((time.perf_counter() - t0) * 1000.0)
    db_insert_stats = compute_percentiles(db_insert_times)

    # Aggregate Statistics Latency
    db_stats_times = []
    for _ in range(100):
        t0 = time.perf_counter()
        crud.get_aggregate_statistics(db)
        db_stats_times.append((time.perf_counter() - t0) * 1000.0)
    db_agg_stats = compute_percentiles(db_stats_times)

    # History Pagination Latency
    db_hist_times = []
    for _ in range(100):
        t0 = time.perf_counter()
        crud.list_scans(db, skip=0, limit=20, sort_by="created_at", sort_order="desc")
        db_hist_times.append((time.perf_counter() - t0) * 1000.0)
    db_hist_stats = compute_percentiles(db_hist_times)

    db.close()

    print("\n[4] DATABASE OPERATIONS (100 iterations each):")
    print(f"    Insert (create_scan_record):   Mean {db_insert_stats['mean']:.3f} ms | p95: {db_insert_stats['p95']:.3f} ms | p99: {db_insert_stats['p99']:.3f} ms")
    print(f"    Stats (get_aggregate_stats):   Mean {db_agg_stats['mean']:.3f} ms | p95: {db_agg_stats['p95']:.3f} ms | p99: {db_agg_stats['p99']:.3f} ms")
    print(f"    History (list_scans page 1):   Mean {db_hist_stats['mean']:.3f} ms | p95: {db_hist_stats['p95']:.3f} ms | p99: {db_hist_stats['p99']:.3f} ms")

    mem_after = process.memory_info().rss / (1024 * 1024)
    cpu_end = process.cpu_percent(interval=None)

    print("\n[5] PROCESS RESOURCES:")
    print(f"    Memory RSS: {mem_before:.1f} MB -> {mem_after:.1f} MB (Delta: {mem_after - mem_before:.2f} MB)")
    print("=================================================================\n")

    return {
        "ml_inference": inf_stats,
        "feature_extraction": feat_stats,
        "full_scanner": scan_stats,
        "db_insert": db_insert_stats,
        "db_stats": db_agg_stats,
        "db_history": db_hist_stats,
        "memory_mb": mem_after,
    }

if __name__ == "__main__":
    import sys
    out_file = "backend/reports/benchmark_baseline.json"
    if len(sys.argv) > 1:
        out_file = sys.argv[1]
    results = run_benchmarks()
    out_path = Path(out_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Benchmark written to {out_path}")
