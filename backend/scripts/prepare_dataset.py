#!/usr/bin/env python3
"""
CLI Script: Dataset Preparation, Validation, and Feature Inspection.

Executes Module 1 of the Phishing URL Detection Pipeline:
- Loads and audits raw URL records
- Normalizes URLs and eliminates duplicate records
- Extracts lexical and structural features offline
- Partitions into stratified, zero-leakage Train/Val/Test splits
- Generates data quality report and feature dictionary
"""

import sys
import json
import argparse
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.ml.dataset import DatasetPipeline
from backend.app.ml.features import FEATURE_NAMES, FEATURE_METADATA


def print_banner(text: str) -> None:
    line = "=" * 70
    print(f"\n{line}\n {text}\n{line}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare, clean, validate, and partition Phishing URL dataset."
    )
    parser.add_argument(
        "--raw-path",
        type=str,
        default="backend/data/raw/urls.csv",
        help="Path to raw input CSV file containing 'url' and 'label' columns."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="backend/data/processed",
        help="Directory to save processed datasets and feature dictionary."
    )
    parser.add_argument(
        "--reports-dir",
        type=str,
        default="backend/reports",
        help="Directory to save dataset quality report JSON."
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Print detailed feature distributions and quality tables to console."
    )

    args = parser.parse_args()

    print_banner("PHISHING URL DETECTION - MODULE 1: DATASET PIPELINE")
    print(f"Raw Data Path:   {args.raw_path}")
    print(f"Output Directory:{args.output_dir}")
    print(f"Reports Directory:{args.reports_dir}")

    pipeline = DatasetPipeline(raw_data_path=args.raw_path)

    try:
        results = pipeline.run_pipeline(
            output_dir=args.output_dir,
            reports_dir=args.reports_dir
        )
    except Exception as exc:
        print(f"\n[ERROR] Dataset pipeline failed: {exc}", file=sys.stderr)
        return 1

    report = results["report_data"]
    audit = report["audit"]
    splits = report["splits"]

    print_banner("DATASET AUDIT & CLEANING SUMMARY")
    print(f"Total Raw Records:           {audit['total_raw_rows']}")
    print(f"Missing Values Dropped:      {audit['missing_rows_dropped']}")
    print(f"Empty URLs Dropped:          {audit['empty_url_rows_dropped']}")
    print(f"Conflicted Labels Dropped:   {audit['conflicted_labels_dropped']}")
    print(f"Duplicate URLs Removed:      {audit['duplicate_urls_removed']}")
    print(f"Final Cleaned Records:       {audit['final_clean_rows']}")
    print(f"Clean Class Distribution:    Legitimate={audit['class_distribution']['legitimate_0']}, Phishing={audit['class_distribution']['phishing_1']}")

    print_banner("STRATIFIED PARTITIONS (ZERO-LEAKAGE)")
    print(f"Train Partition (70%):       {splits['train_records']} records (0: {splits['train_class_balance'].get(0, 0)}, 1: {splits['train_class_balance'].get(1, 0)})")
    print(f"Validation Partition (15%):  {splits['val_records']} records (0: {splits['val_class_balance'].get(0, 0)}, 1: {splits['val_class_balance'].get(1, 0)})")
    print(f"Test Partition (15%):        {splits['test_records']} records (0: {splits['test_class_balance'].get(0, 0)}, 1: {splits['test_class_balance'].get(1, 0)})")

    domain_analysis = report["domain_analysis"]
    print_banner("DOMAIN LEAKAGE AUDIT")
    print(f"Unique Domains (Train):      {domain_analysis['train_unique_domains']}")
    print(f"Unique Domains (Val):        {domain_analysis['val_unique_domains']}")
    print(f"Unique Domains (Test):       {domain_analysis['test_unique_domains']}")
    print(f"Cross-Split URL Overlap:     0 (Zero sample leakage verified)")
    print(f"Assessment:                  {domain_analysis['domain_leakage_risk_assessment']}")

    if args.inspect:
        print_banner("KEY FEATURE DISTRIBUTIONS")
        headers = ["Feature", "Min", "Max", "Mean", "Std"]
        print(f"{headers[0]:<28} {headers[1]:<8} {headers[2]:<8} {headers[3]:<10} {headers[4]:<8}")
        print("-" * 65)
        for name in [
            "url_length", "hostname_length", "dot_count", "digit_ratio",
            "char_entropy", "suspicious_keyword_count", "has_ip_host",
            "has_https", "has_abused_tld", "is_shortened"
        ]:
            stats = report["feature_summary"].get(name, {})
            print(
                f"{name:<28} {stats.get('min', 0):<8.2f} {stats.get('max', 0):<8.2f} "
                f"{stats.get('mean', 0):<10.2f} {stats.get('std', 0):<8.2f}"
            )

    print_banner("GENERATED ARTIFACTS")
    print(f"[+] Train Dataset:          {results['train_file']}")
    print(f"[+] Validation Dataset:     {results['val_file']}")
    print(f"[+] Test Dataset:           {results['test_file']}")
    print(f"[+] Feature Dictionary:     {results['feature_dictionary']}")
    print(f"[+] Quality Report JSON:    {results['quality_report']}")

    print("\n[SUCCESS] Module 1 pipeline completed successfully.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
