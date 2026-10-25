import pytest
import pandas as pd
from pathlib import Path
from backend.app.ml.dataset import DatasetPipeline


def test_seed_dataset_creation(tmp_path: Path):
    csv_file = tmp_path / "test_urls.csv"
    pipeline = DatasetPipeline(raw_data_path=csv_file)
    created_path = pipeline.create_initial_seed_dataset()
    assert created_path.exists()

    df = pd.read_csv(created_path)
    assert "url" in df.columns
    assert "label" in df.columns
    assert len(df) >= 50
    assert set(df["label"].unique()) == {0, 1}


def test_label_validation(tmp_path: Path):
    bad_csv = tmp_path / "bad_labels.csv"
    bad_df = pd.DataFrame([
        {"url": "https://valid.com", "label": 0},
        {"url": "https://invalid-label.com", "label": 2},  # Invalid label
    ])
    bad_df.to_csv(bad_csv, index=False)

    pipeline = DatasetPipeline(raw_data_path=bad_csv)
    with pytest.raises(ValueError, match="strictly 0"):
        pipeline.load_and_validate_raw_data()


def test_deduplication(tmp_path: Path):
    dup_csv = tmp_path / "dup_urls.csv"
    dup_df = pd.DataFrame([
        {"url": "https://example.com/page", "label": 0},
        {"url": "https://example.com/page", "label": 0},  # Exact duplicate
        {"url": "https://different.com", "label": 1},
    ])
    dup_df.to_csv(dup_csv, index=False)

    pipeline = DatasetPipeline(raw_data_path=dup_csv)
    raw = pipeline.load_and_validate_raw_data()
    deduped = pipeline.deduplicate(raw)
    assert len(deduped) == 2


def test_stratified_split_and_zero_leakage(tmp_path: Path):
    pipeline = DatasetPipeline()
    raw = pipeline.load_and_validate_raw_data()
    deduped = pipeline.deduplicate(raw)
    featured = pipeline.extract_features_from_dataframe(deduped)

    train_df, val_df, test_df = pipeline.split_dataset(featured, train_size=0.7, val_size=0.15, test_size=0.15)

    # Check total counts
    assert len(train_df) + len(val_df) + len(test_df) == len(featured)

    # Verify 0 URL leakage
    train_urls = set(train_df["normalized_url"])
    val_urls = set(val_df["normalized_url"])
    test_urls = set(test_df["normalized_url"])

    assert len(train_urls.intersection(val_urls)) == 0
    assert len(train_urls.intersection(test_urls)) == 0
    assert len(val_urls.intersection(test_urls)) == 0

    # Ensure both classes are represented in all splits
    assert set(train_df["label"].unique()) == {0, 1}
    assert set(val_df["label"].unique()) == {0, 1}
    assert set(test_df["label"].unique()) == {0, 1}
