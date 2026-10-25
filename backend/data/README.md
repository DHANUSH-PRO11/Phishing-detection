# Phishing URL Detection Dataset: Provenance, Curation, & Pipeline Documentation

This directory contains the training and evaluation datasets for the Phishing URL Detection platform.

## 1. Dataset Provenance & Sources

The dataset incorporates real-world, verified URLs derived from established cybersecurity feeds:

1. **Phishing Examples (Label `1`)**:
   - **PhishTank** ([phishtank.org](https://phishtank.org/)): Verified active phishing submissions submitted and confirmed by community analysts.
   - **OpenPhish** ([openphish.com](https://openphish.com/)): Global phishing intelligence feed capturing live social engineering and credential-harvesting campaigns.
   - **Features Represented**: Direct IP hosts, credential harvesting lures (`/webscr/login.php`, `/account-verification/`), URL shorteners, punycode homoglyphs (`xn--`), high-abuse TLDs (`.tk`, `.xyz`, `.buzz`), and brand impersonation.

2. **Legitimate Examples (Label `0`)**:
   - **Tranco Top Sites Ranking** ([tranco-list.eu](https://tranco-list.eu/)): Research-oriented top domain list combining Alexa, Cisco Umbrella, Majestic, and Farsight DNS rankings.
   - **Verified Web Resources**: Reputable academic, news, financial, technology, and developer documentation URLs with authentic deep paths and parameter queries.

## 2. Licensing and Ethical Data Use

- **PhishTank**: PhishTank data is provided by Cisco Talos under the PhishTank API & Data Terms of Use for non-commercial cybersecurity defense research.
- **Tranco List**: Published under an open research license (MIT / CC-BY-4.0).
- **Defensive Cyber Context**: All URLs in this repository are analyzed strictly offline as raw character strings. **No URL is ever navigated to, pinged, or resolved via live DNS during analysis.**

## 3. Dataset Schema & Label Semantics

Input CSV files must follow this schema:

| Column | Data Type | Permitted Values | Description |
| :--- | :--- | :--- | :--- |
| `url` | String | Any valid URI string | Raw URL submitted for inspection. |
| `label` | Integer | `0` or `1` | Binary ground truth (`0` = Legitimate, `1` = Phishing). |

Strict validation rules enforced:
- Null, empty, or whitespace-only URLs are dropped.
- Labels must strictly parse to integer `0` or `1`. Non-binary or ambiguous labels are rejected.
- URLs with contradictory labels (e.g., marked both 0 and 1 in duplicate rows) are eliminated to maintain label veracity.

## 4. How to Import External Public Datasets

To ingest a new bulk dataset (e.g., a freshly downloaded PhishTank export):

1. **Format CSV**: Ensure your file contains headers `url` and `label`.
   ```bash
   # Example input format
   url,label
   https://github.com/torvalds/linux,0
   http://192.168.1.100/secure/login.php,1
   ```
2. **Place File**: Copy your CSV to `backend/data/raw/urls.csv` (or specify via `--raw-path`).
3. **Execute Pipeline**:
   ```bash
   python backend/scripts/prepare_dataset.py --raw-path backend/data/raw/urls.csv --inspect
   ```
4. **Output Verification**: The pipeline outputs cleaned, deduplicated, and stratified CSV files in `backend/data/processed/`.

## 5. Cleaning and Leakage Prevention

Data leakage is a critical vulnerability in machine learning for cybersecurity:

### Zero Sample Leakage Guarantee
- URLs are normalized (whitespace removed, control characters stripped, missing scheme standardized).
- Strict deduplication ensures that duplicate URLs cannot exist in both training and test sets.
- A cryptographic set-intersection check verifies that:
  $$\text{Train} \cap \text{Val} = \emptyset, \quad \text{Train} \cap \text{Test} = \emptyset, \quad \text{Val} \cap \text{Test} = \emptyset$$

### Domain-Level Leakage Considerations
- In URL detection, legitimate domains (e.g., `wikipedia.org`, `github.com`) host millions of legitimate pages.
- While exact URLs are 100% disjoint, multiple benign paths from high-traffic domains may naturally appear across train and test partitions.
- To counter domain memorization, our feature extractor uses lexical, structural, and character-entropy features rather than domain one-hot encodings.

## 6. Directory Structure

```
backend/data/
├── raw/
│   └── urls.csv                 # Raw curated input records
├── processed/
│   ├── train.csv                # 70% stratified training split
│   ├── val.csv                  # 15% stratified validation split
│   ├── test.csv                 # 15% stratified test split
│   ├── cleaned_features.csv     # Full dataset with extracted numeric features
│   └── feature_dictionary.json  # Comprehensive schema and rationale dictionary
└── README.md                    # This provenance and operation guide
```
