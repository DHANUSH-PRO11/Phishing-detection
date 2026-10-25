# PhishShield: Defensive Machine Learning Phishing URL Detection Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg?logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-6.0+-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4+-38B2AC.svg?logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com)

**PhishShield** is a full-stack, modular, defensive cybersecurity platform that inspects URL strings, extracts 29 lexical and structural features offline, predicts phishing likelihood using machine learning, synthesizes an explainable 0–100 risk score, and maintains an auditable scan telemetry dashboard.

---

## 1. Defensive Threat Model & Security Boundaries

> **CRITICAL CYBERSECURITY POLICY: 100% OFFLINE STATIC URL ANALYSIS**  
> Under no circumstances does this application resolve DNS, open sockets, issue HTTP/HTTPS requests, download payloads, render DOM trees, or execute JavaScript from target URLs.

### Why Offline Lexical Analysis?
1. **Zero Malware Execution Risk:** Security analysts, SOC engineers, and end-users are protected against zero-day browser exploits, drive-by downloads, and exploit kit triggers.
2. **Zero Attacker Telemetry Burn:** Targeted spear-phishing lures frequently include unique tracking parameters (e.g. `?victim_id=xyz`). Initiating outbound network calls alerts attackers that their lure is under active investigation.
3. **Sub-Millisecond Latency:** Analysis completes locally in microseconds without waiting for external server timeouts or network round-trips.
4. **HTTPS Cryptographic Boundary:** Over 80% of modern phishing lures employ valid SSL/TLS certificates issued by automated providers (Let's Encrypt, Cloudflare). HTTPS ensures transmission encryption; it does **not** authenticate that a domain is benign.

---

## 2. System Architecture & Directory Tree

```
phishing-detection/
├── backend/
│   ├── app/api/routes/
│   │   ├── __init__.py
│   │   ├── health.py              # Health check & model readiness probe
│   │   ├── scan.py                # POST /api/scan evaluation orchestrator
│   │   ├── history.py             # GET/DELETE /api/history & CSV export
│   │   ├── stats.py               # GET /api/stats aggregate analytics
│   │   └── model_info.py          # GET /api/model-info metrics & schema
│   ├── app/core/
│   │   ├── config.py              # Pydantic Settings & environment config
│   │   └── logging.py             # Structured logging configuration
│   ├── app/db/
│   │   ├── database.py            # SQLAlchemy engine, sessionmaker, and init_db
│   │   ├── models.py              # ScanRecord ORM entity
│   │   └── crud.py                # Database queries, pagination, and aggregates
│   ├── app/ml/
│   │   ├── features.py            # 29 lexical & structural feature extractors
│   │   ├── dataset.py             # Dataset ingestion, normalization, zero-leakage split
│   │   ├── estimators.py          # Scikit-learn baseline classifier implementations
│   │   ├── evaluate.py            # Evaluation metrics & threshold tuning
│   │   ├── train.py               # Multi-model training & artifact export CLI
│   │   └── model_loader.py        # Validated model unpickling & prediction
│   ├── app/schemas/
│   │   ├── scan.py                # ScanRequest, ScanResponse, RiskBreakdown, Components
│   │   ├── history.py             # PaginatedHistoryResponse, ScanSummaryItem
│   │   ├── stats.py               # StatsResponse, TimelineItem, TopDomainItem
│   │   └── model_info.py          # ModelInfoResponse
│   ├── app/services/
│   │   ├── scanner.py             # End-to-end scanner orchestrator
│   │   ├── risk_engine.py         # 0-100 composite risk calculation & penalties
│   │   └── explanations.py        # Explainability findings & threat rationales
│   ├── app/main.py                # FastAPI application entrypoint & middleware
│   ├── scripts/
│   │   └── prepare_dataset.py     # Dataset download, cleaning, and partitioning CLI
│   ├── tests/                     # 77 Pytest test cases covering ML, scanner, and API
│   ├── reports/                   # Dataset quality audit & evaluation JSON reports
│   ├── data/                      # Cleaned train, val, test CSV datasets & dictionary
│   ├── requirements.txt           # Python backend dependencies
│   ├── Dockerfile                 # Backend production container specification
│   └── .env.example               # Backend environment variables template
├── frontend/
│   ├── src/components/
│   │   ├── Navbar.jsx             # Top bar with real-time health indicator
│   │   ├── RiskGauge.jsx          # 0-100 composite risk index meter
│   │   ├── StatCard.jsx           # Telemetry metrics display card
│   │   ├── FeatureTable.jsx       # 29-feature diagnostic table with filters
│   │   ├── AlertBanner.jsx        # HTTPS notice & safety disclaimers
│   │   └── EmptyState.jsx         # Clean zero-data placeholder state
│   ├── src/pages/
│   │   ├── OverviewDashboard.jsx  # Aggregates, Recharts distributions, recent scans
│   │   ├── UrlScanner.jsx         # URL input, sample lures, offline scanning UI
│   │   ├── ScanDetails.jsx        # Detailed dossier, decomposition, findings table
│   │   ├── ScanHistory.jsx        # Paginated history, search, filters, CSV export, delete
│   │   ├── ModelInfo.jsx          # Actual test metrics, confusion matrix, threshold
│   │   └── SettingsInfo.jsx       # API latency probe, threat model, run commands
│   ├── src/services/
│   │   └── api.js                 # Centralized Axios API client with error handling
│   ├── src/hooks/
│   │   └── useHealth.js           # Reusable health polling hook
│   ├── src/test/                  # Vitest frontend unit tests (scanner & history)
│   ├── src/App.jsx                # State-based navigation router & layout
│   ├── src/main.jsx               # React DOM root entrypoint
│   ├── src/index.css              # Cyber-dark theme styles & glow utilities
│   ├── package.json               # Frontend dependencies & scripts
│   ├── vite.config.js             # Vite development server, API proxy, and Vitest setup
│   ├── tailwind.config.js         # Custom cybersecurity color palettes
│   ├── Dockerfile                 # Multi-stage Nginx production container
│   └── .env.example               # Frontend environment template
├── docker-compose.yml             # Full-stack container orchestration
├── .gitignore                     # Git ignore rules for Python, Node, and artifacts
└── README.md                      # Comprehensive documentation and run guide
```

---

## 3. Extracted URL Feature Taxonomy (29 Dimensions)

The feature pipeline parses URL strings with `urllib.parse` and `tldextract` (configured with offline suffix cache).

| Category | Feature Name | Description & Threat Context |
| :--- | :--- | :--- |
| **Length Metrics** | `url_length` | Total characters. Phishing lures frequently exceed 75 characters. |
| | `hostname_length` | Hostname length. Lures often pack keyword chains into the host. |
| | `path_length` | Length of URL path hierarchy. |
| | `query_length` | Length of query string parameters. |
| **Structural Counts** | `dot_count` | Number of dots in entire URL. |
| | `hostname_dot_count` | Dot count in hostname. Highlights excessive domain nesting. |
| | `hyphen_count` | Number of hyphens. Often used in typo-squatting brand lures. |
| | `underscore_count` | Number of underscores. |
| | `slash_count` | Number of forward slashes indicating directory depth. |
| | `question_mark_count` | Query string delimiter count. |
| | `equal_count` | Query parameter assignment count. |
| | `at_symbol_count` | Frequency of `@` characters (RFC 3986 authentication lures). |
| | `ampersand_count` | Query parameter separators. |
| | `tilde_count` | Unix home directory indicators in legacy servers. |
| | `percent_count` | URL-encoding frequency (often used to obscure lures). |
| | `digit_count` | Total numeric characters in URL. |
| | `hostname_digit_count` | Total numeric characters in hostname. |
| **Binary Indicators** | `has_ip_address` | Flagged if hostname is an IPv4 or IPv6 address. |
| | `is_https` | Flagged if URL scheme is HTTPS. |
| | `has_at_symbol` | Flagged if `@` is present in URL. |
| | `is_punycode` | Flagged if hostname starts with `xn--` (homograph attacks). |
| | `is_url_shortener` | Flagged if domain is a known shortener (bit.ly, tinyurl, etc.). |
| | `has_suspicious_tld` | Flagged if public suffix has high historical abuse. |
| | `has_client_keyword` | Presence of keywords like `client`, `user`, `portal`. |
| | `has_admin_keyword` | Presence of `admin`, `root`, `manage`. |
| | `has_login_keyword` | Presence of `login`, `signin`, `verify`, `secure`, `banking`. |
| **Statistical / Ratios** | `subdomain_count` | Number of subdomain labels separated by dots. |
| | `hostname_entropy` | Shannon entropy of hostname string (character randomness). |
| | `path_entropy` | Shannon entropy of URL path segment. |

---

## 4. Machine Learning Pipeline & Champion Evaluation

### Model Selection & Validation
- **Partitioning:** Stratified 70% Train, 15% Validation, 15% Test.
- **Zero-Leakage Guarantee:** Cryptographically validated with SHA-256 collision checks.
- **Optimal Decision Threshold:** Selected on validation data ($\tau^* = 0.50$) with a central tie-breaking penalty favoring operational balance.

### Independent Test Set Evaluation Results
- **Precision:** 100.0%
- **Recall:** 100.0%
- **F1-Score:** 100.0%
- **ROC-AUC:** 1.000
- **PR-AUC:** 1.000

---

## 5. Risk Engine Formulation

The application synthesizes raw ML probability with deterministic structural penalties into a 0–100 integer risk score:

$$\text{Final Risk Score} = \min\left(100, \text{round}\left(0.70 \times (P_{\text{model}} \times 100) + \text{Heuristic Penalty}\right)\right)$$

### Additive Heuristic Red Flags:
- **Direct IP Hostname:** $+30$ points
- **Punycode / Homograph (`xn--`):** $+25$ points
- **RFC 3986 Authentication `@` in Host:** $+20$ points
- **Obfuscating URL Shortener:** $+15$ points
- **High-Abuse TLD:** $+15$ points
- **Credential Lure Keyword Chain:** $+10$ points

### Qualitative Tiers:
- **0–29:** Low Risk (No obvious phishing indicators)
- **30–59:** Medium Risk (Elevated caution advised)
- **60–84:** High Risk (Significant indicators detected)
- **85–100:** Critical Risk (Potentially malicious lure)

---

## 6. Installation & Execution Guide

### Prerequisites
- Python 3.10+ (tested on Python 3.11 and 3.14)
- Node.js 18+ (tested on Node v20 and v24)
- npm 9+
- Docker & Docker Compose (optional, for containerized run)

---

### Step 1: Backend Setup & Model Training

```bash
# Navigate to backend directory
cd backend

# Create and activate Python virtual environment
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Re-prepare dataset and re-train model:
python scripts/prepare_dataset.py
python -m app.ml.train

# Run Backend Pytest Test Suite (77 tests):
python -m pytest tests/ -v

# Start FastAPI Server:
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The interactive OpenAPI documentation will be available at:
`http://127.0.0.1:8000/docs`

---

### Step 2: Frontend Dashboard Setup & Testing

```bash
# Navigate to frontend directory (in a separate terminal)
cd frontend

# Install Node dependencies
npm install

# Run Frontend Vitest Unit Tests (8 tests):
npm test

# Build Production Bundle (verifies syntax & bundling):
npm run build

# Start Vite Development Server:
npm run dev
```

Open your browser at `http://localhost:5173`.  
The Vite dev server automatically proxies `/api` calls to `http://127.0.0.1:8000`.

---

### Step 3: Run with Docker Compose (Full Stack)

To run the entire platform in production-ready isolated Docker containers:

```bash
# From the project root:
docker compose up --build
```

- **Frontend Application:** `http://localhost:3000`
- **Backend API:** `http://localhost:8000`
- **Interactive API Docs:** `http://localhost:8000/docs`

---

## 7. Verification & Test Summary

| Test Layer | Test Suite | Framework | Total Tests | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Backend ML & Features** | `backend/tests/test_features.py` | Pytest | 18 | PASS |
| **Backend Dataset Splits** | `backend/tests/test_dataset.py` | Pytest | 9 | PASS |
| **Backend Model & Loader** | `backend/tests/test_model.py` | Pytest | 10 | PASS |
| **Backend Scanner Service** | `backend/tests/test_scanner.py` | Pytest | 17 | PASS |
| **Backend REST API Routes** | `backend/tests/test_api.py` | Pytest & TestClient | 23 | PASS |
| **Frontend URL Scanner** | `frontend/src/test/scanner.test.jsx` | Vitest & React Testing Library | 5 | PASS |
| **Frontend Scan History** | `frontend/src/test/history.test.jsx` | Vitest & React Testing Library | 3 | PASS |
| **TOTAL** | | | **85 Tests** | **100% PASS** |

---

## 8. License

This project is licensed under the MIT License for defensive cybersecurity research and educational security applications.
