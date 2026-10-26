# Phishing Detection Platform — Load Testing Suite

This directory contains repeatable, automated load testing configurations for measuring baseline and optimized throughput, latency percentiles (p50, p90, p95, p99), error rates, and resource utilization.

---

## Prerequisites
- **k6**: CLI load testing engine (`k6` or `C:\Program Files\k6\k6.exe`)
- **Locust**: Python load testing framework (`locust` or `python -m locust`)
- **FastAPI Backend**: Running locally on `http://localhost:8000` (single-instance or load-balanced)

---

## Test Scenarios & Files

| File | Framework | Purpose |
|---|---|---|
| `scan.js` | k6 | Comprehensive multi-scenario load test (ramping, burst, peak, smoke). |
| `locustfile.py` | Locust | Python-based realistic user workflow (URL scanning, dashboard stats, history pagination). |
| `seeded_urls.json` | Dataset | Seeded, fixed URL dataset: benign, phishing lures, long query URLs, and invalid inputs. |

---

## Running with k6

### 1. Ramping Concurrency Test (5 -> 10 -> 25 -> 50 VUs)
Ramps virtual users gradually over 50 seconds:
```bash
& "C:\Program Files\k6\k6.exe" run tests/load/scan.js
```

### 2. Sudden Traffic Burst Scenario (50 VUs instant spike)
```bash
& "C:\Program Files\k6\k6.exe" run -e SCENARIO=burst tests/load/scan.js
```

### 3. Sustained Peak Load (25 VUs constant for 30 seconds)
```bash
& "C:\Program Files\k6\k6.exe" run -e SCENARIO=sustained_peak tests/load/scan.js
```

### 4. Custom Virtual Users and Duration
```bash
& "C:\Program Files\k6\k6.exe" run --vus 25 --duration 30s tests/load/scan.js
```

### 5. Targeting Load-Balanced Cluster
```bash
& "C:\Program Files\k6\k6.exe" run -e BASE_URL=http://localhost:80 tests/load/scan.js
```

---

## Running with Locust (Headless CLI Mode)

### 1. Normal Load (10 Users, spawn rate 2/s, duration 30s)
```bash
python -m locust -f tests/load/locustfile.py --headless -u 10 -r 2 --run-time 30s --host http://localhost:8000
```

### 2. High Concurrency Load (50 Users, spawn rate 10/s, duration 45s)
```bash
python -m locust -f tests/load/locustfile.py --headless -u 50 -r 10 --run-time 45s --host http://localhost:8000
```

### 3. Interactive Web UI Mode
```bash
python -m locust -f tests/load/locustfile.py --host http://localhost:8000
# Open http://localhost:8089 in your browser
```

---

## Performance Acceptance Thresholds
- **HTTP Request Failure Rate:** `< 1.0%` under normal operating load.
- **p95 Latency:** `< 500ms` for `/api/scan` endpoint.
- **Resource Ceiling:** CPU consumption bounded, zero database connection leaks, no memory growth after test completion.
