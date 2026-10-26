import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter, Rate } from 'k6/metrics';

// Custom metrics for granular per-endpoint latency isolation
const scanLatency = new Trend('scan_endpoint_duration');
const statsLatency = new Trend('stats_endpoint_duration');
const historyLatency = new Trend('history_endpoint_duration');
const errorRate = new Rate('custom_error_rate');
const status200Count = new Counter('http_200_count');
const status422Count = new Counter('http_422_count');
const status429Count = new Counter('http_429_count');

// Load seeded test URLs
const seededData = JSON.parse(open('./seeded_urls.json'));
const allValidUrls = [...seededData.normal_urls, ...seededData.phishing_lures, ...seededData.large_valid_urls];
const invalidUrls = seededData.invalid_urls;

// Configurable target environment
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const SCENARIO_MODE = __ENV.SCENARIO || 'ramping';

// Selectable test configurations
function getOptions(scenario) {
  switch (scenario) {
    case 'smoke':
      return {
        vus: 1,
        duration: '10s',
        thresholds: {
          http_req_failed: ['rate<0.01'],
          http_req_duration: ['p(95)<500'],
        },
      };

    case 'burst':
      return {
        stages: [
          { duration: '5s', target: 5 },
          { duration: '10s', target: 50 }, // sudden burst to 50 VUs
          { duration: '5s', target: 5 },
          { duration: '5s', target: 0 },
        ],
        thresholds: {
          http_req_failed: ['rate<0.05'],
          http_req_duration: ['p(95)<1000'],
        },
      };

    case 'sustained_peak':
      return {
        stages: [
          { duration: '10s', target: 25 },
          { duration: '30s', target: 25 }, // sustained peak at 25 VUs
          { duration: '10s', target: 0 },
        ],
        thresholds: {
          http_req_failed: ['rate<0.02'],
          http_req_duration: ['p(95)<600'],
        },
      };

    case 'ramping':
    default:
      return {
        stages: [
          { duration: '10s', target: 5 },  // 5 VUs normal load
          { duration: '10s', target: 10 }, // 10 VUs medium load
          { duration: '10s', target: 25 }, // 25 VUs elevated load
          { duration: '10s', target: 50 }, // 50 VUs peak load
          { duration: '10s', target: 0 },  // Ramp-down
        ],
        thresholds: {
          http_req_failed: ['rate<0.02'],
          http_req_duration: ['p(95)<500'],
          'custom_error_rate': ['rate<0.02'],
        },
      };
  }
}

export const options = getOptions(SCENARIO_MODE);

export default function () {
  const headers = { 'Content-Type': 'application/json' };

  // 1. URL Scan Request (70% traffic weight)
  const isInvalid = Math.random() < 0.05; // 5% intentional negative tests
  const targetUrl = isInvalid
    ? invalidUrls[Math.floor(Math.random() * invalidUrls.length)]
    : allValidUrls[Math.floor(Math.random() * allValidUrls.length)];

  const scanPayload = JSON.stringify({ url: targetUrl });
  const scanRes = http.post(`${BASE_URL}/api/scan`, scanPayload, { headers });

  scanLatency.add(scanRes.timings.duration);

  if (scanRes.status === 200) {
    status200Count.add(1);
    errorRate.add(0);
    check(scanRes, {
      'scan 200 OK': (r) => r.status === 200,
      'scan returns risk score': (r) => JSON.parse(r.body).risk !== undefined,
      'scan credentials sanitized': (r) => !r.body.includes('superSecretPass'),
    });
  } else if (scanRes.status === 422) {
    status422Count.add(1);
    errorRate.add(0); // Expected for invalid input test
    check(scanRes, { 'scan 422 for malformed': (r) => r.status === 422 });
  } else if (scanRes.status === 429) {
    status429Count.add(1);
    check(scanRes, { 'rate limited properly': (r) => r.status === 429 });
  } else {
    errorRate.add(1);
  }

  // 2. Aggregate Statistics Request (15% traffic weight)
  if (Math.random() < 0.20) {
    const statsRes = http.get(`${BASE_URL}/api/stats`);
    statsLatency.add(statsRes.timings.duration);
    check(statsRes, {
      'stats 200 OK': (r) => r.status === 200,
      'stats has total_scans': (r) => JSON.parse(r.body).total_scans !== undefined,
    });
  }

  // 3. Scan History Request (15% traffic weight)
  if (Math.random() < 0.15) {
    const historyRes = http.get(`${BASE_URL}/api/history?page=1&size=10&sort_by=created_at&sort_order=desc`);
    historyLatency.add(historyRes.timings.duration);
    check(historyRes, {
      'history 200 OK': (r) => r.status === 200,
      'history items is array': (r) => Array.isArray(JSON.parse(r.body).items),
    });
  }

  sleep(0.1 + Math.random() * 0.2); // 100ms - 300ms realistic user think time
}
