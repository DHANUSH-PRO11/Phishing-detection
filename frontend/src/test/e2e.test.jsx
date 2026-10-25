import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import App from '../App';
import { api } from '../services/api';

vi.mock('../services/api', () => ({
  api: {
    getHealth: vi.fn(),
    getStats: vi.fn(),
    scanUrl: vi.fn(),
    getHistory: vi.fn(),
    getScanDetails: vi.fn(),
    deleteScan: vi.fn(),
    getModelInfo: vi.fn(),
    getExportCsvUrl: vi.fn(() => '/api/history/export/csv'),
  },
}));

describe('End-to-End Application Flow', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    api.getHealth.mockResolvedValue({
      status: 'ok',
      model_ready: true,
      timestamp: '2026-10-26T01:00:00Z',
    });

    api.getStats.mockResolvedValue({
      total_scans: 1,
      phishing_detected_count: 1,
      legitimate_count: 0,
      inconclusive_count: 0,
      average_risk_score: 92.0,
      status_distribution: { 'Potentially Phishing': 1 },
      risk_category_distribution: { 'Critical Risk': 1 },
      recent_scans_timeline: [
        {
          scan_id: 'e2e-scan-1',
          domain: 'phishing-login-portal.com',
          status: 'Potentially Phishing',
          risk_score: 92,
          timestamp: '2026-10-26T01:00:00Z',
        },
      ],
      top_flagged_domains: [{ domain: 'phishing-login-portal.com', count: 1 }],
    });

    api.getHistory.mockResolvedValue({
      items: [
        {
          scan_id: 'e2e-scan-1',
          url: 'http://phishing-login-portal.com/update-security',
          domain: 'phishing-login-portal.com',
          status: 'Potentially Phishing',
          is_phishing: true,
          is_inconclusive: false,
          risk_score: 92,
          risk_category: 'Critical Risk',
          model_name: 'RandomForestClassifier',
          created_at: '2026-10-26T01:00:00Z',
        },
      ],
      total: 1,
      page: 1,
      size: 10,
      pages: 1,
    });
  });

  it('completes the full flow: Overview -> Scanner -> Submit URL -> Review Dossier -> View History', async () => {
    const mockScanResult = {
      scan_id: 'e2e-scan-1',
      url: 'http://phishing-login-portal.com/update-security',
      normalized_url: 'http://phishing-login-portal.com/update-security',
      status: 'Potentially Phishing',
      is_phishing: true,
      is_inconclusive: false,
      risk: {
        model_probability: 0.94,
        decision_threshold: 0.50,
        heuristic_penalty: 25,
        final_risk_score: 92,
        risk_category: 'Critical Risk',
        formula_documentation: '0.70 * (0.94 * 100) + 25 = 92',
        limitations_caveat: 'Offline lexical analysis only',
      },
      https_analysis: 'Insecure plain HTTP connection.',
      safety_disclaimer: 'Automated ML prediction disclaimer.',
      components: {
        scheme: 'http',
        netloc: 'phishing-login-portal.com',
        domain: 'phishing-login-portal.com',
        subdomain: '',
        suffix: 'com',
        path: '/update-security',
        query: '',
        fragment: '',
      },
      explanations: [
        {
          rule: 'RULE_SECURITY_KEYWORDS',
          title: 'Credential Harvesting Keywords',
          severity: 'HIGH',
          message: 'Deceptive keyword lures observed.',
          threat_context: 'Attacker credential harvest tactic.',
        },
      ],
      features: { url_length: 50, has_ip_address: 0 },
      feature_details: [
        {
          name: 'url_length',
          value: 50,
          description: 'Total URL character count',
          threat_rationale: 'Long URLs pack lures',
          is_flagged: false,
        },
      ],
      model_name: 'RandomForestClassifier',
      scan_timestamp_utc: '2026-10-26T01:00:00Z',
    };

    api.scanUrl.mockResolvedValueOnce(mockScanResult);
    api.getScanDetails.mockResolvedValueOnce(mockScanResult);

    render(<App />);

    // 1. Initial Dashboard loads
    expect(await screen.findByText(/Security Telemetry & Overview/i)).toBeInTheDocument();

    // 2. Click "Scan Suspicious URL" or Nav to Scanner
    const scannerNavBtns = screen.getAllByRole('button', { name: /URL Scanner/i });
    fireEvent.click(scannerNavBtns[0]);

    // 3. On Scanner page
    expect(await screen.findByText(/Cybersecurity URL Scanner/i)).toBeInTheDocument();

    const input = screen.getByPlaceholderText(/e.g., https:\/\//i);
    fireEvent.change(input, {
      target: { value: 'http://phishing-login-portal.com/update-security' },
    });

    const scanBtn = screen.getByRole('button', { name: /Scan URL/i });
    fireEvent.click(scanBtn);

    // 4. Result appears
    await waitFor(() => {
      expect(api.scanUrl).toHaveBeenCalledWith('http://phishing-login-portal.com/update-security');
    });

    expect(await screen.findByText('Credential Harvesting Keywords')).toBeInTheDocument();

    // 5. Click "View Full Diagnostics & Features"
    const viewDetailsBtn = screen.getByRole('button', { name: /View Full Diagnostics & Features/i });
    fireEvent.click(viewDetailsBtn);

    // 6. On Scan Details dossier
    expect(await screen.findByText(/Security Diagnostic Dossier/i)).toBeInTheDocument();
    expect(screen.getByText('URL Structural Decomposition')).toBeInTheDocument();

    // 7. Navigate to History
    const historyNavBtns = screen.getAllByRole('button', { name: /Scan History/i });
    fireEvent.click(historyNavBtns[0]);

    expect(await screen.findByText(/Audit Scan History/i)).toBeInTheDocument();
    expect(await screen.findByText('phishing-login-portal.com')).toBeInTheDocument();
  });
});
