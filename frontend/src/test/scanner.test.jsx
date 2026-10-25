import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import UrlScanner from '../pages/UrlScanner';
import { api } from '../services/api';

vi.mock('../services/api', () => ({
  api: {
    scanUrl: vi.fn(),
  },
}));

describe('UrlScanner Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders scanner input and sample quick buttons', () => {
    render(<UrlScanner onScanComplete={vi.fn()} onViewDetails={vi.fn()} />);
    
    expect(screen.getByPlaceholderText(/e.g., https:\/\//i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Scan URL/i })).toBeInTheDocument();
    expect(screen.getByText(/Legitimate Domain/i)).toBeInTheDocument();
    expect(screen.getByText(/IP-Based Host Lure/i)).toBeInTheDocument();
  });

  it('validates empty URL input and displays error message', async () => {
    render(<UrlScanner onScanComplete={vi.fn()} onViewDetails={vi.fn()} />);

    const submitBtn = screen.getByRole('button', { name: /Scan URL/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByText(/Please enter a URL to analyze/i)).toBeInTheDocument();
    expect(api.scanUrl).not.toHaveBeenCalled();
  });

  it('rejects unsupported javascript: and data: schemes', async () => {
    render(<UrlScanner onScanComplete={vi.fn()} onViewDetails={vi.fn()} />);

    const input = screen.getByPlaceholderText(/e.g., https:\/\//i);
    fireEvent.change(input, { target: { value: 'javascript:alert(1)' } });

    const submitBtn = screen.getByRole('button', { name: /Scan URL/i });
    fireEvent.click(submitBtn);

    expect(await screen.findByText(/Unsupported URI scheme/i)).toBeInTheDocument();
    expect(api.scanUrl).not.toHaveBeenCalled();
  });

  it('successfully triggers scan and renders results on API success', async () => {
    const mockScanResponse = {
      scan_id: 'scan-uuid-1234',
      url: 'http://192.168.1.1/login',
      normalized_url: 'http://192.168.1.1/login',
      status: 'Potentially Phishing',
      is_phishing: true,
      is_inconclusive: false,
      risk: {
        model_probability: 0.95,
        decision_threshold: 0.50,
        heuristic_penalty: 30,
        final_risk_score: 95,
        risk_category: 'Critical Risk',
        formula_documentation: 'Synthesized formula',
        limitations_caveat: 'Offline analysis only',
      },
      https_analysis: 'HTTP connection without TLS encryption.',
      safety_disclaimer: 'Automated ML prediction, not a guarantee of safety.',
      components: {
        scheme: 'http',
        netloc: '192.168.1.1',
        domain: '192.168.1.1',
        subdomain: '',
        suffix: '',
        path: '/login',
        query: '',
        fragment: '',
      },
      explanations: [
        {
          rule: 'RULE_IP_HOST',
          title: 'IP Address Used as Hostname',
          severity: 'HIGH',
          message: 'Direct IPv4 host detected.',
          threat_context: 'Attacker evasion tactic.',
        },
      ],
      features: { has_ip_address: 1.0 },
      feature_details: [],
      model_name: 'RandomForestClassifier',
      scan_timestamp_utc: '2026-10-26T01:00:00Z',
    };

    api.scanUrl.mockResolvedValueOnce(mockScanResponse);
    const mockOnComplete = vi.fn();

    render(<UrlScanner onScanComplete={mockOnComplete} onViewDetails={vi.fn()} />);

    const input = screen.getByPlaceholderText(/e.g., https:\/\//i);
    fireEvent.change(input, { target: { value: 'http://192.168.1.1/login' } });

    const submitBtn = screen.getByRole('button', { name: /Scan URL/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(api.scanUrl).toHaveBeenCalledWith('http://192.168.1.1/login');
      expect(mockOnComplete).toHaveBeenCalledWith(mockScanResponse);
    });

    expect(screen.getByText('Potentially Phishing')).toBeInTheDocument();
    expect(screen.getByText('IP Address Used as Hostname')).toBeInTheDocument();
    expect(screen.getByText(/View Full Diagnostics & Features/i)).toBeInTheDocument();
  });

  it('handles backend network failures gracefully', async () => {
    api.scanUrl.mockRejectedValueOnce(
      new Error('Backend server is unreachable. Please verify that the API service is running on port 8000.')
    );

    render(<UrlScanner onScanComplete={vi.fn()} onViewDetails={vi.fn()} />);

    const input = screen.getByPlaceholderText(/e.g., https:\/\//i);
    fireEvent.change(input, { target: { value: 'https://example.com' } });

    const submitBtn = screen.getByRole('button', { name: /Scan URL/i });
    fireEvent.click(submitBtn);

    expect(
      await screen.findByText(/Backend server is unreachable/i)
    ).toBeInTheDocument();
  });
});
