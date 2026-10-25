import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import ScanHistory from '../pages/ScanHistory';
import { api } from '../services/api';

vi.mock('../services/api', () => ({
  api: {
    getHistory: vi.fn(),
    deleteScan: vi.fn(),
    getExportCsvUrl: vi.fn(() => '/api/history/export/csv'),
  },
}));

describe('ScanHistory Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockHistoryData = {
    items: [
      {
        scan_id: 'uuid-1',
        url: 'http://malicious-login.com/auth',
        domain: 'malicious-login.com',
        status: 'Potentially Phishing',
        is_phishing: true,
        is_inconclusive: false,
        risk_score: 88,
        risk_category: 'High Risk',
        model_name: 'RandomForestClassifier',
        created_at: '2026-10-26T00:30:00Z',
      },
      {
        scan_id: 'uuid-2',
        url: 'https://stanford.edu',
        domain: 'stanford.edu',
        status: 'No Phishing Indicators Detected',
        is_phishing: false,
        is_inconclusive: false,
        risk_score: 5,
        risk_category: 'Low Risk',
        model_name: 'RandomForestClassifier',
        created_at: '2026-10-26T00:35:00Z',
      },
    ],
    total: 2,
    page: 1,
    size: 10,
    pages: 1,
  };

  it('renders history table with items from API', async () => {
    api.getHistory.mockResolvedValueOnce(mockHistoryData);

    render(<ScanHistory onSelectScan={vi.fn()} onNavigateToScanner={vi.fn()} />);

    expect(await screen.findByText('malicious-login.com')).toBeInTheDocument();
    expect(screen.getByText('stanford.edu')).toBeInTheDocument();
    expect(screen.getAllByText('Potentially Phishing').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No Phishing Indicators Detected').length).toBeGreaterThan(0);
  });

  it('filters history by status when dropdown changes', async () => {
    api.getHistory.mockResolvedValueOnce(mockHistoryData);
    api.getHistory.mockResolvedValueOnce({
      items: [mockHistoryData.items[0]],
      total: 1,
      page: 1,
      size: 10,
      pages: 1,
    });

    render(<ScanHistory onSelectScan={vi.fn()} onNavigateToScanner={vi.fn()} />);
    await screen.findByText('malicious-login.com');

    // Select status filter by accessible label
    const statusSelect = screen.getByLabelText(/Filter by Status/i);
    fireEvent.change(statusSelect, { target: { value: 'Potentially Phishing' } });

    await waitFor(() => {
      expect(api.getHistory).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'Potentially Phishing' })
      );
    });
  });

  it('opens confirmation modal and triggers deleteScan upon confirmation', async () => {
    api.getHistory.mockResolvedValue(mockHistoryData);
    api.deleteScan.mockResolvedValueOnce({ success: true, message: 'Deleted', scan_id: 'uuid-1' });

    render(<ScanHistory onSelectScan={vi.fn()} onNavigateToScanner={vi.fn()} />);
    await screen.findByText('malicious-login.com');

    const deleteButtons = screen.getAllByTitle(/Delete this scan record/i);
    fireEvent.click(deleteButtons[0]);

    // Modal appears
    expect(screen.getByText(/Confirm Record Deletion/i)).toBeInTheDocument();

    const confirmBtn = screen.getByRole('button', { name: /Delete Permanently/i });
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(api.deleteScan).toHaveBeenCalledWith('uuid-1');
    });
  });
});
