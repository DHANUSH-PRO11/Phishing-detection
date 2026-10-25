/**
 * Centralized API Client Service.
 * Connects to the FastAPI backend with timeout, error interceptors, and environment configuration.
 */

import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    let message = 'An unexpected network error occurred.';
    if (error.response) {
      // Backend returned error status
      const detail = error.response.data?.detail || error.response.data?.error;
      message = typeof detail === 'string' ? detail : JSON.stringify(detail);
    } else if (error.request) {
      // Request made but no response (server down or timeout)
      message = 'Backend server is unreachable. Please verify that the API service is running on port 8000.';
    }
    return Promise.reject(new Error(message));
  }
);

export const api = {
  // 1. Health check
  getHealth: async () => {
    const res = await apiClient.get('/health');
    return res.data;
  },

  // 2. Scan URL
  scanUrl: async (url) => {
    const res = await apiClient.post('/scan', { url });
    return res.data;
  },

  // 3. Scan History (paginated, searched, filtered)
  getHistory: async ({
    page = 1,
    size = 20,
    search = '',
    status = '',
    risk_category = '',
    sort_by = 'created_at',
    sort_order = 'desc',
  } = {}) => {
    const params = { page, size, sort_by, sort_order };
    if (search) params.search = search;
    if (status) params.status = status;
    if (risk_category) params.risk_category = risk_category;

    const res = await apiClient.get('/history', { params });
    return res.data;
  },

  // 4. Single Scan Details
  getScanDetails: async (scanId) => {
    const res = await apiClient.get(`/history/${scanId}`);
    return res.data;
  },

  // 5. Delete Scan Record
  deleteScan: async (scanId) => {
    const res = await apiClient.delete(`/history/${scanId}`);
    return res.data;
  },

  // 6. Real Aggregate Dashboard Statistics
  getStats: async () => {
    const res = await apiClient.get('/stats');
    return res.data;
  },

  // 7. Model Information & Metrics
  getModelInfo: async () => {
    const res = await apiClient.get('/model-info');
    return res.data;
  },

  // 8. Helper to construct CSV export URL
  getExportCsvUrl: ({ search = '', status = '', risk_category = '' } = {}) => {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (status) params.append('status', status);
    if (risk_category) params.append('risk_category', risk_category);
    return `${API_BASE_URL}/history/export/csv?${params.toString()}`;
  },
};
