import '@testing-library/jest-dom';
import { vi } from 'vitest';

// JSDOM polyfill for ResizeObserver required by Recharts ResponsiveContainer
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// Polyfill window.scrollTo to prevent JSDOM not-implemented console warning
if (typeof window !== 'undefined') {
  window.scrollTo = vi.fn();
}
