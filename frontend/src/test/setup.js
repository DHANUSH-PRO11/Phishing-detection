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

// Silence Recharts width(0) / height(0) warning in headless JSDOM test environment
const originalWarn = console.warn;
const originalError = console.error;
console.warn = (...args) => {
  if (typeof args[0] === 'string' && args[0].includes('The width(0) and height(0) of chart')) return;
  originalWarn(...args);
};
console.error = (...args) => {
  if (typeof args[0] === 'string' && args[0].includes('The width(0) and height(0) of chart')) return;
  originalError(...args);
};
