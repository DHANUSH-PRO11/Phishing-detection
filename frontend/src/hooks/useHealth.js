import { useState, useEffect } from 'react';
import { api } from '../services/api';

/**
 * Reusable React Hook for fetching and polling backend health & model readiness.
 */
export function useHealth(pollIntervalMs = 30000) {
  const [health, setHealth] = useState({ status: 'checking', model_ready: false });
  const [error, setError] = useState(null);

  const checkHealth = async () => {
    try {
      const data = await api.getHealth();
      setHealth(data);
      setError(null);
    } catch (err) {
      setHealth({ status: 'offline', model_ready: false });
      setError(err.message || 'Backend unreachable');
    }
  };

  useEffect(() => {
    checkHealth();
    if (pollIntervalMs > 0) {
      const timer = setInterval(checkHealth, pollIntervalMs);
      return () => clearInterval(timer);
    }
  }, [pollIntervalMs]);

  return { health, error, refreshHealth: checkHealth };
}
