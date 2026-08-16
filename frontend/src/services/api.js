/**
 * Axios API Service Client with Lightweight In-Memory Caching & Concurrency Safeguards
 * Milestone 1: Security Data Aggregation & Threat Intelligence Layer
 * 
 * Interacts with the FastAPI backend endpoints via Vite dev server proxy (/api).
 */

import axios from 'axios';

// Single reusable Axios client
const apiClient = axios.create({
  baseURL: '/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// In-memory cache store: key -> { timestamp, data }
const cacheStore = new Map();
const DEFAULT_TTL_MS = 30000; // 30 seconds TTL

/**
 * Clear all cached API responses (used during logout and manual/auto refresh)
 */
export const clearApiCache = () => {
  cacheStore.clear();
};

/**
 * Generic cached GET request helper
 */
const fetchWithCache = async (url, params = {}, options = {}) => {
  const forceRefresh = options.forceRefresh === true;
  const ttl = options.ttl || DEFAULT_TTL_MS;
  const queryString = new URLSearchParams(params).toString();
  const cacheKey = queryString ? `${url}?${queryString}` : url;
  const now = Date.now();

  if (!forceRefresh && cacheStore.has(cacheKey)) {
    const cached = cacheStore.get(cacheKey);
    if (now - cached.timestamp < ttl) {
      return cached.data;
    }
  }

  const response = await apiClient.get(url, { params });
  cacheStore.set(cacheKey, { timestamp: now, data: response.data });
  return response.data;
};

/**
 * GET /health - Checks FastAPI service and MongoDB database connectivity
 */
export const getHealth = async () => {
  const response = await apiClient.get('/health');
  return response.data;
};

/**
 * GET /events - Retrieves paginated security telemetry records with optional filters & search
 */
export const getEvents = async (params = {}, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get('/events', { params });
    return response.data;
  }
  return fetchWithCache('/events', params, options);
};

/**
 * GET /metrics - Computes aggregate dashboard metrics
 */
export const getMetrics = async (options = {}) => {
  return fetchWithCache('/metrics', {}, options);
};

/**
 * GET /events/trend - Computes hourly time-series event activity
 */
export const getEventTrend = async (options = {}) => {
  return fetchWithCache('/events/trend', {}, options);
};

/**
 * GET /mitre - Retrieves MITRE ATT&CK coverage statistics
 */
export const getMitre = async (options = {}) => {
  return fetchWithCache('/mitre', {}, options);
};

/**
 * GET /assets - Retrieves IT asset inventory enriched with CVE context
 */
export const getAssets = async (options = {}) => {
  return fetchWithCache('/assets', {}, options);
};

/**
 * GET /threat-intel - Retrieves IoC threat intelligence records
 */
export const getThreatIntel = async (options = {}) => {
  return fetchWithCache('/threat-intel', {}, options);
};

export default apiClient;
