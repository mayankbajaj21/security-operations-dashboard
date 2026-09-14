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

// Attach Authorization Bearer token to requests if available
apiClient.interceptors.request.use((config) => {
  try {
    const token = localStorage.getItem('soc_access_token') || sessionStorage.getItem('soc_access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  } catch (e) {
    // Non-blocking storage access
  }
  return config;
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

/* ==========================================================================
 * Milestone 2: Prediction APIs
 * ========================================================================== */

/**
 * POST /predict - Triggers real-time ML inference & security threat classification
 */
export const predictEvent = async (payload) => {
  const response = await apiClient.post('/predict', payload);
  return response.data;
};

/**
 * GET /predictions - Retrieves paginated stored threat predictions from MongoDB
 */
export const getPredictions = async (params = {}, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get('/predictions', { params });
    return response.data;
  }
  return fetchWithCache('/predictions', params, options);
};

/**
 * GET /predictions/{event_id} - Retrieves a single threat prediction by event ID
 */
export const getPredictionByEventId = async (eventId, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get(`/predictions/${eventId}`);
    return response.data;
  }
  return fetchWithCache(`/predictions/${eventId}`, {}, options);
};

/**
 * GET /anomalies - Retrieves detected suspicious anomaly predictions
 */
export const getAnomalies = async (params = {}, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get('/anomalies', { params });
    return response.data;
  }
  return fetchWithCache('/anomalies', params, options);
};

/**
 * GET /model-performance - Retrieves Isolation Forest evaluation metrics & diagnostics
 */
export const getModelPerformance = async (options = {}) => {
  return fetchWithCache('/model-performance', {}, options);
};

/**
 * GET /threat-summary - Retrieves aggregate threat statistics across all predictions
 */
export const getThreatSummary = async (options = {}) => {
  return fetchWithCache('/threat-summary', {}, options);
};

/* ==========================================================================
 * Milestone 3: Risk Prioritization & Security Intelligence APIs
 * ========================================================================== */

/**
 * POST /v1/risk/calculate - Computes Multi-Factor Risk Score from the 5 normalized M3 pillars
 */
export const calculateRisk = async (payload) => {
  const response = await apiClient.post('/v1/risk/calculate', payload);
  return response.data;
};

/**
 * GET /v1/risk/high - Retrieves paginated high/critical risk events (Risk Score >= min_risk)
 */
export const getHighRisk = async (params = {}, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get('/v1/risk/high', { params });
    return response.data;
  }
  return fetchWithCache('/v1/risk/high', params, options);
};

/**
 * GET /v1/risk/summary - Computes macro risk stats, 5-tier distribution, and top contributing factors
 */
export const getRiskSummary = async (options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get('/v1/risk/summary');
    return response.data;
  }
  return fetchWithCache('/v1/risk/summary', {}, options);
};

/**
 * GET /v1/incidents - Retrieves paginated security incidents with multi-field filtering
 */
export const getIncidents = async (params = {}, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get('/v1/incidents', { params });
    return response.data;
  }
  return fetchWithCache('/v1/incidents', params, options);
};

/**
 * GET /v1/incidents/{incident_id} - Retrieves a single security incident record
 */
export const getIncident = async (incidentId, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get(`/v1/incidents/${incidentId}`);
    return response.data;
  }
  return fetchWithCache(`/v1/incidents/${incidentId}`, {}, options);
};

/**
 * PATCH /v1/incidents/{incident_id}/status - Updates an incident's lifecycle status
 */
export const updateIncidentStatus = async (incidentId, updateData) => {
  const response = await apiClient.patch(`/v1/incidents/${incidentId}/status`, updateData);
  clearApiCache(); // Invalidate cache on mutation
  return response.data;
};

/**
 * GET /v1/recommendations/{incident_id} - Retrieves prescriptive mitigation recommendations for an incident
 */
export const getRecommendations = async (incidentId, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get(`/v1/recommendations/${incidentId}`);
    return response.data;
  }
  return fetchWithCache(`/v1/recommendations/${incidentId}`, {}, options);
};

/**
 * GET /v1/attack-chains - Retrieves correlated multi-stage cyber attack chains
 */
export const getAttackChains = async (params = {}, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get('/v1/attack-chains', { params });
    return response.data;
  }
  return fetchWithCache('/v1/attack-chains', params, options);
};

/* ==========================================================================
 * Milestone 3 — Optional Advanced Features APIs
 * ========================================================================== */

/**
 * GET /v1/risk/weights - Retrieves active 5-pillar calculation weights and defaults
 */
export const getRiskWeights = async (options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get('/v1/risk/weights');
    return response.data;
  }
  return fetchWithCache('/v1/risk/weights', {}, { ...options, ttl: 5000 });
};

/**
 * PUT /v1/risk/weights - Updates 5-pillar risk calculation weights
 */
export const updateRiskWeights = async (weightsPayload) => {
  const response = await apiClient.put('/v1/risk/weights', weightsPayload);
  clearApiCache();
  return response.data;
};

/**
 * POST /v1/risk/weights/reset - Resets risk weights to authoritative M3 defaults (25/25/20/20/10)
 */
export const resetRiskWeights = async () => {
  const response = await apiClient.post('/v1/risk/weights/reset');
  clearApiCache();
  return response.data;
};

/**
 * GET /v1/risk/comparison/{event_id} - Retrieves Before vs After correlation comparison
 */
export const getRiskComparison = async (eventId, options = {}) => {
  if (options.noCache) {
    const response = await apiClient.get(`/v1/risk/comparison/${eventId}`);
    return response.data;
  }
  return fetchWithCache(`/v1/risk/comparison/${eventId}`, {}, options);
};

/**
 * POST /v1/incidents/{incident_id}/feedback - Submits True/False Positive analyst feedback
 */
export const submitIncidentFeedback = async (incidentId, feedbackData) => {
  const response = await apiClient.post(`/v1/incidents/${incidentId}/feedback`, feedbackData);
  clearApiCache();
  return response.data;
};

/* ==========================================================================
 * Authentication APIs
 * ========================================================================== */

/**
 * POST /v1/auth/login - Authenticates analyst credentials and returns JWT Bearer token
 */
export const loginUser = async (email, password) => {
  const response = await apiClient.post('/v1/auth/login', {
    email: email ? email.trim().toLowerCase() : '',
    password: password
  });
  return response.data;
};

/**
 * POST /v1/auth/register - Registers a new analyst user account
 */
export const registerUser = async (payload) => {
  const response = await apiClient.post('/v1/auth/register', payload);
  return response.data;
};

/**
 * GET /v1/auth/me - Retrieves active session profile from Bearer token
 */
export const getCurrentAuthUser = async () => {
  const response = await apiClient.get('/v1/auth/me');
  return response.data;
};

export default apiClient;


