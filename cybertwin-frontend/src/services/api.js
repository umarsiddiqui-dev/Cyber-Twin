/**
 * api.js – Updated Phase 1 Security Hardening
 * Axios instance now injects Authorization: Bearer <token> on every request.
 * Handles 401 responses by redirecting to /login automatically.
 * Removed reviewed_by from approveAction and rejectAction — identity comes from JWT.
 */
import axios from 'axios';
import { getToken, logout } from './auth.js';

/**
 * CyberTwin API Client
 * Axios instance pre-configured with base URL and default headers.
 * Vite proxy forwards /api/* → http://localhost:8000
 */
const apiClient = axios.create({
    baseURL: '/api',
    headers: { 'Content-Type': 'application/json' },
    timeout: 15000,
});

/**
 * Separate client for chat — Gemma 4 local inference can take up to 60–90s.
 * All other endpoints keep the snappy 15s timeout.
 */
const chatClient = axios.create({
    baseURL: '/api',
    headers: { 'Content-Type': 'application/json' },
    timeout: 120000,   // 2 minutes — Gemma 4 can be slow on first token
});

// ── Request interceptor: attach Bearer token ────────────────────────────────────────────
const attachToken = (config) => {
    const token = getToken();
    if (token) config.headers.Authorization = `Bearer ${token}`;
    return config;
};
apiClient.interceptors.request.use(attachToken);
chatClient.interceptors.request.use(attachToken);

// ── Response interceptor: handle 401 (token expired / invalid) ─────────────────
const handle401 = (error) => {
    if (error.response?.status === 401) {
        logout();
        window.location.href = '/login';
    }
    return Promise.reject(error);
};
apiClient.interceptors.response.use((r) => r, handle401);
chatClient.interceptors.response.use((r) => r, handle401);

// ── Chat ─────────────────────────────────────────────────────────────────────

/** Send a chat message — uses chatClient (120s timeout for Gemma 4). */
export async function sendMessage(message, sessionId = null) {
    const payload = { message };
    if (sessionId) payload.session_id = sessionId;
    const response = await chatClient.post('/chat', payload);
    return response.data;
}

// ── Health ────────────────────────────────────────────────────────────────────

export async function checkHealth() {
    const response = await apiClient.get('/health');
    return response.data;
}

// ── Incidents ─────────────────────────────────────────────────────────────────

export async function getIncidents() {
    const response = await apiClient.get('/incidents');
    return response.data;
}

// ── Actions ───────────────────────────────────────────────────────────────────

export async function proposeActions(incidentId, sessionId = null) {
    const response = await apiClient.post('/actions/propose', {
        incident_id: incidentId,
        session_id: sessionId,
    });
    return response.data;
}

export async function getActions(status = null) {
    const params = {};
    if (status) params.status = status;
    const response = await apiClient.get('/actions', { params });
    return response.data;
}

/**
 * Approve a pending action.
 * JWT identity is extracted server-side — no reviewed_by needed from client.
 */
export async function approveAction(actionId) {
    const response = await apiClient.post(`/actions/${actionId}/approve`, {});
    return response.data;
}

/**
 * Reject a pending action with a mandatory reason.
 * JWT identity is extracted server-side — no reviewed_by needed from client.
 */
export async function rejectAction(actionId, reason) {
    const response = await apiClient.post(`/actions/${actionId}/reject`, { reason });
    return response.data;
}

// ── ML Classification (Phase 6) ─────────────────────────────────────────────────

/** Run ML traffic classification on a flow. */
export async function mlClassify(features) {
    const response = await apiClient.post('/ml/classify', { features });
    return response.data;
}

/** Get the ML model's current health/status. */
export async function mlStatus() {
    const response = await apiClient.get('/ml/health');
    return response.data;
}

// ── Export (Phase 5) ─────────────────────────────────────────────────────────────────

/** Export incidents as JSON or CSV. */
export async function exportIncidents(format = 'json') {
    const response = await apiClient.get(`/export/incidents?format=${format}`, {
        responseType: format === 'csv' ? 'blob' : 'json',
    });
    return response.data;
}

export default apiClient;
