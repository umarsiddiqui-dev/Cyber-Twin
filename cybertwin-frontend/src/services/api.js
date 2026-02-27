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

// ── Request interceptor: attach Bearer token ──────────────────────────────────
apiClient.interceptors.request.use((config) => {
    const token = getToken();
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// ── Response interceptor: handle 401 (token expired / invalid) ───────────────
apiClient.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            // Clear stale token and redirect to login
            logout();
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);

// ── Chat ──────────────────────────────────────────────────────────────────────

export async function sendMessage(message, sessionId = null) {
    const payload = { message };
    if (sessionId) payload.session_id = sessionId;
    const response = await apiClient.post('/chat', payload);
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

export default apiClient;
