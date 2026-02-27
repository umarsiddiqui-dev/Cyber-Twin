/**
 * auth.js – Phase 1 Security Hardening
 * Client-side JWT authentication service.
 *
 * Provides:
 *   login(username, password)  → calls POST /api/auth/login, stores token
 *   logout()                   → clears token from localStorage
 *   getToken()                 → returns stored JWT string or null
 *   isAuthenticated()          → true if a token exists
 *   getAuthHeaders()           → { Authorization: 'Bearer <token>' } object
 */

const TOKEN_KEY = 'cybertwin_access_token';
const USERNAME_KEY = 'cybertwin_username';

const BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

/**
 * Log in with username and password.
 * Stores the returned JWT in localStorage.
 *
 * @param {string} username
 * @param {string} password
 * @returns {Promise<{ access_token: string, username: string, expires_in: number }>}
 * @throws {Error} with a user-friendly message on failure
 */
export async function login(username, password) {
    // OAuth2PasswordRequestForm expects form-encoded body
    const body = new URLSearchParams({ username, password });

    const response = await fetch(`${BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
    });

    if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.detail || 'Login failed. Check your credentials.');
    }

    const data = await response.json();
    localStorage.setItem(TOKEN_KEY, data.access_token);
    localStorage.setItem(USERNAME_KEY, data.username);
    return data;
}

/**
 * Clear the stored JWT (log out).
 */
export function logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USERNAME_KEY);
}

/**
 * Get the stored JWT string, or null if not logged in.
 * @returns {string|null}
 */
export function getToken() {
    return localStorage.getItem(TOKEN_KEY);
}

/**
 * Get the stored username, or null if not logged in.
 * @returns {string|null}
 */
export function getUsername() {
    return localStorage.getItem(USERNAME_KEY);
}

/**
 * Return true if the user has a stored token.
 * NOTE: Does not validate expiry client-side; the server will reject expired tokens.
 * @returns {boolean}
 */
export function isAuthenticated() {
    return Boolean(getToken());
}

/**
 * Return the Authorization header object for use in fetch/axios calls.
 * Returns an empty object if the user is not authenticated.
 * @returns {Record<string, string>}
 */
export function getAuthHeaders() {
    const token = getToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
}
