/**
 * LoginPage.jsx – Phase 1 Security Hardening
 * Full-screen login form that authenticates the analyst against the backend
 * JWT endpoint. On success, redirects to /dashboard.
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login } from '../services/auth.js';

function LoginPage() {
    const navigate = useNavigate();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setLoading(true);
        try {
            await login(username, password);
            navigate('/dashboard', { replace: true });
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'var(--clr-bg-primary, #0a0e1a)',
            fontFamily: "'Inter', sans-serif",
        }}>
            <div style={{
                width: 380,
                background: 'var(--clr-bg-card, #121929)',
                border: '1px solid var(--clr-border, #1e2d4a)',
                borderRadius: 16,
                padding: '40px 36px',
                boxShadow: '0 8px 40px rgba(0,0,0,0.5)',
            }}>
                {/* Logo / Title */}
                <div style={{ textAlign: 'center', marginBottom: 32 }}>
                    <div style={{ fontSize: 36, marginBottom: 8 }}>🛡️</div>
                    <h1 style={{
                        fontSize: 22,
                        fontWeight: 700,
                        color: 'var(--clr-text-primary, #e0e6f0)',
                        margin: 0,
                        letterSpacing: '-0.3px',
                    }}>
                        CyberTwin SOC
                    </h1>
                    <p style={{
                        fontSize: 13,
                        color: 'var(--clr-text-secondary, #6b7fa3)',
                        margin: '6px 0 0',
                    }}>
                        AI-Powered SOC Assistant
                    </p>
                </div>

                {/* Error banner */}
                {error && (
                    <div style={{
                        background: '#ff4d4d18',
                        border: '1px solid #ff4d4d',
                        borderRadius: 8,
                        padding: '10px 14px',
                        color: '#ff4d4d',
                        fontSize: 13,
                        marginBottom: 20,
                    }}>
                        ⚠️ {error}
                    </div>
                )}

                <form onSubmit={handleSubmit}>
                    {/* Username */}
                    <div style={{ marginBottom: 16 }}>
                        <label style={{
                            display: 'block',
                            fontSize: 12,
                            fontWeight: 600,
                            color: 'var(--clr-text-secondary, #6b7fa3)',
                            marginBottom: 6,
                            letterSpacing: 0.5,
                            textTransform: 'uppercase',
                        }}>
                            Username
                        </label>
                        <input
                            id="login-username"
                            type="text"
                            value={username}
                            onChange={e => setUsername(e.target.value)}
                            autoComplete="username"
                            required
                            style={{
                                width: '100%',
                                background: 'var(--clr-bg-elevated, #1a2540)',
                                border: '1px solid var(--clr-border, #1e2d4a)',
                                borderRadius: 8,
                                padding: '10px 14px',
                                color: 'var(--clr-text-primary, #e0e6f0)',
                                fontSize: 14,
                                boxSizing: 'border-box',
                                outline: 'none',
                                transition: 'border-color 0.2s',
                            }}
                            placeholder="admin"
                        />
                    </div>

                    {/* Password */}
                    <div style={{ marginBottom: 24 }}>
                        <label style={{
                            display: 'block',
                            fontSize: 12,
                            fontWeight: 600,
                            color: 'var(--clr-text-secondary, #6b7fa3)',
                            marginBottom: 6,
                            letterSpacing: 0.5,
                            textTransform: 'uppercase',
                        }}>
                            Password
                        </label>
                        <input
                            id="login-password"
                            type="password"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            autoComplete="current-password"
                            required
                            style={{
                                width: '100%',
                                background: 'var(--clr-bg-elevated, #1a2540)',
                                border: '1px solid var(--clr-border, #1e2d4a)',
                                borderRadius: 8,
                                padding: '10px 14px',
                                color: 'var(--clr-text-primary, #e0e6f0)',
                                fontSize: 14,
                                boxSizing: 'border-box',
                                outline: 'none',
                            }}
                            placeholder="••••••••"
                        />
                    </div>

                    {/* Submit */}
                    <button
                        id="login-submit"
                        type="submit"
                        disabled={loading || !username || !password}
                        style={{
                            width: '100%',
                            background: loading
                                ? 'var(--clr-accent-cyan, #00c8f8)33'
                                : 'linear-gradient(135deg, #00c8f8, #0080ff)',
                            border: 'none',
                            borderRadius: 8,
                            padding: '12px 0',
                            color: '#fff',
                            fontSize: 15,
                            fontWeight: 700,
                            cursor: loading ? 'not-allowed' : 'pointer',
                            letterSpacing: 0.3,
                            transition: 'opacity 0.2s',
                            opacity: (!username || !password) ? 0.6 : 1,
                        }}
                    >
                        {loading ? '⏳ Authenticating…' : '🔐 Sign In'}
                    </button>
                </form>

                <p style={{
                    textAlign: 'center',
                    fontSize: 11,
                    color: 'var(--clr-text-secondary, #6b7fa3)',
                    marginTop: 24,
                    opacity: 0.7,
                }}>
                    CyberTwin v5.1 · Secured by JWT
                </p>
            </div>
        </div>
    );
}

export default LoginPage;
