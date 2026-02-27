import { useEffect, useState } from 'react';
import { Bell, Clock } from 'lucide-react';
import { checkHealth } from '../../services/api.js';

function Topbar({ title, subtitle }) {
    const [time, setTime] = useState(new Date());
    const [backendOk, setBackendOk] = useState(null);

    // Update clock every second
    useEffect(() => {
        const t = setInterval(() => setTime(new Date()), 1000);
        return () => clearInterval(t);
    }, []);

    // Health check on mount
    useEffect(() => {
        checkHealth()
            .then(() => setBackendOk(true))
            .catch(() => setBackendOk(false));
    }, []);

    const formattedTime = time.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });

    return (
        <header className="topbar">
            <div className="topbar-left">
                <span className="topbar-title">{title}</span>
                {subtitle && <span className="topbar-subtitle">{subtitle}</span>}
            </div>

            <div className="topbar-right">
                {/* Live clock */}
                <div className="flex items-center gap-8 font-mono text-xs" style={{ color: 'var(--clr-text-muted)' }}>
                    <Clock size={12} />
                    {formattedTime}
                </div>

                {/* Backend status badge */}
                {backendOk !== null && (
                    <span className={`topbar-badge ${backendOk ? 'system-ok' : ''}`}
                        style={!backendOk ? {
                            background: 'rgba(252,75,75,0.12)',
                            color: 'var(--clr-accent-red)',
                            border: '1px solid rgba(252,75,75,0.3)'
                        } : {}}>
                        {backendOk ? '● API Online' : '● API Offline'}
                    </span>
                )}

                {/* Notification bell (stub) */}
                <button
                    aria-label="Notifications"
                    style={{
                        background: 'transparent', border: 'none', cursor: 'pointer',
                        color: 'var(--clr-text-muted)', display: 'flex', alignItems: 'center',
                        transition: 'color 0.15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.color = 'var(--clr-text-primary)'}
                    onMouseLeave={e => e.currentTarget.style.color = 'var(--clr-text-muted)'}
                >
                    <Bell size={16} />
                </button>
            </div>
        </header>
    );
}

export default Topbar;
