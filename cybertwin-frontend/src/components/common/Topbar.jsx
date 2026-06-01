import { useEffect, useState } from 'react';
import { Bell, Clock, Cpu } from 'lucide-react';
import { checkHealth } from '../../services/api.js';

function Topbar({ title, subtitle }) {
    const [time, setTime]           = useState(new Date());
    const [health, setHealth]       = useState(null);
    const [backendOk, setBackendOk] = useState(null);

    // Update clock every second
    useEffect(() => {
        const t = setInterval(() => setTime(new Date()), 1000);
        return () => clearInterval(t);
    }, []);

    // Health check on mount + every 30s
    useEffect(() => {
        const doFetch = () =>
            checkHealth()
                .then((data) => { setHealth(data); setBackendOk(true); })
                .catch(() => { setHealth(null); setBackendOk(false); });
        doFetch();
        const id = setInterval(doFetch, 30000);
        return () => clearInterval(id);
    }, []);

    const formattedTime = time.toLocaleTimeString([], {
        hour: '2-digit', minute: '2-digit', second: '2-digit',
    });

    const ollamaOk  = health?.llm?.ollama_reachable && health?.llm?.model_loaded;
    const modelName = health?.llm?.model ?? 'gemma4:e2b';

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

                {/* Ollama / LLM badge — shown once health is fetched */}
                {health !== null && (
                    <span
                        className={`topbar-badge ${ollamaOk ? 'system-ok' : ''}`}
                        title={ollamaOk ? `${modelName} loaded and ready` : 'Ollama not reachable – using fallback'}
                        style={!ollamaOk ? {
                            background: 'rgba(246,201,14,0.12)',
                            color: 'var(--clr-accent-yellow)',
                            border: '1px solid rgba(246,201,14,0.3)',
                        } : {}}
                    >
                        <Cpu size={10} style={{ marginRight: 4, display: 'inline' }} />
                        {ollamaOk ? modelName : 'LLM offline'}
                    </span>
                )}

                {/* Backend status badge */}
                {backendOk !== null && (
                    <span
                        className={`topbar-badge ${backendOk ? 'system-ok' : ''}`}
                        style={!backendOk ? {
                            background: 'rgba(252,75,75,0.12)',
                            color: 'var(--clr-accent-red)',
                            border: '1px solid rgba(252,75,75,0.3)',
                        } : {}}
                    >
                        {backendOk ? '● API Online' : '● API Offline'}
                    </span>
                )}

                {/* Notification bell */}
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
