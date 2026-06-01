import { useEffect, useState } from 'react';
import { checkHealth } from '../../services/api.js';
import useIncidentStore from '../../store/incidentStore.js';

/**
 * StatusPanel – Live system component status.
 * Phase 7: fetches /api/health to show real Ollama + backend state.
 */
function StatusPanel() {
    const [health, setHealth] = useState(null);
    const connectionStatus = useIncidentStore((s) => s.connectionStatus);

    useEffect(() => {
        const fetchHealth = () => {
            checkHealth()
                .then(setHealth)
                .catch(() => setHealth(null));
        };
        fetchHealth();
        const id = setInterval(fetchHealth, 30000); // refresh every 30s
        return () => clearInterval(id);
    }, []);

    const ollamaReachable = health?.llm?.ollama_reachable;
    const modelLoaded     = health?.llm?.model_loaded;
    const modelName       = health?.llm?.model ?? 'gemma4:e2b';

    const wsStatus = connectionStatus === 'connected'
        ? 'online' : connectionStatus === 'connecting' ? 'pending' : 'offline';

    const rows = [
        {
            name: 'FastAPI Backend',
            status: health !== null ? 'online' : 'offline',
            detail: 'Port 8000',
        },
        {
            name: 'SQLite Database',
            status: health !== null ? 'online' : 'offline',
            detail: 'aiosqlite',
        },
        {
            name: 'WebSocket Stream',
            status: wsStatus,
            detail: wsStatus === 'connected' ? '● LIVE' : 'ws/logs',
        },
        {
            name: `Ollama LLM (${modelName})`,
            status: ollamaReachable && modelLoaded ? 'online'
                  : ollamaReachable             ? 'pending'
                  : 'offline',
            detail: ollamaReachable && modelLoaded ? '✅ Gemma 4 ready'
                  : ollamaReachable               ? '⚠️ Model not pulled'
                  : '⚠️ Start ollama serve',
        },
        {
            name: 'MITRE ATT&CK Feed',
            status: health !== null ? 'online' : 'offline',
            detail: 'Local index',
        },
        {
            name: 'ML Classifier',
            status: health !== null ? 'online' : 'pending',
            detail: 'LightGBM + RF',
        },
        {
            name: 'Context Indexer',
            status: health?.context_indexer ? 'online' : 'pending',
            detail: health?.context_indexer
                ? `${health.context_indexer.files_indexed} files`
                : '—',
        },
    ];

    return (
        <div className="status-grid">
            {rows.map(({ name, status, detail }) => (
                <div className="status-row" key={name}>
                    <span className="status-name">{name}</span>
                    <div className="flex items-center gap-8">
                        <span style={{ fontSize: 11, color: 'var(--clr-text-muted)' }}>{detail}</span>
                        <span className={`status-badge ${status}`}>
                            {status.charAt(0).toUpperCase() + status.slice(1)}
                        </span>
                    </div>
                </div>
            ))}
        </div>
    );
}

export default StatusPanel;
