import useIncidentStore from '../../store/incidentStore.js';

const SEV_CONFIG = [
    { key: 'critical', label: 'Critical', icon: '🔴', colorClass: 'red' },
    { key: 'high', label: 'High', icon: '🟠', colorClass: 'red' },
    { key: 'medium', label: 'Medium', icon: '🟡', colorClass: 'yellow' },
    { key: 'low', label: 'Low', icon: '🟢', colorClass: 'green' },
];

/**
 * IncidentStats – Live stat cards driven by the incidentStore.
 * Replaces the static "0" placeholders on the Dashboard.
 */
function IncidentStats() {
    const stats = useIncidentStore((s) => s.stats);
    const connectionStatus = useIncidentStore((s) => s.connectionStatus);

    return (
        <div className="stats-grid">
            {/* Total alerts */}
            <div className="stat-card">
                <div className="stat-icon cyan">🎯</div>
                <div>
                    <div className="stat-value">{stats.total}</div>
                    <div className="stat-label">
                        Total Alerts
                        <span style={{
                            marginLeft: 6, fontSize: 10, fontWeight: 600, padding: '1px 6px',
                            borderRadius: 99,
                            background: connectionStatus === 'connected'
                                ? 'rgba(72,187,120,0.12)' : 'rgba(246,201,14,0.12)',
                            color: connectionStatus === 'connected'
                                ? 'var(--clr-accent-green)' : 'var(--clr-accent-yellow)',
                        }}>
                            {connectionStatus === 'connected' ? '● LIVE' : connectionStatus === 'connecting' ? '◌ …' : '○ offline'}
                        </span>
                    </div>
                </div>
            </div>

            {/* Per-severity cards */}
            {SEV_CONFIG.map(({ key, label, icon, colorClass }) => (
                <div className="stat-card" key={key}>
                    <div className={`stat-icon ${colorClass}`}>{icon}</div>
                    <div>
                        <div className="stat-value">{stats[key]}</div>
                        <div className="stat-label">{label} Alerts</div>
                    </div>
                </div>
            ))}
        </div>
    );
}

export default IncidentStats;
