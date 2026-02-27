const components = [
    { name: 'FastAPI Backend', status: 'online', detail: 'Port 8000' },
    { name: 'PostgreSQL DB', status: 'online', detail: 'Port 5432' },
    { name: 'WebSocket Stream', status: 'pending', detail: 'Phase 2' },
    { name: 'Snort IDS', status: 'offline', detail: 'Phase 2' },
    { name: 'OSSEC Agent', status: 'offline', detail: 'Phase 2' },
    { name: 'AI NLP Engine', status: 'pending', detail: 'Phase 3' },
    { name: 'MITRE ATT&CK Feed', status: 'pending', detail: 'Phase 3' },
];

function StatusPanel() {
    return (
        <div className="status-grid">
            {components.map(({ name, status, detail }) => (
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
