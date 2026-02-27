/**
 * AlertCard – Single incident row with MITRE tag and risk score bar.
 */
function AlertCard({ incident }) {
    const {
        severity = 'INFO',
        title = 'Unknown event',
        source = 'unknown',
        src_ip,
        dst_ip,
        port,
        timestamp,
        mitre_id,
        mitre_tactic,
        mitre_technique,
        risk_score,
    } = incident;

    const time = timestamp
        ? new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        : '—';

    const sourceIcon = { snort: '🦈', ossec: '🐧', simulator: '🤖', firewall: '🔥' }[source] || '📋';

    // Risk score bar gradient
    const riskPct = risk_score != null ? Math.min((risk_score / 10) * 100, 100) : 0;
    const riskColor = risk_score >= 8 ? '#fc6a6a' : risk_score >= 6 ? '#f6c50e' : '#48bb78';

    return (
        <div className="alert-item" id={`alert-${incident.id}`}>
            {/* Severity badge */}
            <span className={`alert-severity sev-${severity}`}>{severity}</span>

            {/* Main content */}
            <div className="alert-body">
                <div className="alert-title">{title}</div>
                <div className="alert-meta-row">
                    {sourceIcon} {source.toUpperCase()}
                    {src_ip && <> &nbsp;·&nbsp; <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{src_ip}{dst_ip ? ` → ${dst_ip}` : ''}{port ? `:${port}` : ''}</span></>}
                    &nbsp;·&nbsp; {time}
                </div>

                {/* MITRE tag */}
                {mitre_id && (
                    <div className="alert-mitre-tag">
                        <span className="mitre-id-sm">[{mitre_id}]</span>
                        <span className="mitre-name-sm">{mitre_technique}</span>
                        <span className="mitre-tactic-sm">· {mitre_tactic}</span>
                    </div>
                )}
            </div>

            {/* Risk score bar */}
            {risk_score != null && (
                <div className="risk-bar-wrapper" title={`Risk: ${risk_score}/10`}>
                    <div className="risk-val">{risk_score.toFixed(1)}</div>
                    <div className="risk-bar-track">
                        <div
                            className="risk-bar-fill"
                            style={{ width: `${riskPct}%`, background: riskColor }}
                        />
                    </div>
                </div>
            )}
        </div>
    );
}

export default AlertCard;

