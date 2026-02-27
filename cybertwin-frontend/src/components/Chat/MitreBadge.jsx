/**
 * MitreBadge – Compact ATT&CK technique chip.
 * Shown beneath AI chat messages when a MITRE technique is identified.
 */
function MitreBadge({ mitreId, mitreTactic, mitreTechnique, confidence }) {
    if (!mitreId) return null;

    const pct = confidence ? Math.round(confidence * 100) : null;

    return (
        <div className="mitre-badge">
            <span className="mitre-id">[{mitreId}]</span>
            <span className="mitre-technique">{mitreTechnique}</span>
            <span className="mitre-separator">·</span>
            <span className="mitre-tactic">{mitreTactic}</span>
            {pct !== null && (
                <span className="mitre-confidence">{pct}%</span>
            )}
        </div>
    );
}

export default MitreBadge;
