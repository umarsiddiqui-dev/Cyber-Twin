import { useRef, useEffect } from 'react';
import useIncidentStore from '../../store/incidentStore.js';
import AlertCard from './AlertCard.jsx';

/**
 * AlertFeed – Phase 2 Live feed.
 * Reads incidents from incidentStore and renders a scrollable alert list.
 */
function AlertFeed() {
    const incidents = useIncidentStore((s) => s.incidents);
    const feedRef = useRef(null);

    // Auto-scroll to top on new alert (newest first)
    useEffect(() => {
        if (feedRef.current && incidents.length > 0) {
            feedRef.current.scrollTop = 0;
        }
    }, [incidents.length]);

    if (incidents.length === 0) {
        return (
            <div className="alert-feed">
                <div className="alert-placeholder">
                    <div style={{ fontSize: 32, marginBottom: 10 }}>📡</div>
                    <div style={{ fontWeight: 600, color: 'var(--clr-text-secondary)', marginBottom: 6 }}>
                        Waiting for alerts…
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--clr-text-muted)' }}>
                        The simulator is active. First alert will appear within 5–12 seconds.
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="alert-feed" ref={feedRef}>
            {incidents.map((inc) => (
                <AlertCard key={inc.id} incident={inc} />
            ))}
        </div>
    );
}

export default AlertFeed;
