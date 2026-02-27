import { useEffect, useRef, useState } from 'react';
import { RefreshCw, Zap, Filter } from 'lucide-react';
import ActionCard from './ActionCard.jsx';
import useActionStore from '../../store/actionStore.js';
import { getActions } from '../../services/api.js';

const POLL_INTERVAL = 12000; // ms — refresh every 12 seconds

const STATUS_FILTERS = ['all', 'pending', 'approved', 'rejected', 'executed'];

/**
 * ApprovalPanel – Full actions list with live polling and status filter tabs.
 * Renders ActionCard for each action. Groups pending first.
 */
function ApprovalPanel() {
    const { actions, isLoading, error, setActions, setLoading, setError } = useActionStore();
    const [filter, setFilter] = useState('all');
    const pollRef = useRef(null);

    const fetchActions = async () => {
        setLoading(true);
        try {
            const data = await getActions(filter === 'all' ? null : filter);
            setActions(data.actions || []);
        } catch (e) {
            setError('Failed to fetch actions. Is the backend running?');
        } finally {
            setLoading(false);
        }
    };

    // Initial fetch + poll
    useEffect(() => {
        fetchActions();
        pollRef.current = setInterval(fetchActions, POLL_INTERVAL);
        return () => clearInterval(pollRef.current);
    }, [filter]); // eslint-disable-line react-hooks/exhaustive-deps

    // Sort: pending first, then by created_at desc
    const sorted = [...actions].sort((a, b) => {
        if (a.status === 'pending' && b.status !== 'pending') return -1;
        if (a.status !== 'pending' && b.status === 'pending') return 1;
        return new Date(b.created_at) - new Date(a.created_at);
    });

    return (
        <div className="approval-panel" style={{ padding: '0 24px 24px' }}>
            {/* Filter + refresh bar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                <Filter size={13} style={{ color: 'var(--clr-text-secondary)' }} />
                {STATUS_FILTERS.map(s => (
                    <button
                        key={s}
                        onClick={() => setFilter(s)}
                        style={{
                            padding: '4px 12px',
                            borderRadius: 99,
                            fontSize: 12,
                            fontWeight: filter === s ? 700 : 400,
                            background: filter === s ? 'var(--clr-accent-cyan)22' : 'var(--clr-bg-elevated)',
                            border: `1px solid ${filter === s ? 'var(--clr-accent-cyan)' : 'var(--clr-border)'}`,
                            color: filter === s ? 'var(--clr-accent-cyan)' : 'var(--clr-text-secondary)',
                            cursor: 'pointer',
                            textTransform: 'capitalize',
                            transition: 'all 0.15s',
                        }}
                    >
                        {s}
                    </button>
                ))}

                <button
                    onClick={fetchActions}
                    title="Refresh actions"
                    disabled={isLoading}
                    style={{
                        marginLeft: 'auto',
                        background: 'none',
                        border: '1px solid var(--clr-border)',
                        borderRadius: 6,
                        padding: '4px 10px',
                        color: 'var(--clr-text-secondary)',
                        cursor: isLoading ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        fontSize: 12,
                    }}
                >
                    <RefreshCw size={12} style={{ animation: isLoading ? 'spin 1s linear infinite' : 'none' }} />
                    Refresh
                </button>
            </div>

            {/* Error state */}
            {error && (
                <div style={{
                    background: '#ff4d4d18',
                    border: '1px solid #ff4d4d',
                    borderRadius: 8,
                    padding: '10px 14px',
                    color: '#ff4d4d',
                    fontSize: 13,
                    marginBottom: 14,
                }}>
                    ⚠️ {error}
                </div>
            )}

            {/* Empty state */}
            {!isLoading && sorted.length === 0 && !error && (
                <div style={{
                    textAlign: 'center',
                    padding: '60px 0',
                    color: 'var(--clr-text-secondary)',
                }}>
                    <div style={{ fontSize: 40, marginBottom: 12 }}>⚡</div>
                    <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>No actions yet</div>
                    <div style={{ fontSize: 13 }}>
                        Propose actions from an incident in the Dashboard, or wait for the AI to detect a threat.
                    </div>
                </div>
            )}

            {/* Action cards */}
            {sorted.map(action => (
                <ActionCard key={action.id} action={action} />
            ))}

            {/* Loading skeleton */}
            {isLoading && sorted.length === 0 && (
                [...Array(3)].map((_, i) => (
                    <div key={i} style={{
                        height: 120,
                        background: 'var(--clr-bg-card)',
                        borderRadius: 10,
                        marginBottom: 12,
                        animation: 'pulse 1.5s ease-in-out infinite',
                        opacity: 0.5,
                    }} />
                ))
            )}
        </div>
    );
}

export default ApprovalPanel;
