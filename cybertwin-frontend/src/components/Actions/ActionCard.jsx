import { useState } from 'react';
import { CheckCircle, XCircle, Terminal, Clock, Shield, Zap } from 'lucide-react';
import { approveAction, rejectAction } from '../../services/api.js';
import useActionStore from '../../store/actionStore.js';

/**
 * ActionCard – Displays a single proposed remediation action.
 * Features:
 *   - Colour-coded action type badge
 *   - AI-generated reason/justification
 *   - Command preview in monospace code block
 *   - Approve / Reject buttons (disabled once actioned)
 *   - Live status chip update on interaction
 */

const ACTION_COLORS = {
    block_ip: { bg: '#ff4d4d22', border: '#ff4d4d', icon: '🔴', label: 'Block IP' },
    add_firewall_rule: { bg: '#ff8c0022', border: '#ff8c00', icon: '🟠', label: 'Firewall Rule' },
    isolate_host: { bg: '#ff000033', border: '#ff0000', icon: '⛔', label: 'Isolate Host' },
    kill_process: { bg: '#ffff0022', border: '#ffd700', icon: '🟡', label: 'Kill Process' },
    run_scan: { bg: '#00bfff22', border: '#00bfff', icon: '🔵', label: 'Run Scan' },
};

const STATUS_STYLES = {
    pending: { color: 'var(--clr-accent-yellow)', label: 'PENDING' },
    approved: { color: 'var(--clr-accent-green)', label: 'APPROVED' },
    rejected: { color: '#888', label: 'REJECTED' },
    executed: { color: 'var(--clr-accent-cyan)', label: 'EXECUTED' },
    failed: { color: '#ff4d4d', label: 'FAILED' },
};

function ActionCard({ action }) {
    const [busy, setBusy] = useState(false);
    const [rejectReason, setRejectReason] = useState('');
    const [showRejectInput, setShowRejectInput] = useState(false);
    const updateAction = useActionStore(s => s.updateAction);

    const typeInfo = ACTION_COLORS[action.action_type] || { bg: '#ffffff11', border: '#555', icon: '⚙️', label: action.action_type };
    const statusInfo = STATUS_STYLES[action.status] || STATUS_STYLES.pending;
    const isPending = action.status === 'pending';

    const handleApprove = async () => {
        if (busy) return;
        setBusy(true);
        try {
            // reviewed_by is bound to JWT identity on the backend — no need to pass it
            const updated = await approveAction(action.id);
            updateAction(updated);
        } catch (err) {
            console.error('Approve failed:', err);
        } finally {
            setBusy(false);
        }
    };

    const handleReject = async () => {
        if (!showRejectInput) { setShowRejectInput(true); return; }
        if (!rejectReason.trim() || busy) return;
        setBusy(true);
        try {
            // reviewed_by is bound to JWT identity on the backend — no need to pass it
            const updated = await rejectAction(action.id, rejectReason);
            updateAction(updated);
            setShowRejectInput(false);
        } catch (err) {
            console.error('Reject failed:', err);
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="action-card" style={{
            background: 'var(--clr-bg-card)',
            border: `1px solid ${typeInfo.border}44`,
            borderLeft: `3px solid ${typeInfo.border}`,
            borderRadius: 10,
            padding: 16,
            marginBottom: 12,
            opacity: isPending ? 1 : 0.75,
            transition: 'opacity 0.3s',
        }}>
            {/* Header row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                <span style={{
                    fontSize: 11,
                    fontWeight: 700,
                    background: typeInfo.bg,
                    border: `1px solid ${typeInfo.border}`,
                    borderRadius: 4,
                    padding: '2px 8px',
                    color: typeInfo.border,
                    letterSpacing: 0.5,
                }}>
                    {typeInfo.icon} {typeInfo.label.toUpperCase()}
                </span>

                <span style={{
                    marginLeft: 'auto',
                    fontSize: 11,
                    fontWeight: 700,
                    color: statusInfo.color,
                    letterSpacing: 0.5,
                }}>
                    ● {statusInfo.label}
                </span>
            </div>

            {/* Reason */}
            {action.reason && (
                <p style={{ fontSize: 13, color: 'var(--clr-text-secondary)', marginBottom: 10, lineHeight: 1.5 }}>
                    {action.reason}
                </p>
            )}

            {/* Command preview */}
            <div style={{
                background: 'var(--clr-bg-elevated)',
                border: '1px solid var(--clr-border)',
                borderRadius: 6,
                padding: '8px 12px',
                marginBottom: 12,
                display: 'flex',
                alignItems: 'flex-start',
                gap: 8,
            }}>
                <Terminal size={13} style={{ color: 'var(--clr-accent-cyan)', marginTop: 2, flexShrink: 0 }} />
                <code style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--clr-accent-green)', wordBreak: 'break-all' }}>
                    {action.command}
                </code>
            </div>

            {/* Execution output (after approved/executed) */}
            {action.execution_output && (
                <div style={{
                    background: '#00000044',
                    border: '1px solid var(--clr-border)',
                    borderRadius: 6,
                    padding: '8px 12px',
                    marginBottom: 12,
                    fontSize: 11,
                    fontFamily: 'monospace',
                    color: 'var(--clr-text-secondary)',
                    whiteSpace: 'pre-wrap',
                }}>
                    {action.execution_output}
                </div>
            )}

            {/* Reject reason input */}
            {showRejectInput && isPending && (
                <div style={{ marginBottom: 10 }}>
                    <input
                        type="text"
                        placeholder="Reason for rejection (required)…"
                        value={rejectReason}
                        onChange={e => setRejectReason(e.target.value)}
                        style={{
                            width: '100%',
                            background: 'var(--clr-bg-elevated)',
                            border: '1px solid var(--clr-border)',
                            borderRadius: 6,
                            padding: '6px 10px',
                            color: 'var(--clr-text-primary)',
                            fontSize: 13,
                            boxSizing: 'border-box',
                        }}
                    />
                </div>
            )}

            {/* Action buttons */}
            {isPending && (
                <div style={{ display: 'flex', gap: 8 }}>
                    <button
                        id={`approve-${action.id}`}
                        onClick={handleApprove}
                        disabled={busy}
                        style={{
                            flex: 1,
                            background: 'rgba(0,200,83,0.12)',
                            border: '1px solid var(--clr-accent-green)',
                            borderRadius: 6,
                            color: 'var(--clr-accent-green)',
                            padding: '7px 0',
                            fontSize: 13,
                            fontWeight: 600,
                            cursor: busy ? 'not-allowed' : 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 6,
                            transition: 'background 0.2s',
                        }}
                    >
                        <CheckCircle size={14} /> {busy ? 'Processing…' : 'Approve'}
                    </button>
                    <button
                        id={`reject-${action.id}`}
                        onClick={handleReject}
                        disabled={busy}
                        style={{
                            flex: 1,
                            background: 'rgba(255,77,77,0.10)',
                            border: '1px solid #ff4d4d',
                            borderRadius: 6,
                            color: '#ff4d4d',
                            padding: '7px 0',
                            fontSize: 13,
                            fontWeight: 600,
                            cursor: busy ? 'not-allowed' : 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 6,
                            transition: 'background 0.2s',
                        }}
                    >
                        <XCircle size={14} /> {showRejectInput ? 'Confirm Reject' : 'Reject'}
                    </button>
                </div>
            )}

            {/* Reviewed by info */}
            {action.reviewed_by && (
                <div style={{ marginTop: 10, fontSize: 11, color: 'var(--clr-text-secondary)' }}>
                    Reviewed by <strong>{action.reviewed_by}</strong>
                    {action.reviewed_at && ` · ${new Date(action.reviewed_at).toLocaleString()}`}
                    {action.reject_reason && ` · "${action.reject_reason}"`}
                </div>
            )}
        </div>
    );
}

export default ActionCard;
