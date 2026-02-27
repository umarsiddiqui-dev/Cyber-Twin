import { useState, useEffect } from 'react';
import { Play, Square, Zap } from 'lucide-react';
import { getActions as _unused } from '../../services/api.js';
import apiClient from '../../services/api.js';

const SEVERITY_COLORS = {
    CRITICAL: '#ff4d4d',
    HIGH: '#ff8c00',
    MEDIUM: '#ffd700',
    LOW: '#00bfff',
};

/**
 * ScenarioLauncher – lets analysts trigger realistic attack scenarios
 * that flow through the full CyberTwin pipeline (parse → enrich → broadcast).
 */
function ScenarioLauncher() {
    const [scenarios, setScenarios] = useState([]);
    const [selected, setSelected] = useState('');
    const [running, setRunning] = useState(false);
    const [runningId, setRunningId] = useState(null);
    const [statusMsg, setStatusMsg] = useState('');
    const [elapsed, setElapsed] = useState(0);

    // Load scenario list on mount
    useEffect(() => {
        apiClient.get('/simulation/scenarios')
            .then(r => {
                setScenarios(r.data);
                if (r.data.length) setSelected(r.data[0].id);
            })
            .catch(() => setStatusMsg('Could not load scenarios.'));
    }, []);

    // Poll status + elapsed timer
    useEffect(() => {
        let interval;
        if (running) {
            const start = Date.now();
            interval = setInterval(() => {
                setElapsed(Math.floor((Date.now() - start) / 1000));
                apiClient.get('/simulation/status')
                    .then(r => {
                        if (!r.data.running) {
                            setRunning(false);
                            setRunningId(null);
                            setStatusMsg('✅ Scenario complete. Check the dashboard for new alerts.');
                            clearInterval(interval);
                        }
                    })
                    .catch(() => { });
            }, 2000);
        }
        return () => clearInterval(interval);
    }, [running]);

    const handleRun = async () => {
        if (!selected) return;
        setStatusMsg('');
        setElapsed(0);
        try {
            await apiClient.post('/simulation/run', { scenario_id: selected });
            setRunning(true);
            setRunningId(selected);
            const name = scenarios.find(s => s.id === selected)?.name || selected;
            setStatusMsg(`▶ Running: ${name}`);
        } catch (e) {
            setStatusMsg(e.response?.data?.detail || 'Failed to start scenario.');
        }
    };

    const handleStop = async () => {
        try {
            await apiClient.post('/simulation/stop');
            setRunning(false);
            setRunningId(null);
            setStatusMsg('⏹ Scenario stopped.');
        } catch { /* ignore */ }
    };

    const selectedMeta = scenarios.find(s => s.id === selected);

    return (
        <div style={{
            background: 'var(--clr-bg-card)',
            border: '1px solid var(--clr-border)',
            borderRadius: 10,
            padding: 16,
            marginBottom: 20,
        }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                <Zap size={15} style={{ color: 'var(--clr-accent-yellow)' }} />
                <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--clr-text-primary)' }}>
                    Attack Scenario Simulator
                </span>
                <span style={{ fontSize: 11, color: 'var(--clr-text-secondary)', marginLeft: 4 }}>
                    Atomic Red Team–inspired
                </span>
            </div>

            {/* Scenario selector */}
            <select
                id="scenario-select"
                value={selected}
                onChange={e => setSelected(e.target.value)}
                disabled={running}
                style={{
                    width: '100%',
                    background: 'var(--clr-bg-elevated)',
                    border: '1px solid var(--clr-border)',
                    borderRadius: 6,
                    padding: '7px 10px',
                    color: 'var(--clr-text-primary)',
                    fontSize: 13,
                    marginBottom: 10,
                    cursor: running ? 'not-allowed' : 'pointer',
                }}
            >
                {scenarios.map(s => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                ))}
            </select>

            {/* Metadata strip */}
            {selectedMeta && (
                <div style={{ fontSize: 12, color: 'var(--clr-text-secondary)', marginBottom: 12, lineHeight: 1.5 }}>
                    <span style={{
                        background: `${SEVERITY_COLORS[selectedMeta.severity]}22`,
                        border: `1px solid ${SEVERITY_COLORS[selectedMeta.severity]}`,
                        color: SEVERITY_COLORS[selectedMeta.severity],
                        borderRadius: 4,
                        padding: '1px 6px',
                        fontSize: 10,
                        fontWeight: 700,
                        marginRight: 8,
                    }}>{selectedMeta.severity}</span>
                    {selectedMeta.description}
                    {' · '}
                    <span style={{ color: 'var(--clr-accent-cyan)' }}>
                        {selectedMeta.log_count} logs · ~{selectedMeta.duration_seconds}s
                    </span>
                </div>
            )}

            {/* Controls */}
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {!running ? (
                    <button
                        id="run-scenario-btn"
                        onClick={handleRun}
                        disabled={!selected || scenarios.length === 0}
                        style={{
                            flex: 1,
                            background: 'rgba(0,200,83,0.12)',
                            border: '1px solid var(--clr-accent-green)',
                            borderRadius: 6,
                            color: 'var(--clr-accent-green)',
                            padding: '8px 0',
                            fontWeight: 700,
                            fontSize: 13,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 6,
                        }}
                    >
                        <Play size={14} /> Run Scenario
                    </button>
                ) : (
                    <button
                        id="stop-scenario-btn"
                        onClick={handleStop}
                        style={{
                            flex: 1,
                            background: 'rgba(255,77,77,0.12)',
                            border: '1px solid #ff4d4d',
                            borderRadius: 6,
                            color: '#ff4d4d',
                            padding: '8px 0',
                            fontWeight: 700,
                            fontSize: 13,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 6,
                        }}
                    >
                        <Square size={14} /> Stop ({elapsed}s)
                    </button>
                )}
            </div>

            {/* Status message */}
            {statusMsg && (
                <div style={{
                    marginTop: 10,
                    fontSize: 12,
                    color: running ? 'var(--clr-accent-yellow)' : 'var(--clr-text-secondary)',
                    animation: running ? 'pulse 1.5s ease-in-out infinite' : 'none',
                }}>
                    {statusMsg}
                </div>
            )}
        </div>
    );
}

export default ScenarioLauncher;
