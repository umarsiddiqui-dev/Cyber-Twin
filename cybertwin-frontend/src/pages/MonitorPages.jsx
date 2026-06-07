import React, { useState, useEffect, useMemo } from 'react';
import { getIncidents, exportIncidents, proposeActions } from '../services/api.js';
import Sidebar from '../components/common/Sidebar.jsx';
import Topbar from '../components/common/Topbar.jsx';
import useLogStream from '../hooks/useLogStream.js';
import useIncidentStore from '../store/incidentStore.js';
import { 
    ShieldAlert, 
    Activity, 
    FileText, 
    Download, 
    Search, 
    Filter, 
    RefreshCw, 
    Shield, 
    AlertTriangle, 
    CheckCircle, 
    Info, 
    Terminal, 
    ChevronDown, 
    ChevronUp, 
    ExternalLink 
} from 'lucide-react';

export function AlertsPage() {
    // Keep log stream active for real-time alerts
    useLogStream();
    
    const liveIncidents = useIncidentStore((s) => s.incidents);
    const [dbIncidents, setDbIncidents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');
    const [severityFilter, setSeverityFilter] = useState('ALL');
    const [sourceFilter, setSourceFilter] = useState('ALL');
    const [selectedIncident, setSelectedIncident] = useState(null);
    const [refreshing, setRefreshing] = useState(false);
    const [mitigationStatus, setMitigationStatus] = useState({}); // { incidentId: 'pending' | 'success' | 'error' }

    const fetchIncidents = async () => {
        setRefreshing(true);
        try {
            const data = await getIncidents();
            setDbIncidents(data);
        } catch (err) {
            console.error('Failed to fetch incidents:', err);
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    };

    useEffect(() => {
        fetchIncidents();
    }, []);

    // Merge database incidents and live streaming incidents uniquely by id
    const incidents = useMemo(() => {
        const merged = [];
        const seenIds = new Set();

        // 1. Add real-time streaming incidents (newest first)
        liveIncidents.forEach(inc => {
            if (inc && inc.id && !seenIds.has(inc.id)) {
                seenIds.add(inc.id);
                merged.push(inc);
            }
        });

        // 2. Add database historical incidents
        dbIncidents.forEach(inc => {
            if (inc && inc.id && !seenIds.has(inc.id)) {
                seenIds.add(inc.id);
                merged.push(inc);
            }
        });

        // Sort by timestamp desc or created_at desc if available
        return merged.sort((a, b) => new Date(b.timestamp || b.created_at) - new Date(a.timestamp || a.created_at));
    }, [liveIncidents, dbIncidents]);

    // Derived statistics
    const stats = useMemo(() => {
        const counts = { total: incidents.length, critical: 0, high: 0, warning: 0, resolved: 0 };
        incidents.forEach(inc => {
            const sev = inc.severity?.toUpperCase();
            if (sev === 'CRITICAL') counts.critical++;
            else if (sev === 'HIGH') counts.high++;
            else counts.warning++;

            if (inc.status?.toLowerCase() === 'resolved') {
                counts.resolved++;
            }
        });
        return counts;
    }, [incidents]);

    // Unique sources list for filter
    const sources = useMemo(() => {
        const unique = new Set(incidents.map(inc => inc.source?.toUpperCase()).filter(Boolean));
        return ['ALL', ...Array.from(unique)];
    }, [incidents]);

    // Filter and search incidents
    const filteredIncidents = useMemo(() => {
        return incidents.filter(inc => {
            const matchesSearch = 
                inc.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                inc.src_ip?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                inc.dst_ip?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                inc.mitre_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                inc.mitre_technique?.toLowerCase().includes(searchQuery.toLowerCase());
            
            const matchesSeverity = severityFilter === 'ALL' || inc.severity?.toUpperCase() === severityFilter;
            const matchesSource = sourceFilter === 'ALL' || inc.source?.toUpperCase() === sourceFilter;

            return matchesSearch && matchesSeverity && matchesSource;
        });
    }, [incidents, searchQuery, severityFilter, sourceFilter]);

    const handleProposeMitigation = async (incidentId) => {
        setMitigationStatus(prev => ({ ...prev, [incidentId]: 'pending' }));
        try {
            await proposeActions(incidentId);
            setMitigationStatus(prev => ({ ...prev, [incidentId]: 'success' }));
            // Refresh list to update status
            fetchIncidents();
        } catch (err) {
            console.error(err);
            setMitigationStatus(prev => ({ ...prev, [incidentId]: 'error' }));
        }
    };

    const getSeverityDetails = (sev) => {
        switch (sev?.toUpperCase()) {
            case 'CRITICAL':
                return { color: 'var(--clr-sev-critical)', bg: 'rgba(252, 75, 75, 0.12)', glow: '0 0 10px rgba(252, 75, 75, 0.4)' };
            case 'HIGH':
                return { color: 'var(--clr-sev-high)', bg: 'rgba(249, 115, 22, 0.12)', glow: '0 0 10px rgba(249, 115, 22, 0.4)' };
            case 'MEDIUM':
                return { color: 'var(--clr-sev-medium)', bg: 'rgba(246, 201, 14, 0.12)', glow: '0 0 10px rgba(246, 201, 14, 0.4)' };
            case 'LOW':
                return { color: 'var(--clr-sev-low)', bg: 'rgba(72, 187, 120, 0.12)', glow: '0 0 10px rgba(72, 187, 120, 0.4)' };
            default:
                return { color: 'var(--clr-sev-info)', bg: 'rgba(79, 142, 247, 0.12)', glow: '0 0 10px rgba(79, 142, 247, 0.4)' };
        }
    };

    return (
        <div className="app-shell">
            <Sidebar />
            <div className="main-area">
                <Topbar
                    title="System Alerts"
                    subtitle="Real-time threat detections, ML classification, and MITRE ATT&CK mappings"
                />
                <main className="page-content">
                    {/* Stats Summary Cards */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
                        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 20px' }}>
                            <div style={{ background: 'rgba(99, 179, 237, 0.1)', padding: 10, borderRadius: 8, color: 'var(--clr-accent-blue)' }}>
                                <Shield size={24} />
                            </div>
                            <div>
                                <div style={{ fontSize: 22, fontWeight: 700 }}>{stats.total}</div>
                                <div style={{ fontSize: 12, color: 'var(--clr-text-secondary)' }}>Total Incidents</div>
                            </div>
                        </div>
                        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 20px' }}>
                            <div style={{ background: 'rgba(252, 75, 75, 0.1)', padding: 10, borderRadius: 8, color: 'var(--clr-sev-critical)' }}>
                                <AlertTriangle size={24} />
                            </div>
                            <div>
                                <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--clr-sev-critical)' }}>{stats.critical}</div>
                                <div style={{ fontSize: 12, color: 'var(--clr-text-secondary)' }}>Critical Severity</div>
                            </div>
                        </div>
                        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 20px' }}>
                            <div style={{ background: 'rgba(249, 115, 22, 0.1)', padding: 10, borderRadius: 8, color: 'var(--clr-sev-high)' }}>
                                <ShieldAlert size={24} />
                            </div>
                            <div>
                                <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--clr-sev-high)' }}>{stats.high}</div>
                                <div style={{ fontSize: 12, color: 'var(--clr-text-secondary)' }}>High Severity</div>
                            </div>
                        </div>
                        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 20px' }}>
                            <div style={{ background: 'rgba(72, 187, 120, 0.1)', padding: 10, borderRadius: 8, color: 'var(--clr-accent-green)' }}>
                                <CheckCircle size={24} />
                            </div>
                            <div>
                                <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--clr-accent-green)' }}>{stats.resolved}</div>
                                <div style={{ fontSize: 12, color: 'var(--clr-text-secondary)' }}>Resolved Status</div>
                            </div>
                        </div>
                    </div>

                    {/* Filters Toolbar */}
                    <div className="card" style={{ padding: 16, marginBottom: 20, display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
                        {/* Search */}
                        <div style={{ position: 'relative', flex: 1, minWidth: 260 }}>
                            <Search size={16} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--clr-text-muted)' }} />
                            <input
                                type="text"
                                placeholder="Search by Title, IP, MITRE ID, Technique..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="chat-input"
                                style={{ width: '100%', paddingLeft: 38, paddingRight: 12, height: 38, borderRadius: 6 }}
                            />
                        </div>

                        {/* Severity Filter */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <Filter size={14} style={{ color: 'var(--clr-text-secondary)' }} />
                            <span style={{ fontSize: 13, color: 'var(--clr-text-secondary)' }}>Severity:</span>
                            <select
                                value={severityFilter}
                                onChange={(e) => setSeverityFilter(e.target.value)}
                                style={{
                                    background: 'var(--clr-bg-elevated)',
                                    border: '1px solid var(--clr-border)',
                                    color: 'var(--clr-text-primary)',
                                    padding: '6px 12px',
                                    borderRadius: 6,
                                    outline: 'none',
                                    fontSize: 13,
                                    cursor: 'pointer'
                                }}
                            >
                                <option value="ALL">All Severities</option>
                                <option value="CRITICAL">Critical</option>
                                <option value="HIGH">High</option>
                                <option value="MEDIUM">Medium</option>
                                <option value="LOW">Low</option>
                            </select>
                        </div>

                        {/* Source Filter */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ fontSize: 13, color: 'var(--clr-text-secondary)' }}>Source:</span>
                            <select
                                value={sourceFilter}
                                onChange={(e) => setSourceFilter(e.target.value)}
                                style={{
                                    background: 'var(--clr-bg-elevated)',
                                    border: '1px solid var(--clr-border)',
                                    color: 'var(--clr-text-primary)',
                                    padding: '6px 12px',
                                    borderRadius: 6,
                                    outline: 'none',
                                    fontSize: 13,
                                    cursor: 'pointer'
                                }}
                            >
                                {sources.map(src => (
                                    <option key={src} value={src}>{src === 'ALL' ? 'All Sources' : src}</option>
                                ))}
                            </select>
                        </div>

                        {/* Refresh */}
                        <button
                            onClick={fetchIncidents}
                            disabled={refreshing}
                            className="btn btn-secondary"
                            style={{ padding: '8px 14px', height: 38, gap: 6, cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                        >
                            <RefreshCw size={14} style={{ animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
                            {refreshing ? 'Refreshing...' : 'Refresh'}
                        </button>
                    </div>

                    {/* Alerts Table */}
                    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                        {loading ? (
                            <div style={{ padding: 40, textAlign: 'center', color: 'var(--clr-text-secondary)' }}>
                                <RefreshCw size={24} style={{ animation: 'spin 1s linear infinite', marginBottom: 12 }} />
                                <div>Loading system alerts...</div>
                            </div>
                        ) : filteredIncidents.length === 0 ? (
                            <div style={{ padding: 50, textAlign: 'center', color: 'var(--clr-text-secondary)' }}>
                                <Shield size={36} style={{ marginBottom: 12, opacity: 0.5 }} />
                                <div style={{ fontSize: 16, fontWeight: 600 }}>No alerts found</div>
                                <p style={{ fontSize: 13, color: 'var(--clr-text-muted)', marginTop: 4 }}>
                                    Adjust your search or filters. System state is clean.
                                </p>
                            </div>
                        ) : (
                            <div style={{ overflowX: 'auto' }}>
                                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                                    <thead>
                                        <tr style={{ background: 'rgba(255, 255, 255, 0.02)', borderBottom: '1px solid var(--clr-border)', color: 'var(--clr-text-secondary)', fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                                            <th style={{ padding: '16px 20px' }}>Severity</th>
                                            <th style={{ padding: '16px 20px' }}>Title & Threat Details</th>
                                            <th style={{ padding: '16px 20px' }}>Source IP</th>
                                            <th style={{ padding: '16px 20px' }}>Origin Sensor</th>
                                            <th style={{ padding: '16px 20px' }}>Risk Score</th>
                                            <th style={{ padding: '16px 20px' }}>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filteredIncidents.map(inc => {
                                            const isSelected = selectedIncident?.id === inc.id;
                                            const sevInfo = getSeverityDetails(inc.severity);
                                            const isResolving = mitigationStatus[inc.id] === 'pending';
                                            const isSuccess = mitigationStatus[inc.id] === 'success';

                                            return (
                                                <React.Fragment key={inc.id}>
                                                    <tr 
                                                        onClick={() => setSelectedIncident(isSelected ? null : inc)}
                                                        style={{ 
                                                            borderBottom: '1px solid var(--clr-border)', 
                                                            cursor: 'pointer',
                                                            background: isSelected ? 'rgba(99, 179, 237, 0.04)' : 'transparent',
                                                            transition: 'background 0.2s'
                                                        }}
                                                        className="table-row-hover"
                                                    >
                                                        <td style={{ padding: '16px 20px' }}>
                                                            <span style={{
                                                                color: sevInfo.color,
                                                                background: sevInfo.bg,
                                                                border: `1px solid ${sevInfo.color}35`,
                                                                padding: '4px 10px',
                                                                borderRadius: 4,
                                                                fontSize: 11,
                                                                fontWeight: 700,
                                                                letterSpacing: '0.5px',
                                                                boxShadow: sevInfo.glow,
                                                                textTransform: 'uppercase',
                                                                display: 'inline-block'
                                                            }}>
                                                                {inc.severity}
                                                            </span>
                                                        </td>
                                                        <td style={{ padding: '16px 20px' }}>
                                                            <div style={{ fontWeight: 600, color: 'var(--clr-text-primary)', fontSize: 13.5 }}>
                                                                {inc.title}
                                                            </div>
                                                            {inc.mitre_id && (
                                                                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 4, background: 'rgba(159, 122, 234, 0.08)', border: '1px solid rgba(159, 122, 234, 0.2)', padding: '2px 6px', borderRadius: 4, fontSize: 10.5 }}>
                                                                    <span style={{ color: 'var(--clr-accent-purple)', fontWeight: 700 }}>{inc.mitre_id}</span>
                                                                    <span style={{ color: 'var(--clr-text-secondary)' }}>{inc.mitre_technique}</span>
                                                                </div>
                                                            )}
                                                        </td>
                                                        <td style={{ padding: '16px 20px', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--clr-text-primary)' }}>
                                                            {inc.src_ip || '—'} {inc.port ? `:${inc.port}` : ''}
                                                        </td>
                                                        <td style={{ padding: '16px 20px' }}>
                                                            <span style={{
                                                                background: 'var(--clr-bg-elevated)',
                                                                border: '1px solid var(--clr-border)',
                                                                color: 'var(--clr-text-secondary)',
                                                                padding: '2px 8px',
                                                                borderRadius: 4,
                                                                fontSize: 11.5,
                                                                textTransform: 'uppercase',
                                                                fontWeight: 500
                                                            }}>
                                                                {inc.source || 'simulator'}
                                                            </span>
                                                        </td>
                                                        <td style={{ padding: '16px 20px' }}>
                                                            {inc.risk_score != null ? (
                                                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                                                    <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: inc.risk_score >= 7.5 ? 'var(--clr-sev-critical)' : inc.risk_score >= 5 ? 'var(--clr-sev-medium)' : 'var(--clr-sev-low)' }}>
                                                                        {inc.risk_score.toFixed(1)}
                                                                    </span>
                                                                    <div style={{ width: 40, height: 4, background: 'rgba(255, 255, 255, 0.08)', borderRadius: 99, overflow: 'hidden' }}>
                                                                        <div style={{
                                                                            width: `${(inc.risk_score / 10) * 100}%`,
                                                                            height: '100%',
                                                                            background: inc.risk_score >= 7.5 ? 'var(--clr-sev-critical)' : inc.risk_score >= 5 ? 'var(--clr-sev-medium)' : 'var(--clr-sev-low)'
                                                                        }} />
                                                                    </div>
                                                                </div>
                                                            ) : '—'}
                                                        </td>
                                                        <td style={{ padding: '16px 20px' }}>
                                                            <span style={{
                                                                color: inc.status?.toLowerCase() === 'resolved' ? 'var(--clr-accent-green)' : 'var(--clr-accent-cyan)',
                                                                fontWeight: 600,
                                                                fontSize: 12,
                                                                textTransform: 'uppercase',
                                                                display: 'flex',
                                                                alignItems: 'center',
                                                                gap: 4
                                                            }}>
                                                                <span style={{ width: 6, height: 6, borderRadius: '50%', background: inc.status?.toLowerCase() === 'resolved' ? 'var(--clr-accent-green)' : 'var(--clr-accent-cyan)', boxShadow: `0 0 6px ${inc.status?.toLowerCase() === 'resolved' ? 'var(--clr-accent-green)' : 'var(--clr-accent-cyan)'}` }} />
                                                                {inc.status || 'open'}
                                                            </span>
                                                        </td>
                                                    </tr>

                                                    {/* Expanded Row Detail */}
                                                    {isSelected && (
                                                        <tr style={{ background: 'rgba(255, 255, 255, 0.01)' }}>
                                                            <td colSpan="6" style={{ padding: '16px 24px', borderBottom: '1px solid var(--clr-border)' }}>
                                                                <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 24 }}>
                                                                    <div>
                                                                        <h4 style={{ fontSize: 13, textTransform: 'uppercase', color: 'var(--clr-text-secondary)', marginBottom: 8, letterSpacing: '0.5px' }}>
                                                                            Payload / Event Summary
                                                                        </h4>
                                                                        <div style={{ background: 'var(--clr-bg-primary)', border: '1px solid var(--clr-border)', borderRadius: 6, padding: 12, fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.5, color: '#a0aec0', whiteSpace: 'pre-wrap', maxHeight: 200, overflowY: 'auto' }}>
                                                                            {inc.payload || `Threat signature detected via CyberTwin automated sensors. Signature: ${inc.title}\nSource: ${inc.src_ip || 'Internal Network'}\nDestination: ${inc.dst_ip || 'Local Host'}\nProtocol Port: ${inc.port || 'Any'}\nRule Classification: ${inc.mitre_technique || 'General Incident'}`}
                                                                        </div>
                                                                    </div>
                                                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                                                                        <h4 style={{ fontSize: 13, textTransform: 'uppercase', color: 'var(--clr-text-secondary)', letterSpacing: '0.5px' }}>
                                                                            CyberTwin Interventions
                                                                        </h4>
                                                                        
                                                                        <div style={{ fontSize: 12, color: 'var(--clr-text-secondary)' }}>
                                                                            Timestamp: <span style={{ color: 'var(--clr-text-primary)' }}>{new Date(inc.timestamp || inc.created_at).toLocaleString()}</span>
                                                                        </div>

                                                                        <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                                                                            <button 
                                                                                onClick={() => handleProposeMitigation(inc.id)}
                                                                                disabled={isResolving || inc.status?.toLowerCase() === 'resolved'}
                                                                                className="btn btn-primary"
                                                                                style={{ flex: 1, fontSize: 12, height: 34, padding: '0 12px', justifyContent: 'center' }}
                                                                            >
                                                                                {isResolving ? 'Proposing...' : isSuccess || inc.status?.toLowerCase() === 'resolved' ? 'Mitigation Proposed' : 'Mitigate Threat'}
                                                                            </button>
                                                                            <a 
                                                                                href="/chat"
                                                                                className="btn btn-secondary"
                                                                                style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 34, height: 34, padding: 0 }}
                                                                                title="Ask CyberTwin AI Chat"
                                                                            >
                                                                                <ExternalLink size={14} />
                                                                            </a>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    )}
                                                </React.Fragment>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </main>
            </div>
        </div>
    );
}

export function LiveFeedPage() {
    const [logs, setLogs] = useState([]);
    
    useEffect(() => {
        const interval = setInterval(() => {
            const mockLogs = [
                "[INFO] User admin logged in successfully from 192.168.1.45",
                "[WARN] Multiple failed login attempts detected on SSH",
                "[ALERT] Unusual outbound traffic volume detected on port 443",
                "[INFO] System backup completed successfully",
                "[INFO] Database synchronization started",
                "[WARN] High CPU utilization detected on node-worker-1",
                "[ALERT] Malware signature matched in uploaded file",
                "[INFO] Firewall rule updated by admin",
                "[WARN] Deprecated API endpoint accessed",
                "[INFO] Health check passed for all services"
            ];
            const newLog = {
                id: Date.now(),
                timestamp: new Date().toLocaleTimeString(),
                message: mockLogs[Math.floor(Math.random() * mockLogs.length)]
            };
            setLogs(prev => [newLog, ...prev].slice(0, 50));
        }, 3000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="app-shell">
            <Sidebar />
            <div className="main-area">
                <Topbar
                    title="Live Feed"
                    subtitle="Continuous monitoring of system events and terminal alerts"
                />
                <main className="page-content">
                    <div className="card" style={{ background: '#07090e', border: '1px solid var(--clr-border)' }}>
                        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--clr-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ color: 'var(--clr-accent-green)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                                <div className="sidebar-status-dot" style={{ background: 'var(--clr-accent-green)' }}></div>
                                CyberTwin Agent Status: Active
                            </span>
                            <span style={{ fontSize: 11, color: 'var(--clr-text-muted)', fontFamily: 'var(--font-mono)' }}>STREAM: ws://localhost:8000/ws/logs</span>
                        </div>
                        <div style={{ height: 'calc(100vh - 270px)', overflowY: 'auto', padding: 20, fontFamily: 'var(--font-mono)', fontSize: 13, lineHeight: 1.7, background: '#05070a' }}>
                            {logs.map(log => (
                                <div key={log.id} style={{ display: 'flex', gap: 14, marginBottom: 8 }}>
                                    <span style={{ color: 'var(--clr-text-muted)', minWidth: 80 }}>{log.timestamp}</span>
                                    <span style={{ 
                                        color: log.message.includes('[ALERT]') ? 'var(--clr-sev-critical)' : 
                                               log.message.includes('[WARN]') ? 'var(--clr-sev-medium)' : 'var(--clr-sev-low)' 
                                    }}>
                                        {log.message}
                                    </span>
                                </div>
                            ))}
                            {logs.length === 0 && <div style={{ color: 'var(--clr-text-muted)' }}>Connecting to sensor network feed...</div>}
                        </div>
                    </div>
                </main>
            </div>
        </div>
    );
}

export function ReportsPage() {
    const handleExport = async (format) => {
        try {
            const data = await exportIncidents(format);
            if (format === 'csv') {
                const url = window.URL.createObjectURL(new Blob([data]));
                const link = document.createElement('a');
                link.href = url;
                link.setAttribute('download', 'cybertwin-report.csv');
                document.body.appendChild(link);
                link.click();
            } else {
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
                const link = document.createElement('a');
                link.href = dataStr;
                link.setAttribute('download', 'cybertwin-report.json');
                document.body.appendChild(link);
                link.click();
            }
        } catch (e) {
            console.error('Export failed', e);
        }
    };

    return (
        <div className="app-shell">
            <Sidebar />
            <div className="main-area">
                <Topbar
                    title="Reports & Auditing"
                    subtitle="Export incident logs and threat reports for compliance"
                />
                <main className="page-content">
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
                        <div className="card" style={{ padding: 32, display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 20 }}>
                            <div style={{ background: 'rgba(0, 229, 255, 0.08)', padding: 20, borderRadius: '50%', color: 'var(--clr-accent-cyan)' }}>
                                <Download size={40} />
                            </div>
                            <div>
                                <h3 style={{ fontSize: 18, marginBottom: 8, fontWeight: 700, color: 'var(--clr-text-primary)' }}>Machine-Readable JSON</h3>
                                <p style={{ color: 'var(--clr-text-secondary)', fontSize: 13.5, lineHeight: 1.6 }}>
                                    Export all incidents, MITRE mappings, and ML scores in a structured format suitable for direct ingestion into Splunk, Microsoft Sentinel, or custom SIEM pipelines.
                                </p>
                            </div>
                            <button onClick={() => handleExport('json')} className="btn btn-primary" style={{ marginTop: 'auto', width: '100%', height: 42, justifyContent: 'center' }}>
                                Export JSON Report
                            </button>
                        </div>
                        
                        <div className="card" style={{ padding: 32, display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 20 }}>
                            <div style={{ background: 'rgba(72, 187, 120, 0.08)', padding: 20, borderRadius: '50%', color: 'var(--clr-accent-green)' }}>
                                <FileText size={40} />
                            </div>
                            <div>
                                <h3 style={{ fontSize: 18, marginBottom: 8, fontWeight: 700, color: 'var(--clr-text-primary)' }}>Audit-Friendly CSV</h3>
                                <p style={{ color: 'var(--clr-text-secondary)', fontSize: 13.5, lineHeight: 1.6 }}>
                                    Generate a spreadsheet summary listing severity, rule description, IP address, and MITRE classification. Ideal for compliance reports and manual auditor reviews.
                                </p>
                            </div>
                            <button onClick={() => handleExport('csv')} className="btn btn-primary" style={{ marginTop: 'auto', width: '100%', height: 42, justifyContent: 'center' }}>
                                Export CSV Spreadsheet
                            </button>
                        </div>
                    </div>
                </main>
            </div>
        </div>
    );
}
