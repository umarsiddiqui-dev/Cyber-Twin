import Sidebar from '../components/common/Sidebar.jsx';
import Topbar from '../components/common/Topbar.jsx';
import AlertFeed from '../components/Dashboard/AlertFeed.jsx';
import StatusPanel from '../components/Dashboard/StatusPanel.jsx';
import IncidentStats from '../components/Dashboard/IncidentStats.jsx';
import ScenarioLauncher from '../components/Simulation/ScenarioLauncher.jsx';
import useLogStream from '../hooks/useLogStream.js';

/**
 * Main Dashboard page (Phase 5) – shows scenario launcher, live stats and the real-time alert feed.
 * useLogStream() opens the WebSocket and populates the incidentStore automatically.
 */
function DashboardPage() {
    useLogStream();  // 🔌 Opens WebSocket → feeds incidentStore

    return (
        <div className="app-shell">
            <Sidebar />
            <div className="main-area">
                <Topbar
                    title="Security Dashboard"
                    subtitle="System overview & real-time monitoring"
                />
                <main className="page-content">

                    {/* ── Attack Scenario Simulator (Phase 5) ── */}
                    <div style={{ marginBottom: 4 }}>
                        <ScenarioLauncher />
                    </div>

                    {/* ── Live Stats Row (Phase 2: reads from incidentStore) ── */}
                    <IncidentStats />

                    {/* ── Two-column grid ── */}
                    <div className="dashboard-grid">

                        {/* Alert feed – full width */}
                        <div className="card span-2">
                            <div className="card-title">
                                <span>🔔</span> Live Alert Feed
                                <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--clr-accent-green)', fontWeight: 600 }}>
                                    ● REAL-TIME
                                </span>
                            </div>
                            <AlertFeed />
                        </div>

                        {/* System status */}
                        <div className="card">
                            <div className="card-title"><span>⚙️</span> System Components</div>
                            <StatusPanel />
                        </div>

                        {/* Phase status */}
                        <div className="card">
                            <div className="card-title"><span>📋</span> CyberTwin Status</div>
                            <div style={{ fontSize: 13, color: 'var(--clr-text-secondary)', lineHeight: 1.9 }}>
                                <p>✅ &nbsp;Phases 1–5 complete</p>
                                <p>✅ &nbsp;AI Core (GPT-4o + offline fallback)</p>
                                <p>✅ &nbsp;MITRE ATT&amp;CK classification</p>
                                <p>✅ &nbsp;Risk scoring engine</p>
                                <p>✅ &nbsp;Action approval workflow</p>
                                <p>✅ &nbsp;Voice STT/TTS (Chrome/Edge)</p>
                                <p>✅ &nbsp;Attack scenario simulation</p>
                            </div>
                        </div>

                    </div>
                </main>
            </div>
        </div>
    );
}

export default DashboardPage;
