import { NavLink } from 'react-router-dom';
import {
    LayoutDashboard,
    MessageSquare,
    ShieldAlert,
    Activity,
    FileText,
    Settings,
    Wifi,
    Zap,
} from 'lucide-react';
import useActionStore from '../../store/actionStore.js';

const navItems = [
    { label: 'Dashboard', icon: LayoutDashboard, to: '/dashboard' },
    { label: 'AI Chat', icon: MessageSquare, to: '/chat' },
    { label: 'Actions', icon: Zap, to: '/actions' },
];

const monitorItems = [
    { label: 'Alerts', icon: ShieldAlert, to: '#', disabled: true },
    { label: 'Live Feed', icon: Activity, to: '#', disabled: true },
    { label: 'Reports', icon: FileText, to: '#', disabled: true },
];

function Sidebar() {
    return (
        <aside className="sidebar">
            {/* Logo */}
            <div className="sidebar-logo">
                <div className="sidebar-logo-icon">🛡️</div>
                <div className="sidebar-logo-text">
                    <span className="sidebar-logo-name">CyberTwin</span>
                    <span className="sidebar-logo-sub">SOC Assistant</span>
                </div>
            </div>

            {/* Navigation */}
            <nav className="sidebar-nav">
                <span className="nav-section-label">Main</span>
                {navItems.map(({ label, icon: Icon, to }) => {
                    const isPending = label === 'Actions';
                    const pendingCount = isPending ? useActionStore.getState().pendingCount : 0;
                    return (
                        <NavLink
                            key={label}
                            to={to}
                            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                        >
                            <span className="nav-item-icon">
                                <Icon size={16} />
                            </span>
                            {label}
                            {isPending && pendingCount > 0 && (
                                <span style={{
                                    marginLeft: 'auto',
                                    background: 'var(--clr-accent-yellow)',
                                    color: '#000',
                                    borderRadius: 99,
                                    fontSize: 10,
                                    fontWeight: 700,
                                    padding: '1px 6px',
                                    minWidth: 18,
                                    textAlign: 'center',
                                }}>
                                    {pendingCount}
                                </span>
                            )}
                        </NavLink>
                    );
                })}

                <span className="nav-section-label" style={{ marginTop: 8 }}>Monitor</span>
                {monitorItems.map(({ label, icon: Icon }) => (
                    <button
                        key={label}
                        className="nav-item"
                        disabled
                        title="Available in Phase 2"
                        style={{ opacity: 0.4, cursor: 'not-allowed' }}
                    >
                        <span className="nav-item-icon">
                            <Icon size={16} />
                        </span>
                        {label}
                        <span style={{ marginLeft: 'auto', fontSize: 9, letterSpacing: 0.5, color: 'var(--clr-accent-yellow)' }}>P2</span>
                    </button>
                ))}

                <span className="nav-section-label" style={{ marginTop: 8 }}>System</span>
                <button className="nav-item" disabled style={{ opacity: 0.4, cursor: 'not-allowed' }}>
                    <span className="nav-item-icon"><Settings size={16} /></span>
                    Settings
                </button>
            </nav>

            {/* Footer status */}
            <div className="sidebar-footer">
                <div className="flex items-center gap-8" style={{ fontSize: 12, color: 'var(--clr-text-secondary)' }}>
                    <Wifi size={13} style={{ color: 'var(--clr-accent-green)' }} />
                    <span>
                        <span className="sidebar-status-dot" />
                        Backend: Connected
                    </span>
                </div>
            </div>
        </aside>
    );
}

export default Sidebar;
