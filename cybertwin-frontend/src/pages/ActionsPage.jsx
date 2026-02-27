import Sidebar from '../components/common/Sidebar.jsx';
import Topbar from '../components/common/Topbar.jsx';
import ApprovalPanel from '../components/Actions/ApprovalPanel.jsx';

/**
 * ActionsPage – SOC analyst action review interface.
 * Displays proposed remediation actions awaiting human approval.
 */
function ActionsPage() {
    return (
        <div className="app-shell">
            <Sidebar />
            <div className="main-area">
                <Topbar
                    title="⚡ Action Center"
                    subtitle="Review and approve AI-proposed remediation actions"
                />
                <ApprovalPanel />
            </div>
        </div>
    );
}

export default ActionsPage;
