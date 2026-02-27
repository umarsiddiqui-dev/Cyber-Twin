import Sidebar from '../components/common/Sidebar.jsx';
import Topbar from '../components/common/Topbar.jsx';
import ChatWindow from '../components/Chat/ChatWindow.jsx';

function ChatPage() {
    return (
        <div className="app-shell">
            <Sidebar />
            <div className="main-area" style={{ overflow: 'hidden' }}>
                <Topbar
                    title="AI Assistant"
                    subtitle="Threat interpretation & incident response"
                />
                <ChatWindow />
            </div>
        </div>
    );
}

export default ChatPage;
