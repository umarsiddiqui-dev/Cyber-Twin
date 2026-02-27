import { Routes, Route, Navigate } from 'react-router-dom';
import { isAuthenticated } from './services/auth.js';
import DashboardPage from './pages/DashboardPage.jsx';
import ChatPage from './pages/ChatPage.jsx';
import ActionsPage from './pages/ActionsPage.jsx';
import LoginPage from './pages/LoginPage.jsx';

/** Redirect to /login if the user has no JWT token. */
function ProtectedRoute({ element }) {
    return isAuthenticated() ? element : <Navigate to="/login" replace />;
}

function App() {
    return (
        <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<ProtectedRoute element={<DashboardPage />} />} />
            <Route path="/chat" element={<ProtectedRoute element={<ChatPage />} />} />
            <Route path="/actions" element={<ProtectedRoute element={<ActionsPage />} />} />
        </Routes>
    );
}

export default App;
