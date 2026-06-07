import React, { useState, useRef } from 'react';
import { changePassword, scanDevice, scanFile } from '../services/api.js';
import Sidebar from '../components/common/Sidebar.jsx';
import Topbar from '../components/common/Topbar.jsx';
import { Settings as SettingsIcon, ShieldCheck, Key, Search, FileSearch, HardDrive, UploadCloud, Eye, EyeOff } from 'lucide-react';

function SettingsPage() {
    const [activeTab, setActiveTab] = useState('password');

    return (
        <div className="app-shell">
            <Sidebar />
            <div className="main-area">
                <Topbar
                    title="System Settings"
                    subtitle="Configure security settings and run diagnostics"
                />
                <main className="page-content">
                    <div style={{ display: 'flex', gap: 24 }}>
                        <aside style={{ width: 240, display: 'flex', flexDirection: 'column', gap: 8 }}>
                            <button 
                                className={`btn ${activeTab === 'password' ? 'btn-primary' : 'btn-secondary'}`}
                                onClick={() => setActiveTab('password')}
                                style={{ justifyContent: 'flex-start' }}
                            >
                                <Key size={16} /> Change Password
                            </button>
                            <button 
                                className={`btn ${activeTab === 'scanner' ? 'btn-primary' : 'btn-secondary'}`}
                                onClick={() => setActiveTab('scanner')}
                                style={{ justifyContent: 'flex-start' }}
                            >
                                <Search size={16} /> System Scanner
                            </button>
                        </aside>
                        
                        <main style={{ flex: 1 }}>
                            {activeTab === 'password' && <ChangePasswordTab />}
                            {activeTab === 'scanner' && <ScannerTab />}
                        </main>
                    </div>
                </main>
            </div>
        </div>
    );
}

function ChangePasswordTab() {
    const [formData, setFormData] = useState({ old_password: '', new_password: '', confirm_password: '' });
    const [status, setStatus] = useState(null);
    const [loading, setLoading] = useState(false);
    
    // Show/hide password states
    const [showOld, setShowOld] = useState(false);
    const [showNew, setShowNew] = useState(false);
    const [showConfirm, setShowConfirm] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setStatus(null);
        setLoading(true);
        try {
            const res = await changePassword(formData);
            setStatus({ type: 'success', msg: res.message });
            setFormData({ old_password: '', new_password: '', confirm_password: '' });
        } catch (err) {
            setStatus({ type: 'error', msg: err.response?.data?.detail || err.message });
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="card" style={{ padding: 24 }}>
            <h2 style={{ fontSize: 18, marginBottom: 16 }}>Change Password</h2>
            <p style={{ color: 'var(--clr-text-secondary)', marginBottom: 24, fontSize: 14 }}>
                Password must be at least 8 characters and contain alphanumeric values and symbols (at least 1 upper, 1 lower, 1 number, 1 symbol).
            </p>
            
            {status && (
                <div style={{
                    padding: 12, marginBottom: 16, borderRadius: 6, fontSize: 14,
                    background: status.type === 'error' ? 'rgba(255, 77, 77, 0.1)' : 'rgba(74, 222, 128, 0.1)',
                    color: status.type === 'error' ? '#ff4d4d' : '#4ade80',
                    border: `1px solid ${status.type === 'error' ? '#ff4d4d' : '#4ade80'}`
                }}>
                    {status.msg}
                </div>
            )}

            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 400 }}>
                <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: 'var(--clr-text-secondary)' }}>Old Password</label>
                    <div style={{ position: 'relative', width: '100%' }}>
                        <input 
                            type={showOld ? "text" : "password"} 
                            required 
                            className="form-input"
                            style={{ width: '100%', paddingRight: '40px' }}
                            value={formData.old_password}
                            onChange={e => setFormData(p => ({ ...p, old_password: e.target.value }))}
                        />
                        <button
                            type="button"
                            onClick={() => setShowOld(!showOld)}
                            style={{
                                position: 'absolute',
                                right: '12px',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                background: 'none',
                                border: 'none',
                                color: 'var(--clr-text-secondary)',
                                cursor: 'pointer',
                                padding: '4px',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center'
                            }}
                            title={showOld ? "Hide Password" : "Show Password"}
                        >
                            {showOld ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                    </div>
                </div>
                <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: 'var(--clr-text-secondary)' }}>New Password</label>
                    <div style={{ position: 'relative', width: '100%' }}>
                        <input 
                            type={showNew ? "text" : "password"} 
                            required 
                            className="form-input"
                            style={{ width: '100%', paddingRight: '40px' }}
                            value={formData.new_password}
                            onChange={e => setFormData(p => ({ ...p, new_password: e.target.value }))}
                        />
                        <button
                            type="button"
                            onClick={() => setShowNew(!showNew)}
                            style={{
                                position: 'absolute',
                                right: '12px',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                background: 'none',
                                border: 'none',
                                color: 'var(--clr-text-secondary)',
                                cursor: 'pointer',
                                padding: '4px',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center'
                            }}
                            title={showNew ? "Hide Password" : "Show Password"}
                        >
                            {showNew ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                    </div>
                </div>
                <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: 'var(--clr-text-secondary)' }}>Confirm Password</label>
                    <div style={{ position: 'relative', width: '100%' }}>
                        <input 
                            type={showConfirm ? "text" : "password"} 
                            required 
                            className="form-input"
                            style={{ width: '100%', paddingRight: '40px' }}
                            value={formData.confirm_password}
                            onChange={e => setFormData(p => ({ ...p, confirm_password: e.target.value }))}
                        />
                        <button
                            type="button"
                            onClick={() => setShowConfirm(!showConfirm)}
                            style={{
                                position: 'absolute',
                                right: '12px',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                background: 'none',
                                border: 'none',
                                color: 'var(--clr-text-secondary)',
                                cursor: 'pointer',
                                padding: '4px',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center'
                            }}
                            title={showConfirm ? "Hide Password" : "Show Password"}
                        >
                            {showConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                    </div>
                </div>
                <button type="submit" disabled={loading} className="btn btn-primary" style={{ alignSelf: 'flex-start', marginTop: 8 }}>
                    {loading ? 'Updating...' : 'Update Password'}
                </button>
            </form>
        </div>
    );
}

function ScannerTab() {
    const [scanState, setScanState] = useState({ isScanning: false, result: null, details: null });
    
    // File scan states
    const [filePath, setFilePath] = useState('');
    const [selectedFile, setSelectedFile] = useState(null);
    const fileInputRef = useRef(null);

    const handleDeviceScan = async () => {
        if (!window.confirm("Are you sure you want to run a full device scan? This may take several hours.")) return;
        
        setScanState({ isScanning: true, result: null, details: null });
        try {
            const res = await scanDevice();
            setScanState({ isScanning: false, result: res.result, details: res.details });
        } catch (err) {
            setScanState({ isScanning: false, result: 'Error', details: err.message });
        }
    };

    const handleFileScan = async () => {
        if (!filePath && !selectedFile) return;
        
        setScanState({ isScanning: true, result: null, details: null });
        try {
            const formData = new FormData();
            if (filePath) formData.append('path', filePath);
            if (selectedFile) formData.append('file', selectedFile);
            
            const res = await scanFile(formData);
            setScanState({ isScanning: false, result: res.result, details: res.details });
        } catch (err) {
            setScanState({ isScanning: false, result: 'Error', details: err.response?.data?.detail || err.message });
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            setSelectedFile(e.dataTransfer.files[0]);
            setFilePath('');
        }
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            {/* Device Scanner */}
            <div className="card" style={{ padding: 24 }}>
                <h2 style={{ fontSize: 18, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <HardDrive size={20} /> Full Device Scan
                </h2>
                <p style={{ color: 'var(--clr-text-secondary)', marginBottom: 20, fontSize: 14 }}>
                    Scans all local drives for malware, unauthorized executables, and security misconfigurations.
                </p>
                <button 
                    onClick={handleDeviceScan} 
                    disabled={scanState.isScanning} 
                    className="btn btn-primary"
                >
                    {scanState.isScanning ? 'Scanning...' : 'Start Device Scan'}
                </button>
            </div>

            {/* File/Folder Scanner */}
            <div className="card" style={{ padding: 24 }}>
                <h2 style={{ fontSize: 18, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <FileSearch size={20} /> Scan File or Folder
                </h2>
                <p style={{ color: 'var(--clr-text-secondary)', marginBottom: 20, fontSize: 14 }}>
                    Drag and drop a file, or enter an absolute path to scan a specific target.
                </p>
                
                <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 16 }}>
                    <input 
                        type="text" 
                        placeholder="Enter absolute path (e.g., C:\Downloads\suspicious.exe)" 
                        className="form-input"
                        style={{ flex: 1 }}
                        value={filePath}
                        onChange={e => { setFilePath(e.target.value); setSelectedFile(null); }}
                        disabled={scanState.isScanning}
                    />
                    <span style={{ color: 'var(--clr-text-secondary)' }}>OR</span>
                    <button 
                        className="btn btn-secondary" 
                        onClick={() => fileInputRef.current?.click()}
                        disabled={scanState.isScanning}
                    >
                        Browse
                    </button>
                    <input 
                        type="file" 
                        ref={fileInputRef} 
                        style={{ display: 'none' }} 
                        onChange={e => {
                            if(e.target.files.length > 0) {
                                setSelectedFile(e.target.files[0]);
                                setFilePath('');
                            }
                        }}
                    />
                </div>

                <div 
                    onDragOver={e => e.preventDefault()}
                    onDrop={handleDrop}
                    style={{
                        border: '2px dashed var(--clr-border)',
                        borderRadius: 8,
                        padding: 32,
                        textAlign: 'center',
                        color: 'var(--clr-text-secondary)',
                        background: 'var(--clr-bg-elevated)',
                        marginBottom: 16
                    }}
                >
                    <UploadCloud size={32} style={{ marginBottom: 8, opacity: 0.5 }} />
                    <div>
                        {selectedFile ? (
                            <span style={{ color: 'var(--clr-text-primary)' }}>Selected: {selectedFile.name}</span>
                        ) : (
                            "Drag & Drop a file here to upload"
                        )}
                    </div>
                </div>

                <button 
                    onClick={handleFileScan} 
                    disabled={scanState.isScanning || (!filePath && !selectedFile)} 
                    className="btn btn-primary"
                >
                    {scanState.isScanning ? 'Scanning...' : 'Scan Target'}
                </button>
            </div>

            {/* Results Area */}
            {scanState.isScanning && (
                <div className="card" style={{ padding: 24, textAlign: 'center' }}>
                    <div className="typing-indicator" style={{ display: 'inline-flex', marginBottom: 16 }}>
                        <div className="typing-dot" />
                        <div className="typing-dot" />
                        <div className="typing-dot" />
                    </div>
                    <p style={{ color: 'var(--clr-text-secondary)' }}>CyberTwin AI is actively analyzing the target...</p>
                </div>
            )}

            {scanState.result && !scanState.isScanning && (
                <div className="card" style={{ 
                    padding: 24, 
                    border: `1px solid ${scanState.result === 'Clean' ? '#4ade80' : '#ff4d4d'}`,
                    background: scanState.result === 'Clean' ? 'rgba(74, 222, 128, 0.05)' : 'rgba(255, 77, 77, 0.05)'
                }}>
                    <h3 style={{ 
                        fontSize: 18, 
                        marginBottom: 12, 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: 8,
                        color: scanState.result === 'Clean' ? '#4ade80' : '#ff4d4d'
                    }}>
                        <ShieldCheck size={24} /> Scan Complete: {scanState.result}
                    </h3>
                    <p style={{ lineHeight: 1.6 }}>{scanState.details}</p>
                </div>
            )}
        </div>
    );
}

export default SettingsPage;
