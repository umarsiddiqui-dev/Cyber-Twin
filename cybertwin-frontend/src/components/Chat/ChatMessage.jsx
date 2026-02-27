import { Volume2, VolumeX } from 'lucide-react';
import MitreBadge from './MitreBadge.jsx';
import useTTS from '../../hooks/useTTS.js';

/**
 * ChatMessage – Renders a single message bubble.
 * For bot messages, shows optional TTS speaker, MitreBadge, and risk score chip.
 * role: 'user' | 'bot'
 */
function ChatMessage({ role, text, timestamp, mitre_id, mitre_tactic, mitre_technique, confidence, risk_score }) {
    const isUser = role === 'user';
    const { speak, stop, isSpeaking, supported: ttsSupported } = useTTS();

    return (
        <>
            <div className={`chat-bubble-wrapper ${isUser ? 'user' : 'bot'}`}>
                {!isUser && (
                    <div className="chat-avatar bot">🛡️</div>
                )}
                <div className={`chat-bubble ${isUser ? 'user' : 'bot'}`} style={{ position: 'relative' }}>
                    {/* Render markdown-like line breaks */}
                    {text.split('\n').map((line, i) => (
                        <span key={i}>{line}<br /></span>
                    ))}

                    {/* TTS speaker button – bot messages only */}
                    {!isUser && ttsSupported && (
                        <button
                            id={`tts-btn-${timestamp}`}
                            onClick={() => isSpeaking ? stop() : speak(text)}
                            title={isSpeaking ? 'Stop reading' : 'Read aloud'}
                            style={{
                                position: 'absolute',
                                top: 6,
                                right: 6,
                                background: 'none',
                                border: 'none',
                                cursor: 'pointer',
                                color: isSpeaking ? 'var(--clr-accent-cyan)' : 'var(--clr-text-secondary)',
                                padding: 2,
                                opacity: 0.7,
                                transition: 'opacity 0.15s, color 0.15s',
                            }}
                            onMouseOver={e => e.currentTarget.style.opacity = 1}
                            onMouseOut={e => e.currentTarget.style.opacity = 0.7}
                        >
                            {isSpeaking ? <VolumeX size={13} /> : <Volume2 size={13} />}
                        </button>
                    )}
                </div>
                {isUser && (
                    <div className="chat-avatar user">👤</div>
                )}
            </div>

            {/* MITRE badge + risk score — shown only on bot replies */}
            {!isUser && (mitre_id || risk_score != null) && (
                <div className="chat-enrichment-row">
                    <MitreBadge
                        mitreId={mitre_id}
                        mitreTactic={mitre_tactic}
                        mitreTechnique={mitre_technique}
                        confidence={confidence}
                    />
                    {risk_score != null && (
                        <span className="risk-chip" title={`Risk score: ${risk_score}/10`}>
                            ⚠️ Risk {risk_score.toFixed(1)}/10
                        </span>
                    )}
                </div>
            )}

            <div className={`chat-bubble-time ${isUser ? '' : 'bot-time'}`}>
                {timestamp}
            </div>
        </>
    );
}

export default ChatMessage;

