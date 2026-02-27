import { useRef, useState, useEffect, useCallback } from 'react';
import { Send, Mic, MicOff } from 'lucide-react';
import { sendMessage } from '../../services/api.js';
import useChatStore from '../../store/chatStore.js';
import useVoiceInput from '../../hooks/useVoiceInput.js';

/**
 * ChatInput – Textarea + Send button.
 * Submits message on Enter (without Shift) or clicking Send.
 */
function ChatInput() {
    const [draft, setDraft] = useState('');
    const textareaRef = useRef(null);
    const { addMessage, setLoading, setSessionId, sessionId, isLoading, suggestion, clearSuggestion } = useChatStore();

    // Voice STT — auto-submits when a final transcript is received
    const handleVoiceResult = useCallback((text) => {
        setDraft(text);
        setTimeout(() => submitRef.current?.(), 80);
    }, []);
    const { isListening, startListening, stopListening, supported: voiceSupported } = useVoiceInput(handleVoiceResult);

    // When a SuggestionChip sets a suggestion, populate the textarea and submit
    useEffect(() => {
        if (suggestion) {
            setDraft(suggestion);
            clearSuggestion();
            // Submit on next tick so draft state has settled
            setTimeout(() => {
                submitRef.current?.();
            }, 50);
        }
    }, [suggestion, clearSuggestion]);

    // Keep a stable ref to handleSubmit so the suggestion effect can call it
    const submitRef = useRef(null);

    // Auto-resize textarea
    useEffect(() => {
        const el = textareaRef.current;
        if (el) {
            el.style.height = 'auto';
            el.style.height = `${Math.min(el.scrollHeight, 120)}px`;
        }
    }, [draft]);

    const handleSubmit = async () => {
        const text = draft.trim();
        if (!text || isLoading) return;

        setDraft('');
        addMessage('user', text);
        setLoading(true);

        try {
            // Pass the current sessionId for multi-turn conversation continuity
            const currentSessionId = useChatStore.getState().sessionId;
            const data = await sendMessage(text, currentSessionId);

            // Store reply with Phase 3 enrichment fields
            addMessage('bot', data.reply, {
                mitre_id: data.mitre_id,
                mitre_tactic: data.mitre_tactic,
                mitre_technique: data.mitre_technique,
                confidence: data.confidence,
                risk_score: data.risk_score,
            });

            if (data.session_id) setSessionId(data.session_id);
        } catch {
            addMessage('bot', '⚠️ Unable to reach the backend. Please ensure the server is running on port 8000.');
        } finally {
            setLoading(false);
        }
    };

    // Wire the submit ref for suggestion auto-submit
    submitRef.current = handleSubmit;

    const handleKeyDown = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSubmit();
        }
    };

    return (
        <div className="chat-input-bar">
            <div className="chat-input-wrapper">
                {/* Microphone button (Phase 5 – shown only when browser supports STT) */}
                {voiceSupported && (
                    <button
                        id="chat-mic-btn"
                        onClick={isListening ? stopListening : startListening}
                        disabled={isLoading}
                        title={isListening ? 'Stop listening' : 'Start voice input (Chrome/Edge)'}
                        aria-label="Voice input"
                        style={{
                            background: isListening ? 'rgba(255,77,77,0.15)' : 'none',
                            border: `1px solid ${isListening ? '#ff4d4d' : 'var(--clr-border)'}`,
                            borderRadius: 8,
                            padding: '0 10px',
                            color: isListening ? '#ff4d4d' : 'var(--clr-text-secondary)',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 4,
                            fontSize: 12,
                            animation: isListening ? 'voice-pulse 1.2s ease-in-out infinite' : 'none',
                            transition: 'all 0.2s',
                        }}
                    >
                        {isListening ? <MicOff size={14} /> : <Mic size={14} />}
                    </button>
                )}
                <textarea
                    id="chat-input"
                    ref={textareaRef}
                    className="chat-input"
                    placeholder={isListening ? '🎤 Listening…' : 'Ask CyberTwin about a threat, log entry, or security event…'}
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    onKeyDown={handleKeyDown}
                    rows={1}
                    disabled={isLoading}
                    aria-label="Chat message input"
                />
                <button
                    id="chat-send-btn"
                    className="chat-send-btn"
                    onClick={handleSubmit}
                    disabled={!draft.trim() || isLoading}
                    aria-label="Send message"
                    title="Send (Enter)"
                >
                    <Send size={15} />
                </button>
            </div>
            <div className="chat-hint">
                Press <kbd style={{ background: 'var(--clr-bg-elevated)', padding: '1px 5px', borderRadius: 3, fontSize: 10, border: '1px solid var(--clr-border)' }}>Enter</kbd> to send &nbsp;·&nbsp;
                <kbd style={{ background: 'var(--clr-bg-elevated)', padding: '1px 5px', borderRadius: 3, fontSize: 10, border: '1px solid var(--clr-border)' }}>Shift+Enter</kbd> for new line
                {voiceSupported && <>&nbsp;·&nbsp; 🎤 Click mic for voice input</>}
            </div>
        </div>
    );
}

export default ChatInput;
