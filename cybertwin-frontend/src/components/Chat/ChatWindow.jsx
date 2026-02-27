import { useEffect, useRef } from 'react';
import useChatStore from '../../store/chatStore.js';
import ChatMessage from './ChatMessage.jsx';
import ChatInput from './ChatInput.jsx';

/**
 * ChatWindow – Full chat panel: message history + input bar.
 * Auto-scrolls to the latest message.
 */
function ChatWindow() {
    const { messages, isLoading } = useChatStore();
    const bottomRef = useRef(null);

    // Scroll to bottom whenever messages update
    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages, isLoading]);

    return (
        <div className="chat-layout">
            {/* ── Message area ── */}
            <div className="chat-messages" id="chat-messages-container">

                {messages.length === 0 && !isLoading ? (
                    <div className="chat-empty">
                        <div className="chat-empty-icon">🛡️</div>
                        <div className="chat-empty-title">CyberTwin is ready</div>
                        <div className="chat-empty-sub">
                            Ask me about a threat, paste a log entry, or describe suspicious activity.
                            I'll help you interpret and respond to it.
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12, justifyContent: 'center' }}>
                            {EXAMPLE_PROMPTS.map((p) => (
                                <SuggestionChip key={p} text={p} />
                            ))}
                        </div>
                    </div>
                ) : (
                    <>
                        {messages.map((msg) => (
                            // BUG FIX: spread all msg fields so ChatMessage receives
                            // mitre_id, mitre_tactic, mitre_technique, confidence, risk_score
                            <ChatMessage key={msg.id} {...msg} />
                        ))}

                        {/* Typing indicator while loading */}
                        {isLoading && (
                            <div className="chat-bubble-wrapper bot">
                                <div className="chat-avatar bot">🛡️</div>
                                <div className="typing-indicator">
                                    <div className="typing-dot" />
                                    <div className="typing-dot" />
                                    <div className="typing-dot" />
                                </div>
                            </div>
                        )}

                        <div ref={bottomRef} />
                    </>
                )}
            </div>

            {/* ── Input bar ── */}
            <ChatInput />
        </div>
    );
}

/* ── Example prompt chips ── */
const EXAMPLE_PROMPTS = [
    'Explain this SSH brute force alert',
    'What is MITRE T1595?',
    'How do I block port 4444?',
    'What does a DDoS attack look like?',
];

/**
 * SuggestionChip – Clicking pre-fills and submits the chat input.
 * Uses the global Zustand store's submit action so the API is called.
 */
function SuggestionChip({ text }) {
    return (
        <button
            onClick={() => {
                // Dispatch to the store's pending input and trigger submit
                useChatStore.getState().setSuggestion(text);
            }}
            style={{
                background: 'var(--clr-bg-elevated)',
                border: '1px solid var(--clr-border)',
                borderRadius: 99,
                padding: '5px 14px',
                fontSize: 12,
                color: 'var(--clr-text-secondary)',
                cursor: 'pointer',
                transition: 'border-color 0.15s, color 0.15s',
            }}
            onMouseEnter={e => {
                e.currentTarget.style.borderColor = 'var(--clr-accent-cyan)';
                e.currentTarget.style.color = 'var(--clr-accent-cyan)';
            }}
            onMouseLeave={e => {
                e.currentTarget.style.borderColor = 'var(--clr-border)';
                e.currentTarget.style.color = 'var(--clr-text-secondary)';
            }}
        >
            {text}
        </button>
    );
}

export default ChatWindow;

