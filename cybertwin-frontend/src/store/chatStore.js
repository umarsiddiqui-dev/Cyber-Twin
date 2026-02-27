import { create } from 'zustand';

/**
 * CyberTwin Chat Store (Zustand)
 * Manages the full conversation state for the chat interface.
 */
const useChatStore = create((set, get) => ({
    /** @type {Array<{ id: string, role: 'user'|'bot', text: string, timestamp: string }>} */
    messages: [],

    /** Whether a backend response is in flight */
    isLoading: false,

    /** Current session ID (set by backend on first message) */
    sessionId: null,

    /**
     * Pending suggestion from a SuggestionChip click.
     * ChatInput watches this and auto-submits when set.
     */
    suggestion: null,

    /**
     * Add a message to the conversation.
     * @param {'user'|'bot'} role
     * @param {string} text
     * @param {object} enrichment - Phase 3 AI enrichment (mitre_id, risk_score, etc.)
     */
    addMessage: (role, text, enrichment = {}) => {
        const msg = {
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
            role,
            text,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            // Phase 3 enrichment
            mitre_id: enrichment.mitre_id || null,
            mitre_tactic: enrichment.mitre_tactic || null,
            mitre_technique: enrichment.mitre_technique || null,
            confidence: enrichment.confidence ?? null,
            risk_score: enrichment.risk_score ?? null,
        };
        set((state) => ({ messages: [...state.messages, msg] }));
        return msg;
    },

    setLoading: (val) => set({ isLoading: val }),

    setSessionId: (id) => set({ sessionId: id }),

    setSuggestion: (text) => set({ suggestion: text }),

    clearSuggestion: () => set({ suggestion: null }),

    clearChat: () => set({ messages: [], sessionId: null, suggestion: null }),
}));

export default useChatStore;
