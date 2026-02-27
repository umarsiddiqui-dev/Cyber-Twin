import { create } from 'zustand';

/**
 * CyberTwin Incident Store (Zustand) – Phase 2
 * Holds the live incident feed streamed via WebSocket.
 */
const useIncidentStore = create((set) => ({
    /** @type {Array<IncidentEvent>} Live incidents, newest first */
    incidents: [],

    /** Connection state for the WebSocket */
    connectionStatus: 'disconnected',  // 'connecting' | 'connected' | 'disconnected'

    /** Aggregate stats derived from incidents */
    stats: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },

    /**
     * Add a new incident from the WebSocket stream.
     * Caps the list at 200 to avoid memory growth.
     */
    addIncident: (event) => {
        set((state) => {
            const updated = [event, ...state.incidents].slice(0, 200);
            return {
                incidents: updated,
                stats: computeStats(updated),
            };
        });
    },

    setConnectionStatus: (status) => set({ connectionStatus: status }),

    clearIncidents: () =>
        set({ incidents: [], stats: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 } }),
}));

/** Compute severity counts from the incident list. */
function computeStats(incidents) {
    return incidents.reduce(
        (acc, inc) => {
            const key = inc.severity?.toLowerCase() || 'info';
            if (key in acc) acc[key]++;
            acc.total++;
            return acc;
        },
        { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
    );
}

export default useIncidentStore;
