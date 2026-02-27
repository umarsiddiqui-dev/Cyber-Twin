/**
 * actionStore.js – Phase 4 (Zustand)
 * Manages the list of proposed + reviewed actions.
 */

import { create } from 'zustand';

const useActionStore = create((set, get) => ({
    actions: [],
    pendingCount: 0,
    isLoading: false,
    error: null,

    setActions: (actions) => set({
        actions,
        pendingCount: actions.filter(a => a.status === 'pending').length,
        error: null,
    }),

    setLoading: (val) => set({ isLoading: val }),

    setError: (msg) => set({ error: msg }),

    /** Update a single action in the list (after approve/reject) */
    updateAction: (updated) => set((state) => {
        const actions = state.actions.map(a => a.id === updated.id ? updated : a);
        return {
            actions,
            pendingCount: actions.filter(a => a.status === 'pending').length,
        };
    }),

    /** Prepend newly proposed actions to the list */
    addActions: (newActions) => set((state) => {
        const merged = [...newActions, ...state.actions];
        return {
            actions: merged,
            pendingCount: merged.filter(a => a.status === 'pending').length,
        };
    }),

    clearActions: () => set({ actions: [], pendingCount: 0 }),
}));

export default useActionStore;
