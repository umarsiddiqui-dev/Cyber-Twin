import { useEffect, useRef } from 'react';
import useIncidentStore from '../store/incidentStore.js';

// Phase 4 fix: read from env so any deployment target can override this
const WS_URL = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000/ws/logs';
const RECONNECT_DELAYS = [1000, 2000, 4000, 8000, 15000]; // exponential backoff

/**
 * useLogStream – React hook that opens a WebSocket to the backend
 * and pipes incoming alert events into the incidentStore.
 *
 * Features:
 *  - Automatic reconnect with exponential backoff
 *  - Connection status tracking (connecting / connected / disconnected)
 *  - Cleans up on component unmount
 */
function useLogStream() {
    const { addIncident, setConnectionStatus } = useIncidentStore();
    const wsRef = useRef(null);
    const attemptRef = useRef(0);
    const unmountedRef = useRef(false);

    useEffect(() => {
        unmountedRef.current = false;

        function connect() {
            if (unmountedRef.current) return;

            setConnectionStatus('connecting');
            const ws = new WebSocket(WS_URL);
            wsRef.current = ws;

            ws.onopen = () => {
                if (unmountedRef.current) { ws.close(); return; }
                setConnectionStatus('connected');
                attemptRef.current = 0;  // reset backoff on success
            };

            ws.onmessage = (evt) => {
                try {
                    const msg = JSON.parse(evt.data);
                    if (msg.type === 'alert') {
                        addIncident(msg);
                    }
                    // 'connected', 'pong', 'heartbeat' messages are intentionally ignored
                } catch {
                    // Malformed JSON – skip
                }
            };

            ws.onclose = () => {
                if (unmountedRef.current) return;
                setConnectionStatus('disconnected');
                // Auto-reconnect with backoff
                const delay = RECONNECT_DELAYS[Math.min(attemptRef.current, RECONNECT_DELAYS.length - 1)];
                attemptRef.current++;
                setTimeout(connect, delay);
            };

            ws.onerror = () => {
                // onclose fires after onerror – reconnect handled there
                setConnectionStatus('disconnected');
            };
        }

        connect();

        return () => {
            unmountedRef.current = true;
            wsRef.current?.close();
        };
    }, []); // eslint-disable-line react-hooks/exhaustive-deps
}

export default useLogStream;
