"""
WebSocket Connection Manager
Manages all active browser connections and broadcasts JSON alerts to all of them.
Thread-safe for use with asyncio.
"""

import asyncio
import json
import logging
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Maintains the set of active WebSocket connections and broadcasts
    messages to all of them concurrently.
    """

    def __init__(self):
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)
        logger.info(f"[WS] Client connected. Total: {len(self._connections)}")

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
        logger.info(f"[WS] Client disconnected. Total: {len(self._connections)}")

    async def broadcast(self, message: dict) -> None:
        """Send a JSON message to every connected client. Drops dead connections."""
        if not self._connections:
            return

        payload = json.dumps(message, default=str)
        dead: list[WebSocket] = []

        async with self._lock:
            targets = list(self._connections)

        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        # Clean up dead connections
        if dead:
            async with self._lock:
                for d in dead:
                    if d in self._connections:
                        self._connections.remove(d)

    @property
    def client_count(self) -> int:
        return len(self._connections)


# ── Singleton shared across routers and services ──────────────────────────────
manager = ConnectionManager()
