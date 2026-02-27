"""
WebSocket Log Stream – Phase 2 (Real Implementation)
Replaces the Phase 1 stub. Registers each browser tab into the
ConnectionManager so incident_service can broadcast live alerts to all clients.
"""

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.ws.connection_manager import manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/logs")
async def log_stream(websocket: WebSocket):
    """
    Connect browser clients to the live alert stream.
    - Sends an immediate 'connected' handshake.
    - Stays open; alerts are pushed by incident_service via ConnectionManager.broadcast().
    - Listens for client pings and replies with pongs.
    """
    await manager.connect(websocket)

    try:
        # Send connection confirmation
        await websocket.send_text(json.dumps({
            "type": "connected",
            "message": "CyberTwin live stream active. Monitoring for threats.",
            "clients": manager.client_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        # Listen loop – keeps connection alive; handles client ping/close
        while True:
            try:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text(json.dumps({
                        "type": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }))
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)
        logger.info("[WS] Client cleanly disconnected")
