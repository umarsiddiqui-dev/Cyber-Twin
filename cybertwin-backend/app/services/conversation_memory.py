"""
Conversation Memory Service
Stores per-session chat history for multi-turn AI conversations.

Storage: In-memory dict (no DB required).
TTL: Sessions expire after 30 minutes of inactivity.
Capacity: Keeps last 10 turns (20 messages) per session.

REPLACEMENT POINT (Phase 4+):
  Swap the in-memory dict for a Redis client to support
  multi-process deployments and persistent history.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
MAX_TURNS    = 10      # max (user, assistant) pairs stored per session
SESSION_TTL  = 1800    # seconds before inactive session is evicted (30 min)


# ── Internal store ────────────────────────────────────────────────────────────
# Structure: { session_id: {"messages": [...], "last_active": datetime} }
_store: dict[str, dict] = defaultdict(lambda: {"messages": [], "last_active": None})
_cleanup_task: asyncio.Task | None = None


def get_history(session_id: str) -> list[dict]:
    """Return the list of {role, content} dicts for this session."""
    entry = _store[session_id]
    entry["last_active"] = datetime.now(timezone.utc)
    return list(entry["messages"])


def add_turn(session_id: str, user_message: str, assistant_reply: str) -> None:
    """Append a user+assistant turn to this session's history."""
    entry = _store[session_id]
    entry["last_active"] = datetime.now(timezone.utc)

    messages: list[dict] = entry["messages"]
    messages.append({"role": "user",      "content": user_message})
    messages.append({"role": "assistant", "content": assistant_reply})

    # Trim to last MAX_TURNS * 2 messages
    if len(messages) > MAX_TURNS * 2:
        entry["messages"] = messages[-(MAX_TURNS * 2):]
    else:
        entry["messages"] = messages


def clear_session(session_id: str) -> None:
    """Manually clear a session (e.g. on user logout)."""
    if session_id in _store:
        del _store[session_id]


def session_count() -> int:
    return len(_store)


# ── Background TTL cleanup ────────────────────────────────────────────────────

async def _cleanup_loop(interval: int = 300) -> None:
    """Periodically evict sessions that have been inactive for SESSION_TTL seconds."""
    while True:
        await asyncio.sleep(interval)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=SESSION_TTL)
        expired = [
            sid for sid, data in _store.items()
            if data["last_active"] and data["last_active"] < cutoff
        ]
        for sid in expired:
            del _store[sid]
        if expired:
            logger.debug(f"[Memory] Evicted {len(expired)} expired sessions")


def start_cleanup_task() -> asyncio.Task:
    """Start the background cleanup task. Call from app lifespan."""
    global _cleanup_task
    _cleanup_task = asyncio.create_task(_cleanup_loop())
    return _cleanup_task


def stop_cleanup_task() -> None:
    """Cancel the background cleanup task. Call on shutdown."""
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()
