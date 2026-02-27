"""
Echo Service – Phase 1 dummy responder.

This module purposefully contains NO AI logic.
It is a pure stub that returns a structured, canned response.

REPLACEMENT POINT (Phase 3):
  Replace the `generate_reply()` function body with a call to
  the OpenAI/Rasa NLP module. The router will NOT change.
"""

import uuid
from datetime import datetime, timezone


_PHASE1_REPLIES = [
    (
        "👋 CyberTwin received your message. In Phase 3, I'll analyze this using "
        "OpenAI GPT and cross-reference MITRE ATT&CK to provide a contextual explanation."
    ),
    (
        "📡 Message logged. When the AI core is active (Phase 3), I'll interpret this "
        "as a potential threat or query and suggest appropriate countermeasures."
    ),
    (
        "🛡️ Understood. Full NLP-based threat interpretation will be available once the "
        "AI engine is connected in Phase 3."
    ),
]

# Cycle through canned replies for variety in Phase 1
_reply_counter = 0


def generate_reply(message: str) -> dict:
    """
    Generate a Phase-1 stub response.

    Args:
        message: The user's input text.

    Returns:
        dict with ``reply``, ``session_id``, and ``timestamp``.
    """
    global _reply_counter
    reply = _PHASE1_REPLIES[_reply_counter % len(_PHASE1_REPLIES)]
    _reply_counter += 1

    return {
        "reply": reply,
        "session_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
