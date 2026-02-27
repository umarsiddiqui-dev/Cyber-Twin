"""
Chat Router – Phase 3
Calls the AI service (GPT-4o or offline fallback) instead of the Phase 1 echo stub.
The endpoint URL (/api/chat) and request schema are unchanged.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.schemas.chat import ChatRequest, ChatResponse
from app.services.ai_service import get_response
from app.models.chat_log import ChatLog
from app.models.incident_log import IncidentLog
from app.database import get_db

router = APIRouter(tags=["Chat"])


@router.post("/chat", response_model=ChatResponse, summary="Send a message to CyberTwin AI")
async def chat(body: ChatRequest, db: AsyncSession = Depends(get_db)):
    """
    Accepts a user message, queries the AI engine (with MITRE context),
    persists the exchange, and returns the enriched reply.
    """
    # Fetch recent incident titles for AI context injection
    recent_result = await db.execute(
        select(IncidentLog.title)
        .order_by(desc(IncidentLog.created_at))
        .limit(5)
    )
    recent_incidents = [row[0] for row in recent_result.fetchall()]

    # Call AI service (GPT-4o or offline fallback)
    result = await get_response(
        message=body.message,
        session_id=body.session_id,
        recent_incidents=recent_incidents,
    )

    # Persist to database
    log = ChatLog(
        session_id=result["session_id"],
        user_message=body.message,
        bot_reply=result["reply"],
    )
    db.add(log)
    await db.commit()  # explicitly commit — do not rely on implicit auto-commit

    return ChatResponse(
        reply=result["reply"],
        session_id=result["session_id"],
        timestamp=result["timestamp"],
        mitre_id=result.get("mitre_id"),
        mitre_tactic=result.get("mitre_tactic"),
        mitre_technique=result.get("mitre_technique"),
        confidence=result.get("confidence"),
        risk_score=result.get("risk_score"),
    )

