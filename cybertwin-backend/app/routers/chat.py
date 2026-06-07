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


from fastapi.responses import StreamingResponse
import json

@router.post("/chat", summary="Send a message to CyberTwin AI (Streamed)")
async def chat(body: ChatRequest, db: AsyncSession = Depends(get_db)):
    """
    Accepts a user message, queries the AI engine (with MITRE context),
    and streams the reply via Server-Sent Events (SSE).
    """
    # Fetch recent incident titles for AI context injection
    recent_result = await db.execute(
        select(IncidentLog.title)
        .order_by(desc(IncidentLog.created_at))
        .limit(5)
    )
    recent_incidents = [row[0] for row in recent_result.fetchall()]

    from app.services.ai_service import get_response_stream

    async def event_generator():
        full_reply = ""
        session_id = body.session_id

        async for chunk_json in get_response_stream(body.message, session_id, recent_incidents):
            # Parse json to extract full_reply at the end
            try:
                data = json.loads(chunk_json)
                if data.get("type") == "done":
                    full_reply = data.get("full_reply", "")
                elif data.get("type") == "metadata":
                    session_id = data.get("session_id")
            except:
                pass
            
            yield f"data: {chunk_json}\n\n"
        
        # Persist to database after stream finishes
        log = ChatLog(
            session_id=session_id,
            user_message=body.message,
            bot_reply=full_reply,
        )
        db.add(log)
        await db.commit()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

