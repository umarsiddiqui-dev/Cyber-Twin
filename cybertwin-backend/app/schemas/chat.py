from datetime import datetime
from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    """Incoming chat message from the frontend."""
    message: str = Field(..., min_length=1, max_length=4000, description="User's message text")
    session_id: str | None = Field(None, description="Optional session ID for conversation continuity")


class ChatResponse(BaseModel):
    """Response returned to the frontend — Phase 3 enriched."""
    reply: str
    session_id: str
    timestamp: str
    # Phase 3 enrichment fields (None when offline / not applicable)
    mitre_id: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    confidence: float | None = None
    risk_score: float | None = None


class IncidentSummary(BaseModel):
    """Lightweight incident representation for listing."""
    id: str
    source: str
    severity: str
    title: str
    status: str
    risk_score: float
    created_at: datetime

    class Config:
        from_attributes = True
