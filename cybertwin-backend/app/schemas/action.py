"""
Action Schemas – Phase 4 (Updated Phase 1 Security Hardening)
Pydantic models for the /api/actions router.

Phase 1 changes:
  - Removed 'reviewed_by' from ApproveActionRequest and RejectActionRequest.
    The reviewer identity is now extracted directly from the JWT subject claim
    on the backend, preventing client-supplied identity spoofing.
"""

from datetime import datetime
from pydantic import BaseModel, Field


class ProposeActionsRequest(BaseModel):
    """Request body to propose actions for a given incident."""
    incident_id: str = Field(..., description="UUID of the incident_logs record")
    session_id: str | None = Field(None, description="Optional chat session context")


class ActionResponse(BaseModel):
    """Single action record returned to the frontend."""
    id: str
    incident_id: str | None
    session_id: str | None
    action_type: str
    command: str
    parameters: str | None     # raw JSON string
    reason: str | None
    risk_level: str | None     # stored as part of reason text; parsed in frontend
    status: str                # pending | approved | rejected | executed | failed
    simulated: bool
    execution_output: str | None
    reviewed_by: str | None
    reject_reason: str | None
    created_at: datetime
    reviewed_at: datetime | None
    executed_at: datetime | None

    class Config:
        from_attributes = True


class ApproveActionRequest(BaseModel):
    """
    Request body to approve a pending action.
    NOTE: 'reviewed_by' has been removed — identity is extracted from JWT subject claim.
    Optional notes field for audit context.
    """
    notes: str | None = Field(None, max_length=500, description="Optional approval notes")


class RejectActionRequest(BaseModel):
    """
    Request body to reject a pending action.
    NOTE: 'reviewed_by' has been removed — identity is extracted from JWT subject claim.
    """
    reason: str = Field(..., min_length=1, max_length=1000, description="Justification for rejection")


class ActionListResponse(BaseModel):
    """Paginated action list."""
    total: int
    actions: list[ActionResponse]
