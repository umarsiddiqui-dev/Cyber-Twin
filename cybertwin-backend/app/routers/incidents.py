from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

from app.models.incident_log import IncidentLog
from app.database import get_db

router = APIRouter(tags=["Incidents"])


# ── Response schema ───────────────────────────────────────────────────────────
class IncidentResponse(BaseModel):
    id: str
    source: str
    severity: str
    title: str
    raw_log: str | None
    src_ip: str | None = None
    dst_ip: str | None = None
    port: int | None = None
    risk_score: float
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get(
    "/incidents",
    response_model=list[IncidentResponse],
    summary="List recent security incidents",
)
async def get_incidents(
    limit: int = Query(50, ge=1, le=200, description="Max results to return"),
    severity: str | None = Query(None, description="Filter by severity: CRITICAL|HIGH|MEDIUM|LOW|INFO"),
    status: str | None = Query(None, description="Filter by status: open|resolved|ignored"),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns recent incidents from the database, newest first.
    Phase 3 will add MITRE tagging and risk score to each record.
    """
    stmt = select(IncidentLog).order_by(desc(IncidentLog.created_at)).limit(limit)

    if severity:
        stmt = stmt.where(IncidentLog.severity == severity.upper())
    if status:
        stmt = stmt.where(IncidentLog.status == status.lower())

    result = await db.execute(stmt)
    return result.scalars().all()


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentResponse,
    summary="Get a single incident by ID",
)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(IncidentLog).where(IncidentLog.id == incident_id)
    )
    record = result.scalar_one_or_none()
    if not record:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Incident not found")
    return record


@router.patch(
    "/incidents/{incident_id}/resolve",
    response_model=IncidentResponse,
    summary="Mark an incident as resolved",
)
async def resolve_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """User approval action — mark an incident as resolved."""
    result = await db.execute(
        select(IncidentLog).where(IncidentLog.id == incident_id)
    )
    record = result.scalar_one_or_none()
    if not record:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Incident not found")

    record.status = "resolved"
    record.resolved_at = datetime.utcnow()
    await db.commit()
    await db.refresh(record)
    return record

