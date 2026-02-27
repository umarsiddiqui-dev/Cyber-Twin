"""
Export Router – Phase 5 (Updated Phase 3 Memory Leak Fix)
Streams action_logs and incident_logs as downloadable CSV files.

Phase 3 change:
  Replaced full table load (result.scalars().all()) with yield_per(100)
  batch iteration. For large datasets, this prevents loading the entire
  table into memory. The StreamingResponse generator pulls rows in 100-row
  chunks and yields one CSV line at a time.
"""

import csv
import io
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.action_log import ActionLog
from app.models.incident_log import IncidentLog

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Export"])


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _extract_risk(reason: str | None) -> str:
    if not reason:
        return ""
    if reason.startswith("[HIGH]"):   return "HIGH"
    if reason.startswith("[MEDIUM]"): return "MEDIUM"
    if reason.startswith("[LOW]"):    return "LOW"
    return ""


# ── GET /api/export/actions.csv ───────────────────────────────────────────────

@router.get("/export/actions.csv", summary="Export all action logs as CSV")
async def export_actions(db: AsyncSession = Depends(get_db)):
    """
    Download all action_logs as a CSV file.
    Uses yield_per(100) to stream rows in batches — safe for large tables.
    """
    headers = [
        "id", "incident_id", "action_type", "command",
        "status", "simulated", "risk_level", "reason",
        "reviewed_by", "reject_reason",
        "created_at", "reviewed_at", "executed_at",
    ]

    async def _generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        # Write header
        writer.writerow(headers)
        buf.seek(0)
        yield buf.read()
        buf.seek(0); buf.truncate(0)

        # Stream rows in batches of 100 (yield_per)
        stmt = select(ActionLog).order_by(ActionLog.created_at).execution_options(yield_per=100)
        result = await db.stream(stmt)
        async for partition in result.scalars().partitions():
            for a in partition:
                writer.writerow([
                    a.id, a.incident_id, a.action_type,
                    a.command, a.status, a.simulated,
                    _extract_risk(a.reason), a.reason,
                    a.reviewed_by, a.reject_reason,
                    a.created_at, a.reviewed_at, a.executed_at,
                ])
            buf.seek(0)
            yield buf.read()
            buf.seek(0); buf.truncate(0)

    filename = f"cybertwin_actions_{_timestamp()}.csv"
    logger.info(f"[Export] Streaming actions CSV (yield_per=100)")
    return StreamingResponse(
        _generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── GET /api/export/incidents.csv ─────────────────────────────────────────────

@router.get("/export/incidents.csv", summary="Export all incident logs as CSV")
async def export_incidents(db: AsyncSession = Depends(get_db)):
    """
    Download all incident_logs as a CSV file.
    Uses yield_per(100) to stream rows in batches — safe for large tables.
    """
    headers = [
        "id", "source", "severity", "title",
        "mitre_tactic", "mitre_technique", "risk_score",
        "status", "created_at", "resolved_at",
    ]

    async def _generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(headers)
        buf.seek(0)
        yield buf.read()
        buf.seek(0); buf.truncate(0)

        stmt = select(IncidentLog).order_by(IncidentLog.created_at).execution_options(yield_per=100)
        result = await db.stream(stmt)
        async for partition in result.scalars().partitions():
            for i in partition:
                writer.writerow([
                    i.id, i.source, i.severity, i.title,
                    i.mitre_tactic, i.mitre_technique, i.risk_score,
                    i.status, i.created_at, i.resolved_at,
                ])
            buf.seek(0)
            yield buf.read()
            buf.seek(0); buf.truncate(0)

    filename = f"cybertwin_incidents_{_timestamp()}.csv"
    logger.info(f"[Export] Streaming incidents CSV (yield_per=100)")
    return StreamingResponse(
        _generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
