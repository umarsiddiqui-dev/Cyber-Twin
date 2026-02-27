"""
Actions Router – Phase 4 (Updated Phase 1 Security Hardening + Phase 3 Validation)
Provides endpoints to propose, list, approve, and reject AI-generated
remediation actions.

Phase 1 changes:
  - POST /approve and POST /reject now require a valid JWT (Depends(get_current_user)).
  - reviewed_by is extracted from the JWT subject claim, not trusted from the client.

Phase 3 changes:
  - RFC1918 / reserved IP validation before action generation.

Endpoints:
  POST /api/actions/propose       – Generate actions for an incident
  GET  /api/actions               – List actions (filterable by status)
  POST /api/actions/{id}/approve  – Approve + execute (or simulate)
  POST /api/actions/{id}/reject   – Reject with reason
"""

import json
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.database import get_db
from app.models.action_log import ActionLog
from app.models.incident_log import IncidentLog
from app.schemas.action import (
    ProposeActionsRequest,
    ActionResponse,
    ActionListResponse,
    ApproveActionRequest,
    RejectActionRequest,
)
from app.services.action_generator import generate_actions
from app.services.execution_engine import execute_action
from app.auth.dependencies import get_current_user
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Actions"])


# ── RFC1918 / Reserved IP validation ──────────────────────────────────────────

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("0.0.0.0/8"),        # this-network
]


def _is_private_ip(ip_str: str) -> bool:
    """
    Return True if the IP is RFC1918 private, loopback, link-local, or otherwise
    not routable as a threat actor address.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        # Malformed IP string — treat as invalid/private to be safe
        return True


# ── POST /api/actions/propose ─────────────────────────────────────────────────

@router.post("/actions/propose", response_model=list[ActionResponse], summary="Propose remediation actions for an incident")
async def propose_actions(body: ProposeActionsRequest, db: AsyncSession = Depends(get_db)):
    """
    Look up the incident, run the action generator, and persist all
    proposed actions as 'pending' records in action_logs.
    """
    # Fetch the incident
    result = await db.execute(select(IncidentLog).where(IncidentLog.id == body.incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{body.incident_id}' not found")

    # Determine src_ip — stored in title or raw_log; parse conservatively
    import re
    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", incident.raw_log or incident.title or "")
    src_ip = ip_match.group(1) if ip_match else None

    # ── Phase 3: RFC1918 guard ────────────────────────────────────────────────
    if not src_ip or _is_private_ip(src_ip):
        logger.warning(
            f"[Actions] Propose blocked: src_ip={src_ip!r} is private/reserved "
            f"(incident {body.incident_id})"
        )
        raise HTTPException(
            status_code=400,
            detail=(
                f"Cannot generate firewall actions for private/reserved IP '{src_ip}'. "
                "Threat actor IPs must be publicly routable addresses."
            ),
        )

    # Generate structured actions
    proposed = generate_actions(
        src_ip=src_ip,
        severity=incident.severity,
        mitre_tactic=incident.mitre_tactic,
        mitre_id=incident.mitre_technique,         # column stores the T-code
        mitre_technique=None,
    )

    if not proposed:
        return []

    # Persist each action as a pending record
    saved: list[ActionLog] = []
    for p in proposed:
        record = ActionLog(
            incident_id=body.incident_id,
            session_id=body.session_id,
            action_type=p.action_type,
            command=p.command,
            parameters=json.dumps(p.parameters),
            reason=f"[{p.risk_level}] {p.reason}",
            status="pending",
            simulated=True,
        )
        db.add(record)
        saved.append(record)

    await db.commit()
    for r in saved:
        await db.refresh(r)

    logger.info(f"[Actions] {len(saved)} action(s) proposed for incident {body.incident_id}")
    return saved


# ── GET /api/actions ──────────────────────────────────────────────────────────

@router.get("/actions", response_model=ActionListResponse, summary="List all actions")
async def list_actions(
    status: str | None = Query(None, description="Filter by status: pending|approved|rejected|executed|failed"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Return all action records, optionally filtered by status."""
    query = select(ActionLog).order_by(desc(ActionLog.created_at))
    count_query = select(func.count()).select_from(ActionLog)

    if status:
        query = query.where(ActionLog.status == status)
        count_query = count_query.where(ActionLog.status == status)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    result = await db.execute(query.limit(limit).offset(offset))
    actions = result.scalars().all()
    return ActionListResponse(total=total, actions=list(actions))


# ── POST /api/actions/{action_id}/approve ─────────────────────────────────────

@router.post("/actions/{action_id}/approve", response_model=ActionResponse, summary="Approve and execute an action")
async def approve_action(
    action_id: str,
    body: ApproveActionRequest,
    current_user: Annotated[str, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """
    Human approval gate — sets status to 'approved', runs the execution
    engine (simulation or real), and updates the record with the result.

    Requires a valid JWT. The reviewer identity is extracted from the token's
    'sub' claim — the client cannot supply or spoof it.
    """
    result = await db.execute(select(ActionLog).where(ActionLog.id == action_id))
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Action is already '{action.status}' — only 'pending' actions can be approved"
        )

    # Determine execution mode from config
    use_simulation = not getattr(settings, "ALLOW_REAL_EXECUTION", False)

    exec_result = await execute_action(action.command, simulated=use_simulation)

    # Update record — reviewer identity comes from JWT, not the request body
    action.status = "executed" if exec_result.success else "failed"
    action.reviewed_by = current_user          # ← JWT sub claim
    action.reviewed_at = datetime.now(timezone.utc)
    action.executed_at = exec_result.executed_at
    action.simulated = exec_result.simulated
    action.execution_output = exec_result.output

    await db.commit()
    await db.refresh(action)

    logger.info(
        f"[Actions] {action_id} approved by {current_user!r} → "
        f"status={action.status} simulated={exec_result.simulated}"
    )
    return action


# ── POST /api/actions/{action_id}/reject ──────────────────────────────────────

@router.post("/actions/{action_id}/reject", response_model=ActionResponse, summary="Reject a proposed action")
async def reject_action(
    action_id: str,
    body: RejectActionRequest,
    current_user: Annotated[str, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """
    Mark a proposed action as rejected with a mandatory reason.

    Requires a valid JWT. The reviewer identity is extracted from the token's
    'sub' claim.
    """
    result = await db.execute(select(ActionLog).where(ActionLog.id == action_id))
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Action is already '{action.status}' — only 'pending' actions can be rejected"
        )

    action.status = "rejected"
    action.reviewed_by = current_user          # ← JWT sub claim
    action.reject_reason = body.reason
    action.reviewed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(action)
    logger.info(f"[Actions] {action_id} rejected by {current_user!r}: {body.reason[:60]}")
    return action
