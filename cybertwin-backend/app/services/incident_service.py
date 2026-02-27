"""
Incident Service – Orchestrator (Phase 3 Enriched)
Receives a raw log entry, parses it, enriches with MITRE ATT&CK + risk score,
persists to the database, and broadcasts to all WebSocket clients.
"""

import logging

from app.services.log_parser import parse_log_line, IncidentEvent
from app.services import mitre_service, risk_scorer
from app.models.incident_log import IncidentLog
from app.database import AsyncSessionLocal
from app.ws.connection_manager import manager

logger = logging.getLogger(__name__)


async def ingest_raw_log(raw_log: str, source_hint: str = "simulator") -> IncidentEvent:
    """
    Full pipeline: parse → enrich (MITRE + risk) → persist → broadcast.

    Args:
        raw_log:     Raw log string from simulator or file tailer.
        source_hint: "snort" | "ossec" | "simulator"

    Returns:
        The structured IncidentEvent.
    """
    # 1. Parse raw log
    event = parse_log_line(raw_log, source_hint=source_hint)

    # 2. MITRE ATT&CK classification
    mitre_match = mitre_service.classify(f"{event.title} {event.raw_log}")

    # 3. Composite risk score
    computed_risk = risk_scorer.score(
        severity=event.severity,
        source=event.source,
        mitre_match=mitre_match,
    )

    # 4. Persist to DB (own session — runs outside request context)
    try:
        async with AsyncSessionLocal() as session:
            db_record = IncidentLog(
                id=event.id,
                source=event.source,
                severity=event.severity,
                title=event.title,
                raw_log=event.raw_log,
                mitre_tactic=mitre_match.tactic          if mitre_match else None,
                mitre_technique=mitre_match.technique_id  if mitre_match else None,
                risk_score=computed_risk,
                status="open",
            )
            session.add(db_record)
            await session.commit()

            mitre_str = f"[{mitre_match.technique_id}] {mitre_match.tactic}" if mitre_match else "No MITRE match"
            logger.info(
                f"[IncidentSvc] Saved [{event.severity}] {event.title[:50]} "
                f"| Risk={computed_risk:.1f} | {mitre_str}"
            )
    except Exception as e:
        logger.error(f"[IncidentSvc] DB write failed: {e}")

    # 5. Build enriched broadcast payload
    broadcast_payload = event.to_broadcast_dict()
    broadcast_payload.update({
        "mitre_id":         mitre_match.technique_id   if mitre_match else None,
        "mitre_tactic":     mitre_match.tactic          if mitre_match else None,
        "mitre_technique":  mitre_match.technique_name  if mitre_match else None,
        "mitre_confidence": mitre_match.confidence      if mitre_match else None,
        "risk_score":       computed_risk,
    })

    # 6. Broadcast to all WebSocket clients
    try:
        await manager.broadcast(broadcast_payload)
    except Exception as e:
        logger.error(f"[IncidentSvc] Broadcast failed: {e}")

    return event
