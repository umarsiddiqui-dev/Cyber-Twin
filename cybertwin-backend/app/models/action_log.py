"""
ActionLog Model – Phase 4 (Updated Phase 3 Audit Hardening)
Stores every AI-proposed remediation action with a full audit trail.
Status lifecycle: pending → approved/rejected → executed/failed

Phase 3 change:
  Added a SQLAlchemy ORM event listener that raises ValueError if
  an attempt is made to modify 'created_at', 'command', or 'action_type'
  after the record has been persisted (INSERT). These three fields form
  the immutable audit core of every action record.
"""

import uuid
import json
from datetime import datetime
from sqlalchemy import String, DateTime, Text, func, event
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class ActionLog(Base):
    """
    Audit table for all proposed and executed remediation actions.
    One record per proposed action, one DB row for the full lifecycle.
    """

    __tablename__ = "action_logs"

    # ── Identity ──────────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    incident_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=True)

    # ── Action details ────────────────────────────────────────────────────────
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # e.g.: block_ip | kill_process | isolate_host | run_scan | add_firewall_rule

    command: Mapped[str] = mapped_column(Text, nullable=False)
    # The exact shell command that WOULD run (always stored, even in sim mode)

    parameters: Mapped[str] = mapped_column(Text, nullable=True)
    # JSON-encoded dict of action parameters (ip, pid, host, port, etc.)

    reason: Mapped[str] = mapped_column(Text, nullable=True)
    # AI-generated justification shown to the analyst before approval

    # ── Status lifecycle ──────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(String(20), default="pending")
    # pending | approved | rejected | executed | failed

    simulated: Mapped[bool] = mapped_column(default=True)
    # True by default — set to False only when real execution runs

    execution_output: Mapped[str] = mapped_column(Text, nullable=True)
    # stdout/stderr from execution, or simulation note

    # ── Audit ─────────────────────────────────────────────────────────────────
    reviewed_by: Mapped[str] = mapped_column(String(100), nullable=True)
    reject_reason: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def get_parameters(self) -> dict:
        """Deserialize the JSON parameters column."""
        if self.parameters:
            try:
                return json.loads(self.parameters)
            except Exception:
                return {}
        return {}


# ── Immutability guard (Phase 3) ──────────────────────────────────────────────
# Prevent modification of the three core audit fields after initial creation.
# These columns form the tamper-evident backbone of every action record.

_IMMUTABLE_COLUMNS = frozenset({"created_at", "command", "action_type"})


@event.listens_for(ActionLog, "before_update")
def _prevent_immutable_field_modification(mapper, connection, target):
    """
    SQLAlchemy ORM event listener — fires BEFORE every UPDATE on ActionLog.
    Raises ValueError if any of the three immutable audit columns have been
    modified since the instance was loaded from the database.

    This provides application-layer tamper detection. For database-level
    enforcement, add a PostgreSQL BEFORE UPDATE trigger as well.
    """
    history = mapper.attrs
    for col_name in _IMMUTABLE_COLUMNS:
        attr = history[col_name]
        col_history = attr.load_history()
        # col_history.deleted contains the old value if the attribute was changed
        if col_history.deleted:
            raise ValueError(
                f"[ActionLog] Immutable field '{col_name}' cannot be modified after creation. "
                f"Original: {col_history.deleted[0]!r}"
            )
