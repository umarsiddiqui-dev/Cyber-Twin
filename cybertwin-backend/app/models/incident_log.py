import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Float, func
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class IncidentLog(Base):
    """
    Security incident record.
    Phase 2 will populate this from Snort/OSSEC feeds.
    Phase 3 will add MITRE references and risk scores.
    """

    __tablename__ = "incident_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source: Mapped[str] = mapped_column(String(50), default="manual")   # snort | ossec | manual
    severity: Mapped[str] = mapped_column(String(20), default="INFO")   # CRITICAL|HIGH|MEDIUM|LOW|INFO
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_log: Mapped[str] = mapped_column(Text, nullable=True)
    mitre_tactic: Mapped[str] = mapped_column(String(100), nullable=True)  # Phase 3
    mitre_technique: Mapped[str] = mapped_column(String(100), nullable=True)  # Phase 3
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)           # Phase 3
    status: Mapped[str] = mapped_column(String(20), default="open")    # open | resolved | ignored
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
