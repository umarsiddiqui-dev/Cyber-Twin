"""
AI Service – Phase 3 Core
Replaces echo_service.py. Provides context-aware responses using:
  - OpenAI GPT-4o (when OPENAI_API_KEY is configured)
  - Local MITRE ATT&CK classifier (always available, no key needed)
  - Conversation memory for multi-turn dialogue

This module is the REPLACEMENT POINT committed in Phase 1.
The router signature remains unchanged: accepts a message string,
returns a dict with reply, session_id, timestamp, and enrichment fields.
"""

import uuid
import logging
from datetime import datetime, timezone

from app.config import settings
from app.services import mitre_service, risk_scorer, conversation_memory

logger = logging.getLogger(__name__)

# ── System prompt ─────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """You are CyberTwin, an expert AI-powered Security Operations Center (SOC) Assistant.

Your capabilities:
- Analyze security alerts, logs, and incidents with deep technical expertise
- Explain threats in plain language suitable for both technical and non-technical staff
- Cross-reference MITRE ATT&CK framework tactics and techniques
- Suggest actionable remediation steps, always emphasizing that commands require human approval
- Prioritize incidents by severity and business impact
- Never fabricate CVEs, IOCs or security data — if unsure, say so

Response format guidelines:
- Be concise and structured (use bullet points when listing steps)
- Always cite the MITRE ATT&CK technique if you identify one (format: [T1234] Technique Name)
- For remediation suggestions, always prefix them with ⚠️ APPROVAL REQUIRED: to flag that a human must approve
- If the user pastes a log, interpret it technically before suggesting action

You have access to real-time incident data from this SOC session."""


def _build_offline_response(message: str, mitre_match) -> str:
    """
    Structured offline reply when OpenAI is unavailable.
    Uses MITRE data and keyword analysis to give a useful answer.
    """
    lower = message.lower()

    if mitre_match:
        m = mitre_match
        return (
            f"🛡️ **CyberTwin Analysis** *(Offline Mode)*\n\n"
            f"**MITRE ATT&CK Match:** [{m.technique_id}] {m.technique_name}\n"
            f"**Tactic:** {m.tactic} | **Confidence:** {m.confidence:.0%}\n\n"
            f"**What this means:** {m.description}\n\n"
            f"**Recommended actions:**\n"
            f"- Investigate the source IP for additional connections\n"
            f"- Review authentication logs for related activity\n"
            f"- ⚠️ APPROVAL REQUIRED: Consider blocking the offending IP at the perimeter firewall\n\n"
            f"*Connect an OpenAI API key in `.env` for full NLP-powered analysis.*"
        )

    if any(k in lower for k in ["snort", "alert", "log", "rule"]):
        return (
            "🔍 **Log Analysis** *(Offline Mode)*\n\n"
            "I've analyzed your input but couldn't match a specific MITRE ATT&CK technique without the AI engine.\n\n"
            "**General steps:**\n"
            "- Identify the source and destination IPs involved\n"
            "- Check if the alert rule has triggered previously (pattern analysis)\n"
            "- Correlate with authentication and system logs\n"
            "- ⚠️ APPROVAL REQUIRED: Isolate the host if compromise is confirmed\n\n"
            "*Set `OPENAI_API_KEY` in `.env` for full AI-powered threat interpretation.*"
        )

    return (
        "🤖 **CyberTwin** *(Offline Mode)*\n\n"
        "The AI engine requires an OpenAI API key (`OPENAI_API_KEY` in `.env`).\n"
        "In offline mode, I can still:\n"
        "- Classify alerts against MITRE ATT&CK\n"
        "- Compute risk scores\n"
        "- Display live security events on the dashboard\n\n"
        "Configure the API key to unlock full NLP threat analysis."
    )


async def get_response(
    message: str,
    session_id: str | None = None,
    recent_incidents: list | None = None,
) -> dict:
    """
    Generate an AI response to the user's message.

    Args:
        message:          User's text input
        session_id:       Optional session ID for conversation continuity
        recent_incidents: Optional list of recent incident titles for context injection

    Returns:
        dict with keys: reply, session_id, timestamp,
                        mitre_id, mitre_tactic, mitre_technique, confidence, risk_score
    """
    sid = session_id or str(uuid.uuid4())

    # ── Step 1: MITRE classification (always) ─────────────────────────────────
    mitre_match = mitre_service.classify(message)
    mitre_context = mitre_service.format_mitre_context(mitre_match) if mitre_match else ""

    # ── Step 2: Risk score for the query itself ────────────────────────────────
    query_risk = risk_scorer.score(
        severity="INFO",
        source="manual",
        mitre_match=mitre_match,
    )

    # ── Step 3: Attempt GPT-4o call ───────────────────────────────────────────
    reply_text = None
    if settings.OPENAI_API_KEY:
        try:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

            # Build system context
            sys_content = _SYSTEM_PROMPT
            if mitre_context:
                sys_content += f"\n\nRelevant threat context:\n{mitre_context}"
            if recent_incidents:
                inc_text = "\n".join(f"- {i}" for i in recent_incidents[:5])
                sys_content += f"\n\nRecent active incidents:\n{inc_text}"

            # Fetch conversation history
            history = conversation_memory.get_history(sid)

            messages = [{"role": "system", "content": sys_content}]
            messages.extend(history)
            messages.append({"role": "user", "content": message})

            response = await client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                temperature=0.2,      # Low creativity → factually reliable
                max_tokens=800,
            )
            reply_text = response.choices[0].message.content.strip()

        except Exception as e:
            logger.error(f"[AI] OpenAI request failed: {e}")
            reply_text = None

    # ── Step 4: Offline fallback ──────────────────────────────────────────────
    if reply_text is None:
        reply_text = _build_offline_response(message, mitre_match)

    # ── Step 5: Persist conversation turn ─────────────────────────────────────
    conversation_memory.add_turn(sid, message, reply_text)

    return {
        "reply":            reply_text,
        "session_id":       sid,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "mitre_id":         mitre_match.technique_id   if mitre_match else None,
        "mitre_tactic":     mitre_match.tactic          if mitre_match else None,
        "mitre_technique":  mitre_match.technique_name  if mitre_match else None,
        "confidence":       mitre_match.confidence      if mitre_match else None,
        "risk_score":       query_risk,
    }
