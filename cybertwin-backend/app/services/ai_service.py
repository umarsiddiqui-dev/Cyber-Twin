"""
AI Service – Phase 7
Request routing order:
  1. Local Ollama (gemma4:e2b) with full project context injected  ← PRIMARY
  2. OpenAI GPT-4o (when OPENAI_API_KEY is configured)             ← SECONDARY
  3. Structured offline fallback (MITRE + keywords)                ← TERTIARY

The router signature is unchanged: /api/chat → chat.py → get_response().
No UI changes.
"""

import uuid
import logging
from datetime import datetime, timezone

from app.config import settings
from app.services import mitre_service, risk_scorer, conversation_memory
from app.services.ollama_client import generate as ollama_generate, CYBERTWIN_SYSTEM_PROMPT
from app.services.context_indexer import get_project_context

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
    Uses MITRE data, NVD CVE info, and keyword analysis to give a useful answer.
    """
    lower = message.lower()

    # ── Handle direct queries about Phase 6 ML status/classes/knowledge base ──
    from ml_pipeline.cybertwin_core import agent
    model_ready = agent._models.is_available() and agent._models._loaded
    classes = list(agent._models.le.classes_) if model_ready else [
        "Benign", "Botnet", "BruteForce-FTP", "BruteForce-SSH",
        "BruteForce-Web", "BruteForce-XSS", "DDoS-HOIC", "DDoS-LOIC",
        "DDoS-LOIC-UDP", "DoS-GoldenEye", "DoS-Hulk", "DoS-SlowHTTP",
        "DoS-Slowloris", "Infiltration", "SQLInjection"
    ]
    mitre_count = len(agent._kb.mitre) if agent._kb._loaded else 0
    cve_count = len(agent._kb.cves) if agent._kb._loaded else 0

    if "ml status" in lower or "model status" in lower or "cyber twin status" in lower:
        status_str = "🟢 Active & Loaded" if model_ready else "🟡 Training or Loading (Fallback Active)"
        return (
            f"🛡️ **CyberTwin ML Model Status**\n\n"
            f"- **Ensemble Engine:** LightGBM + Random Forest\n"
            f"- **Status:** {status_str}\n"
            f"- **Dataset:** CSE-CIC-IDS2018 (Traffic Flow ML)\n"
            f"- **Classes Loaded:** {len(classes)} network threat classes\n"
            f"- **MITRE techniques indexed:** {mitre_count}\n"
            f"- **NVD CVEs indexed:** {cve_count}\n"
        )

    if "class" in lower or "detect" in lower or "attack type" in lower:
        class_list = "\n".join(f"- {c}" for c in classes)
        return (
            f"📊 **CyberTwin Classification Categories**\n\n"
            f"The ML engine is trained to classify network traffic into the following {len(classes)} categories:\n"
            f"{class_list}\n"
        )

    if "cve" in lower or "vulnerabilit" in lower:
        # Show a sample of highest CVSS CVEs from local KB
        cve_info = ""
        if agent._kb._loaded and agent._kb.cves:
            top_cves = sorted(agent._kb.cves.values(), key=lambda x: x.get("cvss_score", 0), reverse=True)[:3]
            cve_info = "\n\n**Top Vulnerabilities in Local KB:**\n" + "\n".join(
                f"- **{c['id']}** (CVSS: {c['cvss_score']} - {c['severity']}): {c['description'][:120]}..."
                for c in top_cves
            )
        return (
            f"🔍 **NVD CVE Vulnerability Index**\n\n"
            f"Total indexed CVEs: **{cve_count:,}** from NVD modified feed.{cve_info}\n"
        )

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
        "- Query our local ML Model Status & Classes ('ml status', 'classes')\n"
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

    # ── Step 3a: Ollama (gemma4:e2b) – PRIMARY ───────────────────────────────
    reply_text = None
    try:
        # Gather project context to inject into the 128K window
        project_ctx = get_project_context()

        # Gather ML model + knowledge-base metadata
        try:
            from ml_pipeline.cybertwin_core import agent as _agent
            model_ready  = _agent._models.is_available() and _agent._models._loaded
            classes      = list(_agent._models.le.classes_) if model_ready else []
            mitre_count  = len(_agent._kb.mitre) if _agent._kb._loaded else 0
            cve_count    = len(_agent._kb.cves) if _agent._kb._loaded else 0
        except Exception:
            model_ready, classes, mitre_count, cve_count = False, [], 0, 0

        # Build the enriched prompt (context + conversation history + user message)
        history = conversation_memory.get_history(sid)
        history_text = ""
        for turn in history[-6:]:   # last 3 full turns to avoid prompt bloat
            role_label = "User" if turn["role"] == "user" else "CyberTwin"
            history_text += f"\n{role_label}: {turn['content']}"

        ml_section = (
            f"\n\n[CyberTwin ML Engine]\n"
            f"- Classifier: {'ACTIVE' if model_ready else 'INACTIVE'}\n"
            f"- Threat classes: {classes}\n"
            f"- MITRE ATT&CK techniques: {mitre_count}\n"
            f"- NVD CVEs indexed: {cve_count}\n"
        )
        mitre_section = f"\n[MITRE Match]\n{mitre_context}" if mitre_context else ""
        incidents_section = ""
        if recent_incidents:
            inc_text = "\n".join(f"- {i}" for i in recent_incidents[:5])
            incidents_section = f"\n[Recent Incidents]\n{inc_text}"

        full_prompt = (
            f"[PROJECT SOURCE FILES]\n{project_ctx}\n"
            f"{ml_section}{mitre_section}{incidents_section}"
            f"{history_text}\n\nUser: {message}\nCyberTwin:"
        )

        reply_text = await ollama_generate(
            prompt=full_prompt,
            system=CYBERTWIN_SYSTEM_PROMPT,
        )
        if reply_text:
            logger.info("[AI] Response served by Ollama (gemma4:e2b)")
    except Exception as e:
        logger.error(f"[AI] Ollama pipeline error: {e}")
        reply_text = None

    # ── Step 3b: OpenAI GPT-4o – SECONDARY ───────────────────────────────────
    if reply_text is None and settings.OPENAI_API_KEY:
        try:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

            try:
                from ml_pipeline.cybertwin_core import agent as _agent
                model_ready  = _agent._models.is_available() and _agent._models._loaded
                classes      = list(_agent._models.le.classes_) if model_ready else []
                mitre_count  = len(_agent._kb.mitre) if _agent._kb._loaded else 0
                cve_count    = len(_agent._kb.cves) if _agent._kb._loaded else 0
            except Exception:
                model_ready, classes, mitre_count, cve_count = False, [], 0, 0

            sys_content = _SYSTEM_PROMPT
            sys_content += (
                f"\n\n[Local Security Model Info]\n"
                f"- Threat Classifier Status: {'ACTIVE & LOADED' if model_ready else 'INACTIVE/TRAINING'}\n"
                f"- Trained Threat Classes: {classes}\n"
                f"- MITRE ATT&CK techniques index: {mitre_count} techniques\n"
                f"- NVD CVE database index: {cve_count} CVEs\n"
            )
            if mitre_context:
                sys_content += f"\nRelevant threat context:\n{mitre_context}"
            if recent_incidents:
                inc_text = "\n".join(f"- {i}" for i in recent_incidents[:5])
                sys_content += f"\nRecent active incidents:\n{inc_text}"

            history   = conversation_memory.get_history(sid)
            messages  = [{"role": "system", "content": sys_content}]
            messages.extend(history)
            messages.append({"role": "user", "content": message})

            response   = await client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                temperature=0.2,
                max_tokens=800,
            )
            reply_text = response.choices[0].message.content.strip()
            logger.info("[AI] Response served by OpenAI GPT-4o (fallback)")

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
