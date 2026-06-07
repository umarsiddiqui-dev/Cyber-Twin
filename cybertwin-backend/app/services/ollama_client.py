"""
Ollama Client – CyberTwin Phase 7 (Enhanced)
Expert-grade cybersecurity system prompt + fast context strategy.
"""

import logging
import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ── Master CyberTwin AI System Prompt ────────────────────────────────────────
# Comprehensive expert prompt trained on MITRE ATT&CK, threat response, SOC operations
CYBERTWIN_SYSTEM_PROMPT = """You are CyberTwin AI, an advanced Security Operations Center (SOC) assistant with comprehensive expert knowledge of all cybersecurity domains, threat intelligence, and the complete MITRE ATT&CK framework.

Analyze security events using your deep MITRE ATT&CK expertise. Respond with:
1. Threat Analysis (Attack Type, MITRE Tactic/Technique, Severity)
2. Immediate Mitigation Checklist (Start commands with ⚠️ APPROVAL REQUIRED:)
3. Brief Layman Explanation
4. Indicators of Compromise (IOCs)

If answering a general question, be concise, factual, and showcase your extensive cybersecurity knowledge. Cite MITRE ATT&CK tactics, techniques, and procedures (TTPs) where applicable.
If the question is not about security, politely redirect to cybersecurity.
Keep responses actionable and use markdown formatting. Do not hallucinate CVEs or IOCs.
"""

# Request timeout – generous for large context
_TIMEOUT = httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=5.0)


async def generate(
    prompt: str,
    system: str | None = None,
    model: str | None = None,
    num_ctx: int = 4096,
) -> str | None:
    """
    Send a prompt to the local Ollama engine and return the response text.
    Returns None on any error so the caller can fall back gracefully.
    """
    target_model = model or settings.OLLAMA_MODEL
    system_text  = system or CYBERTWIN_SYSTEM_PROMPT
    url = f"{settings.OLLAMA_BASE_URL}/api/generate"

    payload = {
        "model":  target_model,
        "prompt": prompt,
        "system": system_text,
        "stream": False,
        "keep_alive": -1,  # Keep model loaded in memory indefinitely to avoid 90s delay
        "options": {
            "temperature": 0.15,    # Very factual – security info must be accurate
            "num_ctx":    num_ctx,    # Dynamic context size to speed up CPU inference
            "top_p": 0.9,
            "repeat_penalty": 1.1,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            text = data.get("response", "").strip()
            if not text:
                logger.warning("[Ollama] Empty response received from model.")
                return None
            logger.info(f"[Ollama] Response received ({len(text)} chars) from {target_model}")
            return text

    except httpx.ConnectError:
        logger.warning(
            f"[Ollama] Connection refused at {settings.OLLAMA_BASE_URL}. "
            "Is Ollama running? Falling back to offline mode."
        )
        return None
    except httpx.TimeoutException:
        logger.warning("[Ollama] Request timed out. Falling back.")
        return None
    except Exception as e:
        logger.error(f"[Ollama] Unexpected error: {e}")
        return None

import json
async def generate_stream(
    prompt: str,
    system: str | None = None,
    model: str | None = None,
    num_ctx: int = 4096,
):
    target_model = model or settings.OLLAMA_MODEL
    system_text  = system or CYBERTWIN_SYSTEM_PROMPT
    url = f"{settings.OLLAMA_BASE_URL}/api/generate"

    payload = {
        "model":  target_model,
        "prompt": prompt,
        "system": system_text,
        "stream": True,
        "keep_alive": -1,  # Keep model loaded in memory indefinitely
        "options": {
            "temperature": 0.15,
            "num_ctx":    num_ctx,
            "top_p": 0.9,
            "repeat_penalty": 1.1,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            async with client.stream("POST", url, json=payload) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line:
                        data = json.loads(line)
                        chunk = data.get("response", "")
                        if chunk:
                            yield chunk
    except Exception as e:
        logger.error(f"[Ollama] Stream error: {e}")
        # Yield nothing if there is an error



async def health_check() -> dict:
    """Check whether Ollama is reachable and the target model is loaded."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
            r = await client.get(f"{settings.OLLAMA_BASE_URL}/api/tags")
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
            loaded = any(settings.OLLAMA_MODEL in m for m in models)
            return {
                "ollama_reachable": True,
                "model": settings.OLLAMA_MODEL,
                "model_loaded": loaded,
                "available_models": models,
            }
    except Exception as e:
        return {
            "ollama_reachable": False,
            "model": settings.OLLAMA_MODEL,
            "model_loaded": False,
            "error": str(e),
        }
