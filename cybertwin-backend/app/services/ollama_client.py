"""
Ollama Client – CyberTwin Phase 7
Lightweight async connector to the local Ollama engine (gemma4:e2b).

Exposes a single coroutine:
    generate(prompt, system) -> str | None

Returns None on any error so the caller can fall back gracefully.
"""

import logging
import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ── CyberTwin system instruction (exact wording as specified) ─────────────────
CYBERTWIN_SYSTEM_PROMPT = (
    "You are CyberTwin AI, an expert embedded IDS/IPS companion. "
    "Use your built-in cybersecurity knowledge combined with the provided project data files "
    "to assist the user. "
    "If the input is a live structural system log or security alert, provide immediate, clear, "
    "high-priority mitigation checklists for a SOC assistant, followed by a simple explanation "
    "for a layman. "
    "If it is a standard conversation, answer using your core security knowledge."
)

# Request timeout – generous so large context doesn't time out
_TIMEOUT = httpx.Timeout(connect=5.0, read=120.0, write=30.0, pool=5.0)


async def generate(
    prompt: str,
    system: str | None = None,
    model: str | None = None,
) -> str | None:
    """
    Send a prompt to the local Ollama engine and return the response text.

    Args:
        prompt:  The full user-facing prompt (may include injected context).
        system:  Optional system instruction override. Defaults to CYBERTWIN_SYSTEM_PROMPT.
        model:   Optional model override. Defaults to settings.OLLAMA_MODEL.

    Returns:
        The response string, or None if Ollama is unreachable / returns an error.
    """
    target_model = model or settings.OLLAMA_MODEL
    system_text  = system or CYBERTWIN_SYSTEM_PROMPT
    url = f"{settings.OLLAMA_BASE_URL}/api/generate"

    payload = {
        "model":  target_model,
        "prompt": prompt,
        "system": system_text,
        "stream": False,
        "options": {
            "temperature": 0.2,     # factual, low creativity – good for security analysis
            "num_ctx":    131072,   # unlock full 128K context window
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
            "Is Ollama running? Falling back to OpenAI / offline mode."
        )
        return None
    except httpx.TimeoutException:
        logger.warning("[Ollama] Request timed out. Falling back.")
        return None
    except Exception as e:
        logger.error(f"[Ollama] Unexpected error: {e}")
        return None


async def health_check() -> dict:
    """
    Check whether Ollama is reachable and the target model is loaded.
    Returns a status dict suitable for embedding in /api/health.
    """
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
